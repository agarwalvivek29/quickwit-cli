// Package proxy is the qwproxy request handler: it authenticates the caller's
// OIDC bearer token, enforces a read-only allowlist over Quickwit's API,
// streams the upstream response straight back to the client, and records the
// request envelope (including the search query, never the response body) to the
// async audit writer.
package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/agarwalvivek29/quickwit-cli/internal/audit"
	"github.com/agarwalvivek29/quickwit-cli/internal/oidc"
)

// maxQueryBody caps how many bytes of a search request body we buffer for the
// audit record (and re-attach for forwarding). Quickwit queries are tiny; this
// only guards against a pathological client.
const maxQueryBody = 64 * 1024

// maxMSearchBody caps how many bytes of an _msearch ndjson body we buffer for
// the audit record. _msearch bundles several queries, so it gets more headroom
// than a single search; the full body is still forwarded regardless.
const maxMSearchBody = 256 * 1024

// TokenVerifier validates a raw bearer token and returns its identity claims.
// *oidc.Verifier satisfies this.
type TokenVerifier interface {
	Verify(ctx context.Context, rawToken string) (*oidc.Claims, error)
}

// AuditLogger enqueues an audit record without blocking. *audit.Writer
// satisfies this.
type AuditLogger interface {
	Log(audit.Record)
}

// Options configure a Handler.
type Options struct {
	Upstream *url.URL
	Verifier TokenVerifier
	Audit    AuditLogger
	Metrics  *Metrics // optional; nil disables metrics
	Now      func() time.Time
}

// Handler is the http.Handler for qwproxy.
type Handler struct {
	opts  Options
	proxy *httputil.ReverseProxy
	now   func() time.Time
}

// New builds a Handler that forwards allowed, authenticated requests to
// opts.Upstream.
func New(opts Options) *Handler {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	rp := httputil.NewSingleHostReverseProxy(opts.Upstream)
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		writeJSONError(w, http.StatusBadGateway, "upstream error: "+err.Error())
	}
	return &Handler{opts: opts, proxy: rp, now: opts.Now}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 1. Authenticate.
	raw, ok := bearerToken(r)
	if !ok {
		h.metricAuthFail()
		writeJSONError(w, http.StatusUnauthorized, "missing bearer token")
		return
	}
	claims, err := h.opts.Verifier.Verify(r.Context(), raw)
	if err != nil {
		h.metricAuthFail()
		writeJSONError(w, http.StatusUnauthorized, "invalid token: "+err.Error())
		return
	}

	// 2. Enforce the read-only allowlist.
	if !isAllowed(r.Method, r.URL.Path) {
		writeJSONError(w, http.StatusForbidden, "endpoint not permitted (qwproxy is read-only)")
		return
	}

	// 3. Capture the search query body (only), re-attaching it for forwarding.
	// Native /{index}/search bodies are a single JSON object; the ES-compat
	// _msearch (used by the Grafana plugin) is ndjson, so it is captured as a
	// JSON array and its index is read from the header lines rather than the path.
	var queryBody []byte
	auditIndex := indexFromPath(r.URL.Path)
	switch {
	case isSearch(r.Method, r.URL.Path) && r.Body != nil:
		queryBody = drainAndRestore(r, maxQueryBody)
	case isMSearch(r.Method, r.URL.Path) && r.Body != nil:
		queryBody, auditIndex = drainMSearch(r, maxMSearchBody)
	}

	// 4. Forward, recording status/latency/bytes.
	rec := &recorder{ResponseWriter: w, status: http.StatusOK}
	start := h.now()
	h.proxy.ServeHTTP(rec, r)
	latency := h.now().Sub(start)

	// 5. Audit (non-blocking).
	h.opts.Audit.Log(audit.Record{
		Ts:             start,
		PrincipalSub:   claims.Subject,
		PrincipalEmail: claims.Email,
		ClientIP:       clientIP(r),
		UserAgent:      r.UserAgent(),
		CLIVersion:     r.Header.Get("X-Qw-Cli-Version"),
		Method:         r.Method,
		Path:           r.URL.Path,
		Index:          auditIndex,
		QueryBody:      json.RawMessage(queryBody),
		StatusCode:     rec.status,
		LatencyMS:      latency.Milliseconds(),
		BytesOut:       rec.bytes,
	})
	h.metricRequest(r.Method, rec.status, latency)
}

// --- allowlist ---------------------------------------------------------------

type route struct {
	method string
	re     *regexp.Regexp
}

// allowedRoutes is Quickwit's read surface — exactly what the CLI/MCP need.
// Anything else (ingest, delete, source mutation, clear, ...) is rejected.
var allowedRoutes = []route{
	{http.MethodGet, regexp.MustCompile(`^/api/v1/version$`)},
	{http.MethodGet, regexp.MustCompile(`^/api/v1/indexes/?$`)},
	{http.MethodGet, regexp.MustCompile(`^/api/v1/indexes/[^/]+$`)},
	{http.MethodGet, regexp.MustCompile(`^/api/v1/indexes/[^/]+/describe$`)},
	{http.MethodGet, regexp.MustCompile(`^/api/v1/[^/]+/search$`)},
	{http.MethodPost, regexp.MustCompile(`^/api/v1/[^/]+/search$`)},
	// Elasticsearch-compatible read surface used by the Grafana Quickwit
	// datasource plugin (github.com/quickwit-oss/quickwit-datasource): _msearch
	// for panel/Explore queries, _field_caps + _mapping for schema discovery.
	{http.MethodPost, regexp.MustCompile(`^/api/v1/_elastic/_msearch$`)},
	{http.MethodGet, regexp.MustCompile(`^/api/v1/_elastic/[^/]+/_field_caps$`)},
	{http.MethodGet, regexp.MustCompile(`^/api/v1/_elastic/[^/]+/_mapping$`)},
}

func isAllowed(method, path string) bool {
	for _, rt := range allowedRoutes {
		if rt.method == method && rt.re.MatchString(path) {
			return true
		}
	}
	return false
}

var searchRe = regexp.MustCompile(`^/api/v1/([^/]+)/search$`)

func isSearch(method, path string) bool {
	return (method == http.MethodPost || method == http.MethodGet) && searchRe.MatchString(path)
}

// isMSearch matches the ES-compatible multi-search endpoint the Grafana plugin
// uses. Its ndjson body carries the index in header lines, not the path.
func isMSearch(method, path string) bool {
	return method == http.MethodPost && path == "/api/v1/_elastic/_msearch"
}

// indexFromPath extracts the index segment for /search and /indexes/{id} paths.
func indexFromPath(path string) string {
	if m := searchRe.FindStringSubmatch(path); m != nil {
		return m[1]
	}
	if m := regexp.MustCompile(`^/api/v1/indexes/([^/]+)(?:/describe)?$`).FindStringSubmatch(path); m != nil {
		return m[1]
	}
	return ""
}

// --- helpers -----------------------------------------------------------------

func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const p = "Bearer "
	if len(h) > len(p) && strings.EqualFold(h[:len(p)], p) {
		return h[len(p):], true
	}
	return "", false
}

// drainAndRestore reads up to limit bytes of the body for auditing, then
// restores r.Body (bounded read + any remainder) so the proxy still forwards
// the full request.
func drainAndRestore(r *http.Request, limit int) []byte {
	body, err := io.ReadAll(r.Body)
	_ = r.Body.Close()
	if err != nil {
		r.Body = io.NopCloser(bytes.NewReader(nil))
		return nil
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	captured := body
	if len(captured) > limit {
		captured = captured[:limit]
	}
	// Only keep it if it is valid JSON, so query_body stays a clean jsonb value.
	if !json.Valid(captured) {
		return nil
	}
	return captured
}

// drainMSearch reads an _msearch ndjson body (up to limit) for auditing and
// restores r.Body so the proxy still forwards the full request. It returns the
// non-empty JSON lines wrapped as a single JSON array (a valid jsonb value for
// the audit store) and the first index found in a header line.
func drainMSearch(r *http.Request, limit int) ([]byte, string) {
	body, err := io.ReadAll(r.Body)
	_ = r.Body.Close()
	if err != nil {
		r.Body = io.NopCloser(bytes.NewReader(nil))
		return nil, ""
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	captured := body
	if len(captured) > limit {
		captured = captured[:limit]
	}
	var lines []json.RawMessage
	var index string
	for _, line := range bytes.Split(captured, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || !json.Valid(line) {
			continue // skip blanks and a truncated final line
		}
		lines = append(lines, json.RawMessage(line))
		if index == "" {
			var hdr struct {
				Index string `json:"index"`
			}
			if json.Unmarshal(line, &hdr) == nil && hdr.Index != "" {
				index = hdr.Index
			}
		}
	}
	if len(lines) == 0 {
		return nil, index
	}
	out, err := json.Marshal(lines)
	if err != nil {
		return nil, index
	}
	return out, index
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func writeJSONError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// recorder captures the status code and response byte count while passing
// writes straight through (no buffering of the body — response payloads never
// touch memory in full, nor the audit store).
type recorder struct {
	http.ResponseWriter
	status      int
	bytes       int64
	wroteHeader bool
}

func (r *recorder) WriteHeader(code int) {
	if !r.wroteHeader {
		r.status = code
		r.wroteHeader = true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *recorder) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		r.wroteHeader = true
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += int64(n)
	return n, err
}

// Flush and Unwrap keep streaming + http.ResponseController working through the
// wrapper.
func (r *recorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (r *recorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }
