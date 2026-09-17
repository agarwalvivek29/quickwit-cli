package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// _msearch (Grafana's query path) must be audited with the index (from the
// ndjson header) and the query body captured as valid JSON — and the full body
// must still reach upstream unchanged.
func TestMSearchAuditCapturesIndexAndBody(t *testing.T) {
	up := newUpstream(t)
	ca := &capAudit{}
	h := newHandler(t, up, ca)
	body := "{\"index\":\"core-logs\"}\n{\"query\":{\"match_all\":{}}}\n"
	w := do(h, http.MethodPost, "/api/v1/_elastic/_msearch", "good", body)
	if w.Code != http.StatusOK {
		t.Fatalf("code=%d, want 200", w.Code)
	}
	rec, ok := ca.last()
	if !ok {
		t.Fatal("no audit record")
	}
	if rec.Index != "core-logs" {
		t.Errorf("audit index=%q, want core-logs", rec.Index)
	}
	if len(rec.QueryBody) == 0 || !json.Valid(rec.QueryBody) {
		t.Errorf("audit query_body must be captured valid JSON, got %q", string(rec.QueryBody))
	}
	if up.lastBody != body {
		t.Errorf("upstream body altered: %q", up.lastBody)
	}
}

// The Grafana Quickwit datasource plugin (github.com/quickwit-oss/quickwit-datasource)
// talks to Quickwit's Elasticsearch-compatible API. These read routes must be
// allowed or dashboards/Explore fail with 403.
func TestGrafanaESCompatReadRoutesAllowed(t *testing.T) {
	up := newUpstream(t)
	h := newHandler(t, up, &capAudit{})
	allowed := []struct{ method, path string }{
		{http.MethodPost, "/api/v1/_elastic/_msearch"},
		{http.MethodGet, "/api/v1/_elastic/core-logs/_field_caps"},
		{http.MethodGet, "/api/v1/_elastic/core-logs/_mapping"},
	}
	for _, a := range allowed {
		w := do(h, a.method, a.path, "good", `{}`)
		if w.Code != http.StatusOK {
			t.Errorf("%s %s: code=%d, want 200 (must be allowed for Grafana)", a.method, a.path, w.Code)
		}
	}
}

// ES-compat WRITE endpoints must stay blocked — the proxy is read-only.
func TestGrafanaESCompatWritesStillBlocked(t *testing.T) {
	up := newUpstream(t)
	h := newHandler(t, up, &capAudit{})
	blocked := []struct{ method, path string }{
		{http.MethodPost, "/api/v1/_elastic/_bulk"},
		{http.MethodPost, "/api/v1/_elastic/core-logs/_bulk"},
	}
	for _, b := range blocked {
		w := do(h, b.method, b.path, "good", "{}")
		if w.Code != http.StatusForbidden {
			t.Errorf("%s %s: code=%d, want 403", b.method, b.path, w.Code)
		}
	}
	if up.hits != 0 {
		t.Errorf("blocked writes reached upstream (%d hits)", up.hits)
	}
}

// The proxy must NOT impose a short request timeout: Grafana dashboards run
// wide-time-range queries that take longer than a couple of seconds. A slow
// upstream must stream through, not get cut.
func TestProxyDoesNotCutLongRunningQuery(t *testing.T) {
	const upstreamDelay = 3 * time.Second
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(upstreamDelay)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"num_hits":1,"hits":[{}]}`))
	}))
	defer slow.Close()
	u, _ := url.Parse(slow.URL)
	h := New(Options{Upstream: u, Verifier: stubVerifier{}, Audit: &capAudit{}})

	start := time.Now()
	w := do(h, http.MethodPost, "/api/v1/_elastic/_msearch", "good", "{\"index\":\"x\"}\n{}\n")
	elapsed := time.Since(start)

	if w.Code != http.StatusOK {
		t.Fatalf("code=%d, want 200 after a slow upstream", w.Code)
	}
	if elapsed < upstreamDelay {
		t.Fatalf("returned in %v, expected >= %v (proxy must wait for upstream, not time out)", elapsed, upstreamDelay)
	}
}
