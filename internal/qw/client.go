// Package qw is a thin client for the Quickwit REST API (/api/v1). It speaks
// only the read surface the CLI needs and returns parsed JSON, surfacing
// Quickwit's own error body via *Error so callers can show it to the user.
//
// It is a Go port of the quickwit-mcp client (client.py): same endpoints, same
// request shaping. Authentication is intentionally NOT this client's concern —
// pass an *http.Client whose transport injects the bearer token (e.g. one from
// golang.org/x/oauth2), so the same client works talking directly to Quickwit
// or through qwproxy.
package qw

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const defaultTimeout = 30 * time.Second

// Client is a reusable client bound to a single Quickwit (or qwproxy) base URL.
type Client struct {
	baseURL   string
	hc        *http.Client
	userAgent string
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient sets the underlying HTTP client (use this to inject an
// oauth2-authenticated client, or an httptest one in tests).
func WithHTTPClient(hc *http.Client) Option { return func(c *Client) { c.hc = hc } }

// WithUserAgent sets the User-Agent header sent on every request.
func WithUserAgent(ua string) Option { return func(c *Client) { c.userAgent = ua } }

// New returns a Client for baseURL (e.g. "http://localhost:7280"). A trailing
// slash is trimmed. If no HTTP client is supplied, one with a 30s timeout is used.
func New(baseURL string, opts ...Option) *Client {
	c := &Client{
		baseURL:   strings.TrimRight(baseURL, "/"),
		hc:        &http.Client{Timeout: defaultTimeout},
		userAgent: "quickwit-cli",
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Error is returned for any non-2xx Quickwit response. Body is the raw response
// text so the caller can surface Quickwit's own diagnostics.
type Error struct {
	StatusCode int
	Body       string
	URL        string
}

func (e *Error) Error() string {
	return fmt.Sprintf("quickwit returned HTTP %d for %s: %s", e.StatusCode, e.URL, e.Body)
}

// do executes a request and decodes a 2xx JSON body into out (out may be nil to
// discard the body). Non-2xx responses become *Error.
func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode request body: %w", err)
		}
		rdr = bytes.NewReader(b)
	}

	u := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, method, u, rdr)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, u, err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &Error{StatusCode: resp.StatusCode, Body: strings.TrimSpace(string(data)), URL: u}
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("decode response from %s: %w", u, err)
		}
	}
	return nil
}

// Version calls GET /api/v1/version — a cheap reachability + build-info check.
func (c *Client) Version(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	if err := c.do(ctx, http.MethodGet, "/api/v1/version", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ListIndexes calls GET /api/v1/indexes — metadata for every index.
func (c *Client) ListIndexes(ctx context.Context) ([]IndexMetadata, error) {
	var out []IndexMetadata
	if err := c.do(ctx, http.MethodGet, "/api/v1/indexes", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// GetIndexMetadata calls GET /api/v1/indexes/{id} — full metadata including the
// doc mapping (field schema).
func (c *Client) GetIndexMetadata(ctx context.Context, indexID string) (*IndexMetadata, error) {
	var out IndexMetadata
	if err := c.do(ctx, http.MethodGet, "/api/v1/indexes/"+url.PathEscape(indexID), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DescribeIndex calls GET /api/v1/indexes/{id}/describe — stats + timestamp range.
func (c *Client) DescribeIndex(ctx context.Context, indexID string) (*IndexDescription, error) {
	var out IndexDescription
	if err := c.do(ctx, http.MethodGet, "/api/v1/indexes/"+url.PathEscape(indexID)+"/describe", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Search calls POST /api/v1/{index}/search. index is passed through untouched,
// so single ids, comma-separated lists ("a,b") and globs ("a*") all work.
func (c *Client) Search(ctx context.Context, index string, req SearchRequest) (*SearchResponse, error) {
	var out SearchResponse
	// {index} is a path segment but may legitimately contain commas/globs, which
	// PathEscape would mangle; Quickwit accepts them literally, so keep as-is.
	if err := c.do(ctx, http.MethodPost, "/api/v1/"+index+"/search", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
