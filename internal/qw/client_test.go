package qw

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return New(srv.URL, WithHTTPClient(srv.Client()))
}

func TestVersion(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/version" {
			t.Errorf("path = %q, want /api/v1/version", r.URL.Path)
		}
		if got := r.Header.Get("Accept"); got != "application/json" {
			t.Errorf("Accept = %q", got)
		}
		_, _ = io.WriteString(w, `{"build":{"version":"0.8.2"}}`)
	})

	v, err := c.Version(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	build, _ := v["build"].(map[string]any)
	if build["version"] != "0.8.2" {
		t.Errorf("version = %v, want 0.8.2", build["version"])
	}
}

func TestListIndexes(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `[
			{"version":"0.8","index_config":{"index_id":"core-logs","doc_mapping":{"timestamp_field":"ts","field_mappings":[{"name":"msg","type":"text"}]}}},
			{"version":"0.8","index_config":{"index_id":"sys-logs"}}
		]`)
	})

	idxs, err := c.ListIndexes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(idxs) != 2 {
		t.Fatalf("got %d indexes, want 2", len(idxs))
	}
	if idxs[0].ID() != "core-logs" {
		t.Errorf("idxs[0].ID() = %q", idxs[0].ID())
	}
	if idxs[0].IndexConfig.DocMapping.TimestampField != "ts" {
		t.Errorf("timestamp field = %q", idxs[0].IndexConfig.DocMapping.TimestampField)
	}
}

func TestGetIndexMetadataEscapesID(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		// A slash in the id must be percent-encoded into a single path segment.
		if r.URL.EscapedPath() != "/api/v1/indexes/weird%2Fid" {
			t.Errorf("escaped path = %q", r.URL.EscapedPath())
		}
		_, _ = io.WriteString(w, `{"index_config":{"index_id":"weird/id"}}`)
	})

	m, err := c.GetIndexMetadata(context.Background(), "weird/id")
	if err != nil {
		t.Fatal(err)
	}
	if m.ID() != "weird/id" {
		t.Errorf("id = %q", m.ID())
	}
}

func TestDescribeIndex(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/indexes/core-logs/describe" {
			t.Errorf("path = %q", r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"index_id":"core-logs","num_published_docs":42,"timestamp_field_name":"ts","min_timestamp":1000,"max_timestamp":2000}`)
	})

	d, err := c.DescribeIndex(context.Background(), "core-logs")
	if err != nil {
		t.Fatal(err)
	}
	if d.NumPublishedDocs != 42 {
		t.Errorf("num docs = %d", d.NumPublishedDocs)
	}
	if d.MinTimestamp == nil || *d.MinTimestamp != 1000 {
		t.Errorf("min timestamp = %v", d.MinTimestamp)
	}
}

func TestSearchSendsBodyAndParsesHits(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		if r.URL.Path != "/api/v1/core-logs/search" {
			t.Errorf("path = %q", r.URL.Path)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["query"] != "level:ERROR" {
			t.Errorf("query = %v", body["query"])
		}
		if body["max_hits"].(float64) != 10 {
			t.Errorf("max_hits = %v", body["max_hits"])
		}
		if body["start_timestamp"].(float64) != 1500 {
			t.Errorf("start_timestamp = %v", body["start_timestamp"])
		}
		// start_offset was nil → must be omitted from the wire body.
		if _, ok := body["start_offset"]; ok {
			t.Errorf("start_offset should be omitted when nil")
		}
		_, _ = io.WriteString(w, `{"num_hits":1,"elapsed_time_micros":123,"hits":[{"msg":"boom","level":"ERROR"}]}`)
	})

	start := int64(1500)
	resp, err := c.Search(context.Background(), "core-logs", SearchRequest{
		Query: "level:ERROR", MaxHits: 10, StartTimestamp: &start,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.NumHits != 1 || len(resp.Hits) != 1 {
		t.Fatalf("num_hits=%d hits=%d", resp.NumHits, len(resp.Hits))
	}
	var doc map[string]any
	if err := json.Unmarshal(resp.Hits[0], &doc); err != nil {
		t.Fatal(err)
	}
	if doc["msg"] != "boom" {
		t.Errorf("hit msg = %v", doc["msg"])
	}
}

func TestNon2xxBecomesError(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"message":"invalid query"}`)
	})

	_, err := c.Search(context.Background(), "core-logs", SearchRequest{Query: "((", MaxHits: 1})
	var qe *Error
	if !errors.As(err, &qe) {
		t.Fatalf("error = %v, want *qw.Error", err)
	}
	if qe.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d", qe.StatusCode)
	}
	if qe.Body != `{"message":"invalid query"}` {
		t.Errorf("body = %q", qe.Body)
	}
}
