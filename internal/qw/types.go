package qw

import "encoding/json"

// IndexMetadata is one entry from GET /api/v1/indexes and the full body of
// GET /api/v1/indexes/{id}. Only the fields the CLI uses are modelled; unknown
// fields (checkpoint, sources, retention, ...) are ignored by the decoder.
type IndexMetadata struct {
	Version     string      `json:"version"`
	IndexConfig IndexConfig `json:"index_config"`
}

// ID is the index identifier, e.g. "core-stage-app-logs".
func (m IndexMetadata) ID() string { return m.IndexConfig.IndexID }

type IndexConfig struct {
	IndexID    string     `json:"index_id"`
	IndexURI   string     `json:"index_uri"`
	DocMapping DocMapping `json:"doc_mapping"`
}

// DocMapping carries the field schema needed to build valid queries. This is
// only present on GET /api/v1/indexes/{id} (and the list endpoint) — not on
// the /describe endpoint.
type DocMapping struct {
	FieldMappings  []FieldMapping `json:"field_mappings"`
	TimestampField string         `json:"timestamp_field"`
}

// FieldMapping is one field in the doc mapping. Object fields nest further
// mappings under FieldMappings.
type FieldMapping struct {
	Name          string          `json:"name"`
	Type          string          `json:"type"`
	Indexed       *bool           `json:"indexed,omitempty"`
	Fast          json.RawMessage `json:"fast,omitempty"`
	FieldMappings []FieldMapping  `json:"field_mappings,omitempty"`
}

// IndexDescription is GET /api/v1/indexes/{id}/describe — stats and the
// timestamp range. The field mapping is NOT here (use IndexMetadata for that).
type IndexDescription struct {
	IndexID                       string `json:"index_id"`
	NumPublishedDocs              int64  `json:"num_published_docs"`
	NumPublishedSplits            int64  `json:"num_published_splits"`
	SizePublishedDocsUncompressed int64  `json:"size_published_docs_uncompressed"`
	SizePublishedSplits           int64  `json:"size_published_splits"`
	TimestampFieldName            string `json:"timestamp_field_name"`
	MinTimestamp                  *int64 `json:"min_timestamp"`
	MaxTimestamp                  *int64 `json:"max_timestamp"`
}

// SearchRequest is the body of POST /api/v1/{index}/search. Pointer fields are
// omitted from the wire body when nil, matching Quickwit's optional semantics.
type SearchRequest struct {
	Query          string          `json:"query"`
	MaxHits        int             `json:"max_hits"`
	StartTimestamp *int64          `json:"start_timestamp,omitempty"`
	EndTimestamp   *int64          `json:"end_timestamp,omitempty"`
	StartOffset    *int            `json:"start_offset,omitempty"`
	SortBy         string          `json:"sort_by,omitempty"`
	SearchField    string          `json:"search_field,omitempty"`
	SnippetFields  string          `json:"snippet_fields,omitempty"`
	Aggs           json.RawMessage `json:"aggs,omitempty"`
}

// SearchResponse is the result of a search. Hits are left as raw JSON so the
// CLI can project arbitrary fields without a fixed document schema.
type SearchResponse struct {
	NumHits           int64             `json:"num_hits"`
	Hits              []json.RawMessage `json:"hits"`
	ElapsedTimeMicros int64             `json:"elapsed_time_micros"`
	Errors            []string          `json:"errors,omitempty"`
	Aggregations      json.RawMessage   `json:"aggregations,omitempty"`
}
