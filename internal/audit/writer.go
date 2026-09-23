// Package audit records the request envelope of every proxied Quickwit call to
// Postgres — asynchronously, so a slow or absent database never adds latency to
// a user's search. Writes go through a bounded channel to a batching worker;
// when the channel is full the record is dropped and counted rather than
// blocking the request path. The audit trail is best-effort by design.
package audit

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"
)

// Record is one audited request. It intentionally has no response-body field.
type Record struct {
	Ts             time.Time
	PrincipalSub   string
	PrincipalEmail string
	AuthMethod     string // "oidc" | "api-key"
	ClientIP       string
	UserAgent      string
	CLIVersion     string
	Method         string
	Path           string
	Index          string
	QueryBody      json.RawMessage
	StatusCode     int
	LatencyMS      int64
	BytesOut       int64
}

// Sink persists a batch of records. Implementations must be safe for use by the
// single writer goroutine.
type Sink interface {
	InsertBatch(ctx context.Context, recs []Record) error
}

// Options tune the async writer.
type Options struct {
	Buffer    int           // channel capacity; overflow is dropped + counted
	BatchSize int           // max rows per InsertBatch
	Flush     time.Duration // max time a partial batch waits before flushing
	OnError   func(error)   // called on InsertBatch failure (optional)
}

func (o Options) withDefaults() Options {
	if o.Buffer <= 0 {
		o.Buffer = 4096
	}
	if o.BatchSize <= 0 {
		o.BatchSize = 100
	}
	if o.Flush <= 0 {
		o.Flush = time.Second
	}
	return o
}

// Writer is the async, drop-on-full audit writer.
type Writer struct {
	sink    Sink
	opts    Options
	ch      chan Record
	done    chan struct{}
	closeMu sync.Once

	dropped  atomic.Int64
	enqueued atomic.Int64
	written  atomic.Int64
}

// New returns a Writer. Call Start to launch the worker.
func New(sink Sink, opts Options) *Writer {
	opts = opts.withDefaults()
	return &Writer{
		sink: sink,
		opts: opts,
		ch:   make(chan Record, opts.Buffer),
		done: make(chan struct{}),
	}
}

// Start launches the background worker. Its inserts use ctx; cancel it (or call
// Close) to stop.
func (w *Writer) Start(ctx context.Context) {
	go w.run(ctx)
}

// Log enqueues a record without blocking. If the buffer is full the record is
// dropped and Dropped() is incremented.
func (w *Writer) Log(r Record) {
	if r.Ts.IsZero() {
		r.Ts = time.Now()
	}
	select {
	case w.ch <- r:
		w.enqueued.Add(1)
	default:
		w.dropped.Add(1)
	}
}

// Close stops accepting records, flushes what is buffered, and waits for the
// worker to finish (bounded by ctx).
func (w *Writer) Close(ctx context.Context) {
	w.closeMu.Do(func() { close(w.ch) })
	select {
	case <-w.done:
	case <-ctx.Done():
	}
}

// Dropped, Enqueued and Written expose counters for metrics.
func (w *Writer) Dropped() int64  { return w.dropped.Load() }
func (w *Writer) Enqueued() int64 { return w.enqueued.Load() }
func (w *Writer) Written() int64  { return w.written.Load() }

func (w *Writer) run(ctx context.Context) {
	defer close(w.done)
	ticker := time.NewTicker(w.opts.Flush)
	defer ticker.Stop()

	batch := make([]Record, 0, w.opts.BatchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := w.sink.InsertBatch(ctx, batch); err != nil {
			if w.opts.OnError != nil {
				w.opts.OnError(err)
			}
			// Drop the batch (best-effort audit) but count it as lost.
			w.dropped.Add(int64(len(batch)))
		} else {
			w.written.Add(int64(len(batch)))
		}
		batch = batch[:0]
	}

	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case r, ok := <-w.ch:
			if !ok {
				flush()
				return
			}
			batch = append(batch, r)
			if len(batch) >= w.opts.BatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}
