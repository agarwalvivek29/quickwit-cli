package audit

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// fakeSink records batches and can optionally block or fail.
type fakeSink struct {
	mu       sync.Mutex
	batches  [][]Record
	entered  chan struct{}
	release  chan struct{}
	failWith error
}

func (f *fakeSink) InsertBatch(ctx context.Context, recs []Record) error {
	if f.entered != nil {
		f.entered <- struct{}{}
	}
	if f.release != nil {
		<-f.release
	}
	if f.failWith != nil {
		return f.failWith
	}
	cp := make([]Record, len(recs))
	copy(cp, recs)
	f.mu.Lock()
	f.batches = append(f.batches, cp)
	f.mu.Unlock()
	return nil
}

func (f *fakeSink) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, b := range f.batches {
		n += len(b)
	}
	return n
}

func rec(i string) Record { return Record{Index: i} }

func TestFlushBySize(t *testing.T) {
	sink := &fakeSink{}
	w := New(sink, Options{Buffer: 100, BatchSize: 3, Flush: time.Hour})
	w.Start(context.Background())
	for _, id := range []string{"a", "b", "c"} {
		w.Log(rec(id))
	}
	w.Close(context.Background())

	if got := w.Written(); got != 3 {
		t.Errorf("written = %d, want 3", got)
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.batches) != 1 || len(sink.batches[0]) != 3 {
		t.Errorf("expected a single batch of 3, got %v", sink.batches)
	}
}

func TestFlushByTicker(t *testing.T) {
	sink := &fakeSink{}
	w := New(sink, Options{Buffer: 100, BatchSize: 100, Flush: 30 * time.Millisecond})
	w.Start(context.Background())
	w.Log(rec("a"))

	deadline := time.Now().Add(2 * time.Second)
	for w.Written() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if w.Written() != 1 {
		t.Errorf("ticker flush: written = %d, want 1", w.Written())
	}
	w.Close(context.Background())
}

func TestDropOnFull(t *testing.T) {
	sink := &fakeSink{
		entered: make(chan struct{}, 10),
		release: make(chan struct{}),
	}
	w := New(sink, Options{Buffer: 2, BatchSize: 1, Flush: time.Hour})
	w.Start(context.Background())

	w.Log(rec("r1")) // worker picks this up and blocks inside InsertBatch
	<-sink.entered

	w.Log(rec("r2")) // buffered (1/2)
	w.Log(rec("r3")) // buffered (2/2, full)
	w.Log(rec("r4")) // dropped
	w.Log(rec("r5")) // dropped

	if w.Dropped() != 2 {
		t.Errorf("dropped = %d, want 2", w.Dropped())
	}
	if w.Enqueued() != 3 {
		t.Errorf("enqueued = %d, want 3", w.Enqueued())
	}

	close(sink.release) // let the worker drain
	w.Close(context.Background())

	if got := sink.count(); got != 3 {
		t.Errorf("persisted = %d, want 3", got)
	}
}

func TestInsertErrorCountsAsDropped(t *testing.T) {
	var gotErr error
	sink := &fakeSink{failWith: errors.New("db down")}
	w := New(sink, Options{Buffer: 10, BatchSize: 10, Flush: time.Hour, OnError: func(e error) { gotErr = e }})
	w.Start(context.Background())
	w.Log(rec("a"))
	w.Close(context.Background())

	if w.Written() != 0 {
		t.Errorf("written = %d, want 0", w.Written())
	}
	if w.Dropped() != 1 {
		t.Errorf("dropped = %d, want 1", w.Dropped())
	}
	if gotErr == nil {
		t.Error("OnError was not called")
	}
}

func TestPartitionNaming(t *testing.T) {
	got := partitionName(time.Date(2026, 8, 6, 15, 0, 0, 0, time.UTC))
	if got != "qw_audit_202608" {
		t.Errorf("partitionName = %q, want qw_audit_202608", got)
	}
	if ms := monthStart(time.Date(2026, 8, 6, 15, 4, 5, 0, time.UTC)); !ms.Equal(time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("monthStart = %v", ms)
	}
}
