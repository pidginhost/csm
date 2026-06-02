//go:build linux && bpf

package bpf

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	csmlog "github.com/pidginhost/csm/internal/log"
)

// ringReader is the subset of *ringbuf.Reader that Reader depends on. It exists
// so the close/shutdown logic can be exercised without a privileged BPF map.
type ringReader interface {
	Read() (ringbuf.Record, error)
	Close() error
}

// Reader wraps cilium/ebpf's ringbuf.Reader with a per-feature decoder
// callback and a typed Go channel. Each BPF feature defines its own event
// struct (CSMConnEvent, CSMExecEvent, etc.) plus a decode func, then loops
// over Events() in its Run goroutine.
//
// The decoder runs on the reader goroutine; keep it allocation-light. Slow
// userspace work (allocating findings, IO) belongs in the consumer.
type Reader[T any] struct {
	rb        ringReader
	decode    func([]byte) (T, error)
	out       chan T
	count     atomic.Uint64
	dropped   atomic.Uint64
	closeOnce sync.Once
	closeErr  error
}

// NewReader takes a ringbuf-typed BPF map and a decoder. The map must have
// already been created and pinned (or kept alive) by the caller.
func NewReader[T any](m *ebpf.Map, decode func([]byte) (T, error)) (*Reader[T], error) {
	if m == nil {
		return nil, errors.New("nil ringbuf map")
	}
	if decode == nil {
		return nil, errors.New("nil decoder")
	}
	rb, err := ringbuf.NewReader(m)
	if err != nil {
		return nil, fmt.Errorf("ringbuf.NewReader: %w", err)
	}
	return &Reader[T]{
		rb:     rb,
		decode: decode,
		out:    make(chan T, 256),
	}, nil
}

// Events returns the channel that delivers decoded events. Closed when Run
// returns (either ctx.Done() or rb.Close()).
func (r *Reader[T]) Events() <-chan T { return r.out }

// EventCount returns the total number of decoded events emitted on the channel.
func (r *Reader[T]) EventCount() uint64 { return r.count.Load() }

// DroppedCount returns events that decoded successfully but were dropped
// because the consumer did not keep up with Events().
func (r *Reader[T]) DroppedCount() uint64 { return r.dropped.Load() }

// Run blocks until ctx is cancelled or the underlying reader is closed.
// Decoder errors are logged at warn level (do not stall the loop on a single
// malformed record).
func (r *Reader[T]) Run(ctx context.Context) {
	defer close(r.out)
	// Closing the reader is what unblocks the Read() below on shutdown. Both
	// this ctx watcher and an external Close() funnel through closeReader, which
	// runs exactly once, so the underlying ringbuf reader is never closed twice
	// (which would race cilium's reader teardown). The watcher exits when Run
	// returns -- via done -- so an external Close() does not leak it.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = r.closeReader()
		case <-done:
		}
	}()
	for {
		rec, err := r.rb.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			csmlog.Warn("bpf ringbuf read error", "err", err)
			return
		}
		ev, err := r.decode(rec.RawSample)
		if err != nil {
			csmlog.Warn("bpf ringbuf decode error", "err", err, "len", len(rec.RawSample))
			continue
		}
		select {
		case r.out <- ev:
			r.count.Add(1)
		default:
			dropped := r.dropped.Add(1)
			if shouldLogDroppedEvent(dropped) {
				csmlog.Warn("bpf ringbuf consumer back-pressure dropped events", "dropped_total", dropped, "events_delivered", r.count.Load())
			}
		}
	}
}

// Close releases the underlying reader. Run will return with ringbuf.ErrClosed.
// Idempotent and safe to call concurrently with Run's own ctx-driven close.
func (r *Reader[T]) Close() error { return r.closeReader() }

// closeReader closes the underlying ringbuf reader exactly once.
func (r *Reader[T]) closeReader() error {
	r.closeOnce.Do(func() { r.closeErr = r.rb.Close() })
	return r.closeErr
}
