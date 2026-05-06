//go:build linux && bpf

package bpf

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	csmlog "github.com/pidginhost/csm/internal/log"
)

// Reader wraps cilium/ebpf's ringbuf.Reader with a per-feature decoder
// callback and a typed Go channel. Each BPF feature defines its own event
// struct (CSMConnEvent, CSMExecEvent, etc.) plus a decode func, then loops
// over Events() in its Run goroutine.
//
// The decoder runs on the reader goroutine; keep it allocation-light. Slow
// userspace work (allocating findings, IO) belongs in the consumer.
type Reader[T any] struct {
	rb      *ringbuf.Reader
	decode  func([]byte) (T, error)
	out     chan T
	count   atomic.Uint64
	dropped atomic.Uint64
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
	go func() {
		<-ctx.Done()
		_ = r.rb.Close()
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
			r.dropped.Add(1)
		}
	}
}

// Close releases the underlying reader. Run will return with ringbuf.ErrClosed.
func (r *Reader[T]) Close() error { return r.rb.Close() }
