// Package broadcast provides a one-to-many publish bus for alert.Finding
// events. Subscribers each get a buffered channel; if a subscriber's
// buffer fills, that subscriber drops the message rather than blocking
// the publisher. Used by the SSE event stream and any other in-process
// passive consumer.
//
// This is intentionally separate from the daemon's primary alert pipeline
// (the unbuffered or large-buffered alertCh that feeds Dispatch). The bus
// is a side-channel for observers that should not influence dispatch.
package broadcast

import (
	"sync"

	"github.com/pidginhost/csm/internal/alert"
)

// Bus fans out published findings to every subscriber.
type Bus struct {
	mu          sync.RWMutex
	subscribers map[chan alert.Finding]struct{}
	buffer      int
	closed      bool
}

// NewBus constructs a Bus with the given per-subscriber buffer.
// A buffer < 1 falls back to 16.
func NewBus(buffer int) *Bus {
	if buffer < 1 {
		buffer = 16
	}
	return &Bus{
		subscribers: make(map[chan alert.Finding]struct{}),
		buffer:      buffer,
	}
}

// Subscribe returns a new buffered channel that receives every published
// finding from this point forward. Caller must Unsubscribe when done to
// release resources.
func (b *Bus) Subscribe() <-chan alert.Finding {
	b.mu.Lock()
	defer b.mu.Unlock()
	ch := make(chan alert.Finding, b.buffer)
	if b.closed {
		close(ch)
		return ch
	}
	b.subscribers[ch] = struct{}{}
	return ch
}

// Unsubscribe removes the channel from the bus and closes it. Safe to
// call with a channel that was never subscribed (noop). The closed
// channel signals the consumer to exit its read loop.
func (b *Bus) Unsubscribe(ch <-chan alert.Finding) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for sub := range b.subscribers {
		if (<-chan alert.Finding)(sub) == ch {
			delete(b.subscribers, sub)
			close(sub)
			return
		}
	}
}

// Publish sends f to every current subscriber. Non-blocking: if a
// subscriber's buffer is full, that delivery is skipped.
func (b *Bus) Publish(f alert.Finding) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.closed {
		return
	}
	for ch := range b.subscribers {
		select {
		case ch <- f:
		default:
			// Slow subscriber; drop rather than block.
		}
	}
}

// Close shuts the bus down and closes every outstanding subscriber channel.
// Idempotent.
func (b *Bus) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	b.closed = true
	for ch := range b.subscribers {
		close(ch)
		delete(b.subscribers, ch)
	}
}
