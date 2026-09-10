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
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/queuehealth"
)

// defaultMaxSubscribers caps concurrent subscribers so a flood of event-stream
// connections (each a goroutine plus a buffered channel) cannot exhaust the
// daemon's memory. Generous for an operator dashboard.
const defaultMaxSubscribers = 256

// Bus fans out published findings to every subscriber.
type Bus struct {
	mu          sync.RWMutex
	subscribers map[*Subscription]struct{}
	buffer      int
	maxSubs     int
	closed      bool
	stats       *queuehealth.Tracker
}

// NewBus constructs a Bus with the given per-subscriber buffer.
// A buffer < 1 falls back to 16.
func NewBus(buffer int) *Bus {
	if buffer < 1 {
		buffer = 16
	}
	return &Bus{
		subscribers: make(map[*Subscription]struct{}),
		buffer:      buffer,
		maxSubs:     defaultMaxSubscribers,
		stats:       queuehealth.New(0, time.Minute),
	}
}

// SetMaxSubscribers overrides the concurrent-subscriber cap. A value < 1 is
// ignored. Safe to call before the bus is in use.
func (b *Bus) SetMaxSubscribers(n int) {
	if n < 1 {
		return
	}
	b.mu.Lock()
	b.maxSubs = n
	b.mu.Unlock()
}

// TrySubscribe is Subscribe with the concurrent-subscriber cap enforced. It
// returns ok=false when the cap is reached so an untrusted caller (the SSE
// endpoint, reachable with a low-trust read token) cannot open unbounded
// long-lived streams. Use this for externally-driven subscriptions; Subscribe
// remains for trusted in-process consumers.
func (b *Bus) TrySubscribe() (*Subscription, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.closed && len(b.subscribers) >= b.maxSubs {
		return nil, false
	}
	return b.subscribe(), true
}

// Subscribe is for trusted in-process consumers. Every received delivery must
// be processed once, and the consumer must Unsubscribe when it stops reading.
func (b *Bus) Subscribe() *Subscription {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.subscribe()
}

func (b *Bus) subscribe() *Subscription {
	sub := &Subscription{events: make(chan Delivery, b.buffer), stats: queuehealth.New(b.buffer, time.Minute)}
	if b.closed {
		close(sub.events)
	} else {
		b.subscribers[sub] = struct{}{}
	}
	return sub
}

// Unsubscribe withdraws demand for unread events, for example when a browser
// tab closes. A delivery already received remains the consumer's responsibility.
func (b *Bus) Unsubscribe(sub *Subscription) {
	b.unsubscribe(sub, false)
}

// Abort removes a failed consumer and counts its unread deliveries as lost.
func (b *Bus) Abort(sub *Subscription) {
	b.unsubscribe(sub, true)
}

func (b *Bus) unsubscribe(sub *Subscription, failed bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.subscribers[sub]; !ok {
		return
	}
	delete(b.subscribers, sub)
	if !b.closed {
		close(sub.events)
	}
	for delivery := range sub.events {
		delivery.finish(failed)
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
	for sub := range b.subscribers {
		now := time.Now()
		delivery := Delivery{finding: f, total: b.stats.Begin(now), local: sub.stats.Begin(now)}
		select {
		case sub.events <- delivery:
		default:
			delivery.finish(true)
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
	// Consumers may still drain buffered deliveries after close. Retain their
	// capacity and ownership until they unsubscribe.
	for sub := range b.subscribers {
		close(sub.events)
	}
}
