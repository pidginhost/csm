package reporting

import (
	"context"
	"encoding/json"
	"log"
	"time"
)

// Spooler is the production Reporter: it enqueues minimized reports to a durable
// spool and drains them to all configured targets on an interval, retrying from
// the spool when a collector is down. It never blocks the alert path beyond a
// single bbolt write.
type Spooler struct {
	spool    *Spool
	sender   *Sender
	targets  map[string]Target
	order    []string
	interval time.Duration
	logf     func(string, ...any)
}

// NewSpooler builds a Spooler over a spool, a sender, and the configured
// targets. A zero interval defaults to one minute.
func NewSpooler(spool *Spool, sender *Sender, targets []Target, interval time.Duration) *Spooler {
	if interval <= 0 {
		interval = time.Minute
	}
	m := make(map[string]Target, len(targets))
	order := make([]string, 0, len(targets))
	for _, t := range targets {
		m[t.Name] = t
		order = append(order, t.Name)
	}
	return &Spooler{spool: spool, sender: sender, targets: m, order: order, interval: interval, logf: log.Printf}
}

// Enqueue persists r for delivery to every configured target. Dropped-count
// from spool overflow is logged so a sustained outage is visible.
func (s *Spooler) Enqueue(r Report) {
	body, err := json.Marshal(r)
	if err != nil {
		return
	}
	for _, name := range s.order {
		dropped, err := s.spool.Enqueue(name, body)
		if err != nil {
			s.logf("reporting: spool enqueue for %s failed: %v", name, err)
			continue
		}
		if dropped > 0 {
			s.logf("reporting: spool over capacity, dropped %d oldest reports for %s", dropped, name)
		}
	}
}

// DrainOnce attempts one delivery pass over the spool.
func (s *Spooler) DrainOnce(ctx context.Context) {
	_, err := s.spool.Drain(func(target string, body []byte) error {
		t, ok := s.targets[target]
		if !ok {
			// Target removed from config: drop the item by reporting success.
			return nil
		}
		return s.sender.Send(ctx, t, body)
	})
	if err != nil {
		s.logf("reporting: drain paused (will retry): %v", err)
	}
}

// Run drains the spool every interval until ctx is cancelled.
func (s *Spooler) Run(ctx context.Context) {
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.DrainOnce(ctx)
		}
	}
}
