package reporting

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"
)

// Spooler is the production Reporter: it enqueues minimized reports to a durable
// spool and drains them to all configured targets on an interval, retrying from
// the spool when a collector is down. The daemon invokes persistence from its
// report worker so database writes do not block the alert path.
type Spooler struct {
	spool    *Spool
	sender   *Sender
	targets  map[string]Target
	order    []string
	interval time.Duration
	logf     func(string, ...any)
	now      func() time.Time
	drainMu  sync.Mutex
	retries  map[string]targetRetry // guarded by drainMu
}

type targetRetry struct {
	ready    time.Time
	backoff  time.Duration
	logAfter time.Time
}

var errRetryPending = errors.New("reporting: target waiting to retry")

// maxRequestedWait bounds a collector's Retry-After. Retry state lives in
// memory, so an unbounded value would park the target until a restart.
const maxRequestedWait = time.Hour

// A progressing collector may throttle normally. Preserve the failure for
// spool accounting without repeating a warning for each delivered batch.
type quietRetryError struct{ error }

func (e *quietRetryError) Unwrap() error { return e.error }

// NewSpooler builds a Spooler over a spool, a sender, and the configured
// targets. A zero interval defaults to one minute.
func NewSpooler(spool *Spool, sender *Sender, targets []Target, interval time.Duration) *Spooler {
	if interval <= 0 {
		interval = time.Minute
	}
	m := make(map[string]Target, len(targets))
	order := make([]string, 0, len(targets))
	seen := make(map[string]bool, len(targets))
	for _, t := range targets {
		m[t.Name] = t
		if !seen[t.Name] {
			order = append(order, t.Name)
			seen[t.Name] = true
		}
	}
	return &Spooler{spool: spool, sender: sender, targets: m, order: order, interval: interval,
		logf: log.Printf, now: time.Now, retries: make(map[string]targetRetry)}
}

// Enqueue persists r for delivery to every configured target. Dropped-count
// from spool overflow is logged so a sustained outage is visible.
func (s *Spooler) Enqueue(r Report) error {
	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
	var failures []error
	for _, name := range s.order {
		dropped, err := s.spool.Enqueue(name, body)
		if err != nil {
			failures = append(failures, fmt.Errorf("spool enqueue for %s: %w", name, err))
			continue
		}
		if dropped > 0 {
			s.logf("reporting: spool over capacity, dropped %d oldest reports for %s", dropped, name)
		}
	}
	return errors.Join(failures...)
}

// DrainOnce attempts one delivery pass over the spool and returns how long to
// wait before the next one. Retry deadlines belong to each target, so an
// earlier pass for another collector cannot shorten its requested wait.
func (s *Spooler) DrainOnce(ctx context.Context) time.Duration {
	s.drainMu.Lock()
	defer s.drainMu.Unlock()
	progress := make(map[string]bool)
	pending := make(map[string]time.Time)
	_, err := s.spool.Drain(func(target string, body []byte) error {
		t, ok := s.targets[target]
		if !ok {
			// Target removed from config: drop the item by reporting success.
			return nil
		}
		retry := s.retries[target]
		if s.now().Before(retry.ready) {
			pending[target] = retry.ready
			return errRetryPending
		}
		err := s.sender.Send(ctx, t, body)
		if err == nil || errors.Is(err, ErrReportRefused) {
			delete(s.retries, target)
			progress[target] = true
			return err
		}
		now := s.now()
		delay, quiet := s.interval, false
		var throttled *ThrottledError
		if errors.As(err, &throttled) && throttled.RetryAfter > 0 {
			// No progress across passes is an outage, even if the collector
			// keeps asking for a short retry. Bound scans and warning volume.
			backoff := min(s.interval, throttled.RetryAfter)
			if retry.backoff > 0 {
				backoff = max(backoff, retry.backoff+min(retry.backoff, s.interval-retry.backoff))
			}
			retry.backoff = backoff
			delay = max(min(throttled.RetryAfter, maxRequestedWait), backoff)
			quiet = progress[target] || now.Before(retry.logAfter)
			if !quiet {
				retry.logAfter = now.Add(s.interval)
			}
		} else {
			retry.backoff = 0
			retry.logAfter = time.Time{}
		}
		retry.ready = now.Add(delay)
		s.retries[target] = retry
		pending[target] = retry.ready
		if quiet {
			return &quietRetryError{err}
		}
		return err
	})
	next := s.interval
	for _, ready := range pending {
		next = min(next, max(0, ready.Sub(s.now())))
	}
	var failures []error
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		failures = joined.Unwrap()
	} else if err != nil {
		failures = []error{err}
	}
	var logged []error
	for _, failure := range failures {
		var quiet *quietRetryError
		if errors.Is(failure, errRetryPending) || errors.As(failure, &quiet) {
			continue
		}
		logged = append(logged, failure)
	}
	if err := errors.Join(logged...); err != nil {
		// Failed reports remain queued; refused reports were dropped.
		s.logf("reporting: delivery incomplete: %v", err)
	}
	return next
}

// Run drains the spool until ctx is cancelled, each pass when the previous
// one asked.
func (s *Spooler) Run(ctx context.Context) {
	t := time.NewTimer(s.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			t.Reset(s.DrainOnce(ctx))
		}
	}
}
