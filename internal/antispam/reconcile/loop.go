package reconcile

import (
	"context"
	"time"
)

// Interval is how often a pass runs without a trigger (spec section 6.5).
const Interval = 15 * time.Minute

// Loop runs passes one at a time: at start, after each trigger, every
// Interval, and sooner when a pass asks to retry.
type Loop struct {
	pass     func(context.Context) Outcome
	report   func(Outcome)
	wake     chan struct{}
	interval time.Duration
}

// NewLoop returns a loop that calls pass and hands each outcome to report.
// pass reads the configuration itself, so each pass sees the latest one.
func NewLoop(pass func(context.Context) Outcome, report func(Outcome)) *Loop {
	return &Loop{pass: pass, report: report, wake: make(chan struct{}, 1), interval: Interval}
}

// Trigger asks for a pass. It never blocks: triggers that arrive while a
// pass runs become one more pass after it.
func (l *Loop) Trigger() {
	select {
	case l.wake <- struct{}{}:
	default:
	}
}

// Run passes until ctx ends.
func (l *Loop) Run(ctx context.Context) {
	for {
		out := l.pass(ctx)
		l.report(out)
		wait := l.interval
		if out.Retry > 0 && out.Retry < wait {
			wait = out.Retry
		}
		select {
		case <-ctx.Done():
			return
		case <-l.wake:
		case <-time.After(wait):
		}
	}
}
