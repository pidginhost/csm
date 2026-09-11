package queuehealth

import "time"

// MeasurementWindow is how long a queue must stay unmeasurable before that
// counts as a degradation. A kernel counter read can fail once, and positions
// loaded separately can produce one incoherent sample, without the queue
// having a problem.
const MeasurementWindow = 30 * time.Second

// Dwell reports whether a condition has held continuously for a window. The
// owner serializes its calls with the rest of its snapshot.
type Dwell struct {
	since time.Time
}

func (d *Dwell) Held(now time.Time, condition bool, window time.Duration) bool {
	if !condition {
		d.since = time.Time{}
		return false
	}
	if d.since.IsZero() {
		d.since = now
	}
	return now.Sub(d.since) >= window
}
