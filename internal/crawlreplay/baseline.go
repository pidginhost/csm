package crawlreplay

import (
	"errors"
	"math"
)

// ErrParams reports a parameter set outside the detector's domain.
var ErrParams = errors.New("crawlreplay: invalid parameters")

// BaselineParams are the hour-of-week profile settings phase 1 freezes.
type BaselineParams struct {
	Alpha       float64 `json:"alpha"`         // EWMA weight of each new complete minute, in (0,1]
	MinObs      int     `json:"min_obs"`       // observed minutes a slot needs before it is trusted
	MinAge      int64   `json:"min_age"`       // minutes after a key's first observation before any slot is trusted
	FloorPerMin float64 `json:"floor_per_min"` // fixed host-profile floor, requests per minute
}

// Validate checks the domain constraints; it approves no tuning value.
func (p BaselineParams) Validate() error {
	switch {
	case math.IsNaN(p.Alpha) || p.Alpha <= 0 || p.Alpha > 1,
		p.MinObs < 1, p.MinAge < 0,
		math.IsNaN(p.FloorPerMin) || math.IsInf(p.FloorPerMin, 0) || p.FloorPerMin <= 0:
		return ErrParams
	}
	return nil
}

type slot struct {
	mean float64
	obs  int
	last int64 // minute of the latest observation
}

// Baseline is one key's UTC hour-of-week profile of its total eligible
// non-infrastructure request rate, per minute.
type Baseline struct {
	p       BaselineParams
	first   int64 // first observed minute
	learned int64 // latest observed minute: each minute is learned at most once
	slots   [168]slot
}

// NewBaseline starts a cold profile for a key first observed at minute first.
func NewBaseline(p BaselineParams, first int64) *Baseline {
	return &Baseline{p: p, first: first}
}

// hourOfWeek maps a Unix minute to its UTC hour-of-week slot, Monday 00:00
// first. The Unix epoch began on a Thursday, three days after a Monday.
func hourOfWeek(minute int64) int {
	return int((minute/60 + 72) % 168)
}

// Expected is the per-minute expectation for minute m. Until the key is old
// enough and the slot has enough observations, and whenever the learned
// expectation is zero, the fixed floor applies.
func (b *Baseline) Expected(m int64) float64 {
	v, _ := b.expected(m)
	return v
}

func (b *Baseline) expected(m int64) (float64, bool) {
	return expected(b.p, b.first, m, &b.slots[hourOfWeek(m)])
}

// expected returns the expectation for a slot judged at minute age, and
// whether it came from the trained slot rather than the floor.
func expected(p BaselineParams, first, age int64, s *slot) (float64, bool) {
	if age-first < p.MinAge || s.obs < p.MinObs || s.mean <= 0 {
		return p.FloorPerMin, false
	}
	return s.mean, true
}

// Observe folds one complete minute's total into its slot and reports
// whether it learned. A minute at or before the latest learned one is
// refused, so no minute counts twice. Callers skip minutes the detector
// freezes and never pass a missing minute as zero.
func (b *Baseline) Observe(m, total int64) bool {
	if m <= b.learned {
		return false
	}
	s := &b.slots[hourOfWeek(m)]
	if s.obs == 0 {
		s.mean = float64(total)
	} else {
		// Weight the nonnegative terms separately so a small new total
		// is not lost when subtracting it from a much larger old mean.
		s.mean = (1-b.p.Alpha)*s.mean + b.p.Alpha*float64(total)
	}
	s.obs++
	s.last, b.learned = m, m
	return true
}

// Profile is a baseline pinned when an episode begins (spec 6.4): its slots
// and trust as they were then, so neither later learning nor the key coming
// of age during the episode moves the expectation it is judged against.
type Profile struct {
	p     BaselineParams
	first int64
	at    int64 // the pinning minute
	slots [168]slot
}

// Pin copies the profile as it stands at minute at.
func (b *Baseline) Pin(at int64) Profile {
	return Profile{p: b.p, first: b.first, at: at, slots: b.slots}
}

// Expected is the pinned expectation for minute m. Minutes before the pin
// keep the trust they had then; later minutes keep the trust of the pinning
// minute.
func (p *Profile) Expected(m int64) float64 {
	v, _ := p.expected(m)
	return v
}

func (p *Profile) expected(m int64) (float64, bool) {
	return expected(p.p, p.first, min(m, p.at), &p.slots[hourOfWeek(m)])
}
