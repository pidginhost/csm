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
}

// Baseline is one key's UTC hour-of-week profile of its total eligible
// non-infrastructure request rate, per minute.
type Baseline struct {
	p     BaselineParams
	first int64 // first observed minute
	slots [168]slot
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
	s := b.slots[hourOfWeek(m)]
	if m-b.first < b.p.MinAge || s.obs < b.p.MinObs || s.mean <= 0 {
		return b.p.FloorPerMin
	}
	return s.mean
}

// Observe folds one covered minute's total into its slot. Callers skip
// minutes the detector freezes and never pass a missing minute as zero.
func (b *Baseline) Observe(m, total int64) {
	s := &b.slots[hourOfWeek(m)]
	if s.obs == 0 {
		s.mean = float64(total)
	} else {
		// Weight the nonnegative terms separately so a small new total
		// is not lost when subtracting it from a much larger old mean.
		s.mean = (1-b.p.Alpha)*s.mean + b.p.Alpha*float64(total)
	}
	s.obs++
}
