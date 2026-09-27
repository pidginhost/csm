package crawlreplay

import (
	"errors"
	"regexp"
)

// ErrFixture reports a fixture outside the generator's domain.
var ErrFixture = errors.New("crawlreplay: invalid fixture")

var fixtureName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// Fixture is a synthetic acceptance workload from spec 13: Train minutes
// of healthy background on one L1 key, then an attack on a sibling L1 key
// for Minutes, sent by fresh clients of Q requests each. The attack rate
// rises linearly from one request to PerMinute over the first RampMinutes
// (zero starts at full rate) and then holds. Optional heavy padding sources
// on the attack key change every minute when Churn is set.
type Fixture struct {
	Name             string `json:"name"`
	Train            int    `json:"train"`      // background minutes before the attack
	Background       int    `json:"background"` // background requests per minute
	Pool             int    `json:"pool"`       // background clients
	Minutes          int    `json:"minutes"`    // attack minutes
	PerMinute        int    `json:"per_minute"` // attack requests per minute
	RampMinutes      int    `json:"ramp_minutes"`
	Q                int    `json:"q"` // requests per attacking client
	PaddingSources   int    `json:"padding_sources"`
	PaddingPerSource int    `json:"padding_per_source"`
	Churn            bool   `json:"churn"`
	Seed             uint64 `json:"seed"`
}

// Validate checks the generator's domain.
func (f Fixture) Validate() error {
	switch {
	case !fixtureName.MatchString(f.Name), f.Train < 0, f.Background < 0,
		f.Background > 0 && f.Pool < 1, f.Minutes < 1, f.PerMinute < 1, f.Q < 1,
		f.RampMinutes < 0, f.RampMinutes > f.Minutes,
		f.PaddingSources < 0, f.PaddingPerSource < 0, (f.PaddingSources > 0) != (f.PaddingPerSource > 0):
		return ErrFixture
	}
	return nil
}

// fixtureSiteName is the fixed pseudonym of every synthetic site.
const fixtureSiteName = "dom-000000.example"

// Site builds the fixture's records, starting at a fixed minute so a
// fixture always lands on the same hour-of-week slots.
func (f Fixture) Site() Site {
	const start = int64(29_833_000)
	s := NewSynth(fixtureSiteName, f.Seed)
	parent, background, attack := SynthKey(1), SynthKey(2), SynthKey(3)
	end := start + int64(f.Train+f.Minutes) - 1
	var recs []Record
	if f.Background > 0 {
		recs = s.Pool(Traffic{From: start, To: end, PerMinute: f.Background, L2: parent, L1: background, Label: LabelHealthy}, f.Pool)
	}
	onset := start + int64(f.Train)
	attackTraffic := Traffic{From: onset, To: end, PerMinute: f.PerMinute, L2: parent, L1: attack, Label: LabelAttack, Episode: f.Name}
	steady := attackTraffic
	if f.RampMinutes > 0 {
		ramp := attackTraffic
		ramp.To = onset + int64(f.RampMinutes) - 1
		recs = append(recs, s.Ramp(ramp, 1, f.PerMinute, f.Q)...)
		steady.From = ramp.To + 1
	}
	if steady.From <= steady.To {
		recs = append(recs, s.Rotating(steady, f.Q)...)
	}
	if f.PaddingSources > 0 {
		recs = append(recs, s.Heavy(attackTraffic, f.PaddingSources, f.PaddingPerSource, f.Churn)...)
	}
	return Site{Records: recs, Coverage: []Span{{From: start, To: end}}}
}
