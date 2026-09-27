package crawlreplay

import (
	"fmt"
	"math/rand/v2"
)

// Synth builds deterministic synthetic records for fixtures and sweeps.
// Every binding it creates is new unless a pool is named, so one generator
// can model any number of distinct clients.
type Synth struct {
	site  string
	rng   *rand.Rand
	seq   int64
	fresh uint64
}

// NewSynth starts a generator for one site pseudonym.
func NewSynth(site string, seed uint64) *Synth {
	// #nosec G404 -- fixtures must be reproducible; nothing here is a secret.
	return &Synth{site: site, rng: rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))}
}

// SynthKey returns a valid key pseudonym for fixture number n.
func SynthKey(n uint64) string { return fmt.Sprintf("k-%016x", n) }

// synthBinding returns a valid binding pseudonym for client number n.
func synthBinding(n uint64) string { return fmt.Sprintf("b-%016x", n) }

func (s *Synth) newBinding() string {
	s.fresh++
	return synthBinding(1<<48 | s.fresh)
}

// Traffic describes one workload on one key over a minute range.
type Traffic struct {
	From, To  int64  // inclusive Unix minutes
	PerMinute int    // requests per minute
	L2, L1    string // key pseudonyms; both empty for queryless dynamic traffic
	Label     string
	Episode   string
}

func (s *Synth) record(minute int64, t Traffic, binding string) Record {
	s.seq++
	r := Record{
		T: minute*60 + s.rng.Int64N(60), Seq: s.seq, Site: s.site, Binding: binding,
		Class: ClassDynamic, Status: 200, Label: t.Label, Episode: t.Episode,
	}
	if t.L2 != "" {
		r.Class, r.L2, r.L1 = ClassExpensive, t.L2, t.L1
	}
	return r
}

// Pool sends the traffic from a fixed pool of clients, uniformly.
func (s *Synth) Pool(t Traffic, clients int) []Record {
	pool := make([]string, clients)
	for i := range pool {
		pool[i] = s.newBinding()
	}
	var out []Record
	for m := t.From; m <= t.To; m++ {
		for range t.PerMinute {
			out = append(out, s.record(m, t, pool[s.rng.IntN(clients)]))
		}
	}
	return out
}

// Rotating sends the traffic from fresh clients that each make exactly q
// requests before the next one starts (the last client of the range may
// make fewer).
func (s *Synth) Rotating(t Traffic, q int) []Record {
	return s.rotating(t, q, func(int64) int { return t.PerMinute })
}

func (s *Synth) rotating(t Traffic, q int, perMinute func(int64) int) []Record {
	var out []Record
	binding, used := s.newBinding(), 0
	for m := t.From; m <= t.To; m++ {
		for range perMinute(m) {
			if used == q {
				binding, used = s.newBinding(), 0
			}
			out = append(out, s.record(m, t, binding))
			used++
		}
	}
	return out
}

// Heavy sends sources clients at perSource requests each per minute; with
// churn every minute uses new clients, otherwise the same ones.
func (s *Synth) Heavy(t Traffic, sources, perSource int, churn bool) []Record {
	var out []Record
	current := make([]string, sources)
	for m := t.From; m <= t.To; m++ {
		for i := range current {
			if churn || current[i] == "" {
				current[i] = s.newBinding()
			}
			for range perSource {
				out = append(out, s.record(m, t, current[i]))
			}
		}
	}
	return out
}

// Ramp sends fresh q-request clients at a rate rising linearly from
// startPerMin to endPerMin over the range.
func (s *Synth) Ramp(t Traffic, startPerMin, endPerMin, q int) []Record {
	span := max(1, t.To-t.From)
	return s.rotating(t, q, func(m int64) int {
		return startPerMin + int(int64(endPerMin-startPerMin)*(m-t.From)/span)
	})
}
