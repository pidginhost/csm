// Package main replays a recorded finding stream through the production
// cross-account correlation so its thresholds can be re-derived against what
// hosts actually produced, instead of against an assumption.
package main

import (
	"sort"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/platform"
)

// Event is one recorded finding in arrival order. At is the audit timestamp,
// which is also the finding's own timestamp; they are kept separately because
// the replay orders by arrival while correlation reads the finding.
type Event struct {
	At      time.Time
	Finding alert.Finding
}

// Batches groups events into dispatch batches. The audit log records no batch
// boundaries, so a gap in arrival time stands in for one: the daemon dispatches
// what accumulated between wakeups, and findings from one scan cycle or one
// burst of file events land together.
func Batches(events []Event, gap time.Duration) [][]Event {
	var out [][]Event
	var current []Event
	for i, e := range events {
		if i > 0 && e.At.Sub(events[i-1].At) > gap {
			out = append(out, current)
			current = nil
		}
		current = append(current, e)
	}
	if len(current) > 0 {
		out = append(out, current)
	}
	return out
}

// ActiveSet models the store's latest-findings state: findings are keyed the
// way alert.Finding.Key keys them, a repeat replaces the stored row rather than
// adding one, and the newest rows win at the cap. Window is the retention the
// store does not currently have: zero keeps every row, which is today's
// behaviour, and a positive value drops rows older than the newest arrival.
type ActiveSet struct {
	window time.Duration
	cap    int
	byKey  map[string]alert.Finding
	newest time.Time
}

// activeSetCap mirrors the store's own bound on the latest-findings set.
const activeSetCap = 15000

func NewActiveSet(window time.Duration) *ActiveSet {
	return &ActiveSet{window: window, cap: activeSetCap, byKey: make(map[string]alert.Finding)}
}

// Admit merges one finding, then evicts anything the window or the cap no
// longer holds. It reports whether any eviction happened, which tells a caller
// the derived result may have changed even though this finding did not feed it.
func (s *ActiveSet) Admit(f alert.Finding) (evicted bool) {
	if f.Timestamp.After(s.newest) {
		s.newest = f.Timestamp
	}
	// The store keeps a condition's first observation across re-reports.
	// Mirror it, or the replay measures a behaviour production no longer has.
	f.FirstSeen = earliestObservation(s.byKey[f.Key()], f)
	s.byKey[f.Key()] = f
	return s.evict()
}

func (s *ActiveSet) evict() (evicted bool) {
	if s.window > 0 {
		cutoff := s.newest.Add(-s.window)
		for key, f := range s.byKey {
			if !f.Timestamp.IsZero() && f.Timestamp.Before(cutoff) {
				delete(s.byKey, key)
				evicted = true
			}
		}
	}
	if len(s.byKey) <= s.cap {
		return evicted
	}
	ordered := s.Findings()
	for _, f := range ordered[s.cap:] {
		delete(s.byKey, f.Key())
		evicted = true
	}
	return evicted
}

// earliestObservation mirrors the store's rule: the stored row's first
// observation wins, falling back to timestamps for rows that carry none.
func earliestObservation(stored, reported alert.Finding) time.Time {
	var earliest time.Time
	for _, t := range []time.Time{stored.FirstSeen, stored.Timestamp, reported.FirstSeen, reported.Timestamp} {
		if t.IsZero() {
			continue
		}
		if earliest.IsZero() || t.Before(earliest) {
			earliest = t
		}
	}
	return earliest
}

// Snapshot returns the set in map order. Correlation does not care about
// order, and sorting the whole set on every derivation dominates a replay of
// a few hundred thousand events.
func (s *ActiveSet) Snapshot() []alert.Finding {
	out := make([]alert.Finding, 0, len(s.byKey))
	for _, f := range s.byKey {
		out = append(out, f)
	}
	return out
}

// Findings returns the set in the store's order: severity first, then newest,
// then key, so a cap drops the oldest low-severity rows.
func (s *ActiveSet) Findings() []alert.Finding {
	out := make([]alert.Finding, 0, len(s.byKey))
	for _, f := range s.byKey {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return out[i].Severity > out[j].Severity
		}
		if !out[i].Timestamp.Equal(out[j].Timestamp) {
			return out[i].Timestamp.After(out[j].Timestamp)
		}
		return out[i].Key() < out[j].Key()
	})
	return out
}

// Pairs reports how many rows the stream carries and how many distinct
// account-and-check combinations produced them. Repeated pairs can represent
// different findings on the same account, not just re-reports of one finding.
func Pairs(events []Event) (rows, pairs int) {
	seen := make(map[[2]string]bool)
	correlator := recordingCorrelator(0)
	for _, e := range events {
		account, eligible := correlator.InputOf(e.Finding)
		if !eligible || account == "" {
			continue
		}
		rows++
		seen[[2]string{account, e.Finding.Check}] = true
	}
	return rows, len(seen)
}

// Spread accumulates the distinct-account count seen at each derivation
// point, so one replay answers what every candidate threshold would have
// done instead of needing a replay per candidate.
type Spread struct {
	counts []int
	max    int
}

func (s *Spread) Observe(accounts int) {
	s.counts = append(s.counts, accounts)
	if accounts > s.max {
		s.max = accounts
	}
}

// AtLeast reports how many derivation points carried threshold accounts or
// more, which is how often that threshold would have raised the aggregate.
func (s *Spread) AtLeast(threshold int) int {
	n := 0
	for _, c := range s.counts {
		if c >= threshold {
			n++
		}
	}
	return n
}

func (s *Spread) Max() int    { return s.max }
func (s *Spread) Points() int { return len(s.counts) }

// Firing is one point in the replay where correlation raised an aggregate.
type Firing struct {
	At    time.Time
	Check string
}

// Derive runs the production correlation over one set of findings and reports
// both the aggregates it raised and the distinct-account count that decided
// them, so a threshold can be re-derived from the same replay.
func Derive(at time.Time, findings []alert.Finding, window time.Duration) (fires []Firing, criticalAccounts int) {
	res := recordingCorrelator(window).Correlate(findings, at)
	for _, d := range res.Derived {
		fires = append(fires, Firing{At: at, Check: d.Check})
	}
	return fires, res.CriticalAccounts
}

func recordingCorrelator(window time.Duration) checks.Correlator {
	// Recordings use cPanel account paths. Constructing Info is pure;
	// Detect would read files and execute commands on the replay machine.
	info := platform.Info{Panel: platform.PanelCPanel}
	return checks.NewCorrelator(window, info.AccountHomeRoots())
}
