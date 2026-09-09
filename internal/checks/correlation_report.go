package checks

import (
	"sync"
	"time"

	csmlog "github.com/pidginhost/csm/internal/log"
)

// AttributionReport is the operator-facing view of correlation attribution.
// Current is what the latest-state active set looks like right now;
// Cumulative is the history since the daemon started. The two answer
// different questions: a producer that lost attribution for weeks and one
// that missed once look identical in a log line, and neither is visible in
// a health endpoint without this.
type AttributionReport struct {
	// Current holds, per check, the qualifying rows in the latest-state
	// active set that carry no hosting owner, as of its most recent merge.
	// It clears when a later merge attributes them.
	Current map[string]int
	// Cumulative sums every unattributed row reported since start, by
	// check, across active-set merges and per-batch derivations.
	Cumulative map[string]int
	// ActiveSetUpdates counts active-set merges since start.
	ActiveSetUpdates int
	// Since is when the first active set was recorded; zero before then.
	Since time.Time
}

// unattributedReporter logs once per check name per process when
// cross-account correlation could not attribute a qualifying finding to a
// hosting account, and keeps the counts behind AttributionHealth. Per-call
// counts are never summed into the active-set snapshot; only the cumulative
// history adds them up.
type unattributedReporter struct {
	mu               sync.Mutex
	seen             map[string]struct{}
	current          map[string]int
	cumulative       map[string]int
	activeSetUpdates int
	since            time.Time
	warn             func(msg string, args ...any)
}

func newUnattributedReporter(warn func(string, ...any)) *unattributedReporter {
	return &unattributedReporter{
		seen:       make(map[string]struct{}),
		current:    make(map[string]int),
		cumulative: make(map[string]int),
		warn:       warn,
	}
}

// eligibleCounts keeps the entries that describe a real attribution loss:
// positive counts for checks that correlation would otherwise count.
func eligibleCounts(counts map[string]int) map[string]int {
	out := make(map[string]int, len(counts))
	for check, n := range counts {
		if n > 0 && securityEventEligible(check) {
			out[check] = n
		}
	}
	return out
}

type unattributedWarning struct {
	check string
	n     int
}

// record publishes all counters together and returns pending warnings so
// callers can release their merge locks before invoking the logger.
func (r *unattributedReporter) record(counts map[string]int, activeSet bool) []unattributedWarning {
	filtered := eligibleCounts(counts)
	var fresh []unattributedWarning
	r.mu.Lock()
	defer r.mu.Unlock()
	if activeSet {
		r.current = filtered
		r.activeSetUpdates++
		if r.since.IsZero() {
			r.since = time.Now()
		}
	}
	for check, n := range filtered {
		r.cumulative[check] += n
		if _, dup := r.seen[check]; !dup {
			r.seen[check] = struct{}{}
			fresh = append(fresh, unattributedWarning{check, n})
		}
	}
	return fresh
}

func (r *unattributedReporter) warnCounts(fresh []unattributedWarning) {
	for _, f := range fresh {
		r.warn("cross-account correlation could not attribute findings to an account", "check", f.check, "rows", f.n)
	}
}

// Report records a per-batch derivation: the rows count toward the
// cumulative history and warn once per check, but the active-set snapshot
// is untouched because a batch is not the persisted state.
func (r *unattributedReporter) Report(counts map[string]int) {
	r.warnCounts(r.record(counts, false))
}

// RecordActiveSet records the latest-state merge: it replaces the
// active-set snapshot, so a merge whose rows all carry owners clears it,
// and adds to the history like a batch report.
func (r *unattributedReporter) RecordActiveSet(counts map[string]int) {
	r.warnCounts(r.record(counts, true))
}

// Health returns a copy of the current state.
func (r *unattributedReporter) Health() AttributionReport {
	r.mu.Lock()
	defer r.mu.Unlock()
	return AttributionReport{
		Current:          copyCounts(r.current),
		Cumulative:       copyCounts(r.cumulative),
		ActiveSetUpdates: r.activeSetUpdates,
		Since:            r.since,
	}
}

func copyCounts(m map[string]int) map[string]int {
	out := make(map[string]int, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

var defaultUnattributedReporter = newUnattributedReporter(csmlog.Warn)

// ReportUnattributedCorrelation records unattributed rows from a per-batch
// derivation through the process-wide reporter. Callers invoke it after
// releasing any state store lock; it never re-enters the store.
func ReportUnattributedCorrelation(counts map[string]int) {
	defaultUnattributedReporter.Report(counts)
}

// RecordUnattributedActiveSet records the unattributed rows of the
// latest-state active set after a merge. Same locking contract as
// ReportUnattributedCorrelation.
func RecordUnattributedActiveSet(counts map[string]int) {
	defaultUnattributedReporter.RecordActiveSet(counts)
}

// AttributionHealth reports the process-wide attribution state for the
// health snapshot and doctor.
func AttributionHealth() AttributionReport {
	return defaultUnattributedReporter.Health()
}

// ResetAttributionHealthForTest replaces the process-wide reporter with a
// fresh one. Test-only.
func ResetAttributionHealthForTest() {
	defaultUnattributedReporter = newUnattributedReporter(csmlog.Warn)
}
