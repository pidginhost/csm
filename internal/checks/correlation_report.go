package checks

import (
	"sync"

	csmlog "github.com/pidginhost/csm/internal/log"
)

// unattributedReporter logs once per check name per process when
// cross-account correlation could not attribute a qualifying finding to a
// hosting account. Counts are per-call snapshots and are never summed; the
// reporter only makes a producer that never attributes visible.
type unattributedReporter struct {
	mu   sync.Mutex
	seen map[string]struct{}
	warn func(msg string, args ...any)
}

func newUnattributedReporter(warn func(string, ...any)) *unattributedReporter {
	return &unattributedReporter{seen: make(map[string]struct{}), warn: warn}
}

// Report warns for each eligible registered check in counts that has not
// been reported by this reporter before. Non-positive counts and names that
// are not eligible checks are ignored, so the seen set is bounded by the
// registry.
func (r *unattributedReporter) Report(counts map[string]int) {
	for check, n := range counts {
		if n <= 0 || !securityEventEligible(check) {
			continue
		}
		r.mu.Lock()
		_, dup := r.seen[check]
		if !dup {
			r.seen[check] = struct{}{}
		}
		r.mu.Unlock()
		if !dup {
			r.warn("cross-account correlation could not attribute findings to an account", "check", check, "rows", n)
		}
	}
}

var defaultUnattributedReporter = newUnattributedReporter(csmlog.Warn)

// ReportUnattributedCorrelation logs unattributed correlation rows through
// the process-wide reporter. Callers invoke it after releasing any state
// store lock; it never re-enters the store.
func ReportUnattributedCorrelation(counts map[string]int) {
	defaultUnattributedReporter.Report(counts)
}
