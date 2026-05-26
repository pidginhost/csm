package daemon

import (
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
)

// expandWithCorrelation runs cross-account correlation over a batch of
// findings and returns the input slice extended with any synthesized
// findings (currently "coordinated_attack" and "cross_account_malware").
// Synthetic findings that arrive without a timestamp get stamped with
// `now` so downstream consumers (incident correlator, alert dispatch,
// store) always see a non-zero time.
//
// Lifted from daemon.go so both the initial-scan path and the steady-
// state tick can call it. Before, only the steady-state tick ran the
// cross-account aggregation, which meant the first batch after a daemon
// restart could carry three account compromises and never emit the
// coordinated-attack synthetic finding.
func expandWithCorrelation(findings []alert.Finding, now time.Time) []alert.Finding {
	extra := checks.CorrelateFindings(findings)
	for i := range extra {
		if extra[i].Timestamp.IsZero() {
			extra[i].Timestamp = now
		}
	}
	return append(findings, extra...)
}
