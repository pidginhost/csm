package daemon

import (
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
)

// expandWithCorrelation runs cross-account correlation over a dispatch
// batch and appends any synthesized findings that are not already present.
// The scan runner may have already produced the same synthetic findings, so
// this helper must be idempotent to avoid double-alerting the first batch.
func expandWithCorrelation(findings []alert.Finding, now time.Time) []alert.Finding {
	seen := make(map[string]struct{})
	for i := range findings {
		if !isCorrelationFinding(findings[i].Check) {
			continue
		}
		if findings[i].Timestamp.IsZero() {
			findings[i].Timestamp = now
		}
		seen[findings[i].Key()] = struct{}{}
	}

	extra := checks.CorrelateFindings(findings)
	for i := range extra {
		if extra[i].Timestamp.IsZero() {
			extra[i].Timestamp = now
		}
		key := extra[i].Key()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		findings = append(findings, extra[i])
	}
	return findings
}

func isCorrelationFinding(check string) bool {
	switch check {
	case "coordinated_attack", "cross_account_malware":
		return true
	default:
		return false
	}
}
