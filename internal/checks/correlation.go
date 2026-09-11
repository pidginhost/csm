package checks

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// correlationWindow bounds how far apart two findings may be and still count
// as one cross-account event. A dispatch batch is stamped within milliseconds,
// so the bound is inert there; it matters for the persisted active set, which
// holds every current finding on the host and has no age of its own.
//
// Without it the aggregate is a latch rather than an alert: replaying a
// 100-day recording of one production host left coordinated_attack raised for
// 76% of the recording, and a two-day recording of a second host for 99%,
// because the first three accounts that ever carried a critical finding never
// left the set. One hour was chosen against those recordings: it holds the
// aggregate raised for 2.4% of the first recording where six hours leaves
// 19.6% and a day leaves 46.1%, and it still spans a full scan sweep, whose
// findings land together. Re-derive it with scripts/correlation-calibrate.
const correlationWindow = time.Hour

// CorrelationResult is the output of one CorrelateFindings call.
type CorrelationResult struct {
	// Derived findings: the coordinated_attack result first, then one
	// cross_account_malware result per qualifying check, sorted by check.
	// Timestamps are left unset for the caller to stamp.
	Derived []alert.Finding
	// Unattributed counts qualifying input rows per check that carried no
	// account identity. It is a snapshot for this call, not a running total,
	// and it counts only rows inside the correlation window: a finding too old
	// to affect an aggregate is not an input whose attribution matters.
	Unattributed map[string]int
}

// CorrelateFindings raises cross-account findings. Eligibility comes from
// the registry classification and identity from extractAccountFromFinding.
// Callers initialize platform.Detect before correlation so account roots
// come from its cache. It does not log or mutate its input.
func CorrelateFindings(findings []alert.Finding) CorrelationResult {
	res := CorrelationResult{Unattributed: make(map[string]int)}
	accounts := make(map[string]bool)
	malwareByCheck := make(map[string]map[string]bool)
	cutoff := correlationCutoff(findings)
	for _, f := range findings {
		class := correlationClassOf(f.Check)
		if class != CorrelationSecurityEvent && class != CorrelationMalwareArtifact {
			continue
		}
		if !f.Timestamp.IsZero() && f.Timestamp.Before(cutoff) {
			continue
		}
		countsForAttack := f.Severity == alert.Critical
		countsForMalware := class == CorrelationMalwareArtifact
		if !countsForAttack && !countsForMalware {
			continue
		}
		account := extractAccountFromFinding(f)
		if account == "" {
			res.Unattributed[f.Check]++
			continue
		}
		if countsForAttack {
			accounts[account] = true
		}
		if countsForMalware {
			if malwareByCheck[f.Check] == nil {
				malwareByCheck[f.Check] = make(map[string]bool)
			}
			malwareByCheck[f.Check][account] = true
		}
	}
	if len(accounts) >= 3 {
		names := sortedKeys(accounts)
		res.Derived = append(res.Derived, alert.Finding{
			Severity: alert.Critical,
			Check:    "coordinated_attack",
			Message:  fmt.Sprintf("Possible coordinated attack: %d accounts have critical security events", len(names)),
			Details:  fmt.Sprintf("Affected accounts: %s", strings.Join(names, ", ")),
		})
	}
	for _, check := range sortedKeys(malwareByCheck) {
		names := sortedKeys(malwareByCheck[check])
		if len(names) < 2 {
			continue
		}
		res.Derived = append(res.Derived, alert.Finding{
			Severity: alert.Critical,
			Check:    "cross_account_malware",
			Message:  fmt.Sprintf("Same malware type (%s) found in %d accounts", check, len(names)),
			Details:  fmt.Sprintf("Accounts: %s", strings.Join(names, ", ")),
		})
	}
	return res
}

// CorrelationInputOf reports how one finding enters cross-account
// correlation: the hosting account it resolves to, empty when none could be
// determined, and whether its check is an eligible input at all. It applies
// the same registry classification and identity rules CorrelateFindings uses,
// so a caller can explain or calibrate a correlation result without
// re-implementing them. Eligibility here is the check's class only; whether a
// given finding then counts also depends on its severity.
func CorrelationInputOf(f alert.Finding) (account string, eligible bool) {
	class := correlationClassOf(f.Check)
	eligible = class == CorrelationSecurityEvent || class == CorrelationMalwareArtifact
	return extractAccountFromFinding(f), eligible
}

// correlationCutoff is the oldest timestamp that still counts towards an
// aggregate: the newest finding in the set, less the window. A finding with no
// timestamp predates the fix that stamps every finding and is always counted,
// so an old stored row cannot drop out of correlation silently.
func correlationCutoff(findings []alert.Finding) time.Time {
	var newest time.Time
	for _, f := range findings {
		if f.Timestamp.After(newest) {
			newest = f.Timestamp
		}
	}
	if newest.IsZero() {
		return time.Time{}
	}
	return newest.Add(-correlationWindow)
}

func uniqueStrings(input []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, s := range input {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// extractAccountFromFinding resolves the hosting account a finding belongs
// to: the producer's TenantID verbatim, then the account home that contains
// an absolute FilePath, then the legacy free-text scan of Message and
// Details. The structured sources win so a path mentioned in free text
// cannot re-attribute a finding whose producer knew its owner.
func extractAccountFromFinding(f alert.Finding) string {
	if f.TenantID != "" {
		return f.TenantID
	}
	if filepath.IsAbs(f.FilePath) {
		if _, account, ok := accountRootOf(f.FilePath); ok {
			return account
		}
	}
	for _, s := range []string{f.Message, f.Details} {
		if account := accountNameInText(s); account != "" {
			return account
		}
	}
	return ""
}
