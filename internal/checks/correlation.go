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
// as one cross-account event in the persisted active set. A dispatch batch
// supplies its own grouping and can include carried-forward timestamps, so
// the batch callers do not apply this bound.
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
	// using the same window as the aggregates. Batch correlation has no age
	// filter; persisted correlation also counts unstamped legacy rows.
	Unattributed map[string]int
	// CriticalAccounts is the distinct attributed account count after the
	// same eligibility and time filters used to derive coordinated_attack.
	CriticalAccounts int
}

// Correlator shares production rules with offline replay. Construct one with
// NewCorrelator to supply recording roots without triggering host discovery.
type Correlator struct {
	window    time.Duration
	accountOf func(alert.Finding) string
}

// NewCorrelator uses only the supplied account roots, with no host lookups.
// Window must be nonnegative; zero reproduces unbounded correlation.
func NewCorrelator(window time.Duration, accountRoots []string) Correlator {
	roots := append([]string(nil), accountRoots...)
	return Correlator{window: window, accountOf: func(f alert.Finding) string {
		return extractAccountFromFindingAt(f, func() []string { return roots })
	}}
}

var defaultCorrelator = Correlator{window: correlationWindow, accountOf: extractAccountFromFinding}

// CorrelateFindings raises cross-account findings. Eligibility comes from
// the registry classification and identity from extractAccountFromFinding.
// Callers initialize platform.Detect before correlation so account roots
// come from its cache. It does not log or mutate its input.
func CorrelateFindings(findings []alert.Finding) CorrelationResult {
	return defaultCorrelator.Correlate(findings, time.Time{})
}

// CorrelateBatchFindings preserves dispatch grouping even when a scan carries
// forward a prior finding whose original timestamp lies outside the window.
func CorrelateBatchFindings(findings []alert.Finding) CorrelationResult {
	batch := defaultCorrelator
	batch.window = 0
	return batch.Correlate(findings, time.Time{})
}

// Correlate derives aggregates at the supplied observation time. A zero time
// uses the newest non-derived input as its reference. Persisted state supplies
// the merge time so even an empty scan can expire old evidence.
func (c Correlator) Correlate(findings []alert.Finding, at time.Time) CorrelationResult {
	res := CorrelationResult{Unattributed: make(map[string]int)}
	accounts := make(map[string]bool)
	malwareByCheck := make(map[string]map[string]bool)
	cutoff := c.cutoff(findings, at)
	for _, f := range findings {
		class := correlationClassOf(f.Check)
		if class != CorrelationSecurityEvent && class != CorrelationMalwareArtifact {
			continue
		}
		if observed := observedAt(f); c.window > 0 && !observed.IsZero() && observed.Before(cutoff) {
			continue
		}
		countsForAttack := f.Severity == alert.Critical
		countsForMalware := class == CorrelationMalwareArtifact
		if !countsForAttack && !countsForMalware {
			continue
		}
		account := c.accountOf(f)
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
	res.CriticalAccounts = len(accounts)
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
	return defaultCorrelator.InputOf(f)
}

// InputOf uses the same classification and identity rules as Correlate.
// Eligibility is the check class only, before severity and window filtering.
func (c Correlator) InputOf(f alert.Finding) (account string, eligible bool) {
	class := correlationClassOf(f.Check)
	eligible = class == CorrelationSecurityEvent || class == CorrelationMalwareArtifact
	return c.accountOf(f), eligible
}

// observedAt is when a finding's condition started: its first observation,
// falling back to its report time. A scan re-emits every finding it still
// sees with a fresh report time, so judging membership by Timestamp let a
// months-old condition re-enter the window on every cycle.
func observedAt(f alert.Finding) time.Time {
	if !f.FirstSeen.IsZero() {
		return f.FirstSeen
	}
	return f.Timestamp
}

// A missing timestamp must not silently discard legacy stored evidence.
func (c Correlator) cutoff(findings []alert.Finding, at time.Time) time.Time {
	if c.window == 0 {
		return time.Time{}
	}
	if at.IsZero() {
		for _, f := range findings {
			// Synthesized findings must not feed back into either aggregate
			// membership or attribution-health accounting. The reference is
			// the newest report, not the newest first observation: it stands
			// for "now" when the caller supplied no observation time.
			if !IsDerivedCorrelationCheck(f.Check) && f.Timestamp.After(at) {
				at = f.Timestamp
			}
		}
	}
	if at.IsZero() {
		return time.Time{}
	}
	return at.Add(-c.window)
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
	return extractAccountFromFindingAt(f, accountHomeRoots)
}

func extractAccountFromFindingAt(f alert.Finding, accountRoots func() []string) string {
	if f.TenantID != "" {
		return f.TenantID
	}
	roots := accountRoots()
	if filepath.IsAbs(f.FilePath) {
		if _, account, ok := accountRootOfAt(f.FilePath, roots); ok {
			return account
		}
	}
	for _, s := range []string{f.Message, f.Details} {
		if account := accountNameInTextAt(s, roots); account != "" {
			return account
		}
	}
	return ""
}
