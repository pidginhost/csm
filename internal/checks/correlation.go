package checks

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
)

// CorrelationResult is the output of one CorrelateFindings call.
type CorrelationResult struct {
	// Derived findings: the coordinated_attack result first, then one
	// cross_account_malware result per qualifying check, sorted by check.
	// Timestamps are left unset for the caller to stamp.
	Derived []alert.Finding
	// Unattributed counts qualifying input rows per check that carried no
	// account identity. It is a snapshot for this call, not a running total.
	Unattributed map[string]int
}

// CorrelateFindings raises cross-account findings. Eligibility comes from
// the registry classification and identity from extractAccountFromFinding.
// It performs no I/O, does not log and does not mutate its input.
func CorrelateFindings(findings []alert.Finding) CorrelationResult {
	res := CorrelationResult{Unattributed: make(map[string]int)}
	accounts := make(map[string]bool)
	malwareByCheck := make(map[string]map[string]bool)
	for _, f := range findings {
		class := correlationClassOf(f.Check)
		if class != CorrelationSecurityEvent && class != CorrelationMalwareArtifact {
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
