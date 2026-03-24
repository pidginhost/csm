package checks

import (
	"fmt"
	"strings"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
)

// CorrelateFindings analyzes findings for cross-account attack patterns.
// Called after all checks complete, adds correlation alerts if patterns match.
func CorrelateFindings(findings []alert.Finding) []alert.Finding {
	var extra []alert.Finding

	// Count critical findings per account
	accountCriticals := make(map[string]int)
	for _, f := range findings {
		if f.Severity != alert.Critical {
			continue
		}
		account := extractAccountFromFinding(f)
		if account != "" {
			accountCriticals[account]++
		}
	}

	// If 3+ accounts have critical findings, it's a coordinated attack
	affectedAccounts := 0
	var accountNames []string
	for account, count := range accountCriticals {
		if count > 0 {
			affectedAccounts++
			accountNames = append(accountNames, account)
		}
	}

	if affectedAccounts >= 3 {
		extra = append(extra, alert.Finding{
			Severity: alert.Critical,
			Check:    "coordinated_attack",
			Message:  fmt.Sprintf("Possible coordinated attack: %d accounts have critical findings", affectedAccounts),
			Details:  fmt.Sprintf("Affected accounts: %s", strings.Join(accountNames, ", ")),
		})
	}

	// Check for same malware hash across accounts
	malwareByHash := make(map[string][]string)
	for _, f := range findings {
		if f.Check == "new_executable_in_config" || f.Check == "backdoor_binary" {
			// Use message as key since it contains the path
			account := extractAccountFromFinding(f)
			if account != "" {
				malwareByHash[f.Check] = append(malwareByHash[f.Check], account)
			}
		}
	}
	for check, accounts := range malwareByHash {
		unique := uniqueStrings(accounts)
		if len(unique) >= 2 {
			extra = append(extra, alert.Finding{
				Severity: alert.Critical,
				Check:    "cross_account_malware",
				Message:  fmt.Sprintf("Same malware type (%s) found in %d accounts", check, len(unique)),
				Details:  fmt.Sprintf("Accounts: %s", strings.Join(unique, ", ")),
			})
		}
	}

	return extra
}

func extractAccountFromFinding(f alert.Finding) string {
	// Try to extract account name from message or details containing /home/<user>/
	for _, s := range []string{f.Message, f.Details} {
		if idx := strings.Index(s, "/home/"); idx >= 0 {
			rest := s[idx+6:]
			if slashIdx := strings.Index(rest, "/"); slashIdx > 0 {
				return rest[:slashIdx]
			}
		}
	}
	return ""
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
