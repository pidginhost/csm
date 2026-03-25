package checks

import (
	"fmt"
	"strings"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
)

// Checks that indicate active security events (not static config issues).
// Only these are used for cross-account correlation.
var securityEventChecks = map[string]bool{
	"fake_kernel_thread":            true,
	"suspicious_process":            true,
	"php_suspicious_execution":      true,
	"backdoor_binary":               true,
	"webshell":                      true,
	"new_webshell_file":             true,
	"new_executable_in_config":      true,
	"new_php_in_uploads":            true,
	"new_php_in_languages":          true,
	"new_php_in_upgrade":            true,
	"obfuscated_php":                true,
	"php_dropper":                   true,
	"webshell_realtime":             true,
	"php_in_uploads_realtime":       true,
	"php_in_sensitive_dir_realtime": true,
	"executable_in_config_realtime": true,
	"obfuscated_php_realtime":       true,
	"webshell_content_realtime":     true,
	"c2_connection":                 true,
	"cpanel_file_upload_realtime":   true,
	"shadow_change":                 true,
	"root_password_change":          true,
}

// CorrelateFindings analyzes findings for cross-account attack patterns.
// Only considers active security events, not static config issues
// (like WAF status, open_basedir, world-writable files).
func CorrelateFindings(findings []alert.Finding) []alert.Finding {
	var extra []alert.Finding

	// Count security event findings per account
	accountCriticals := make(map[string]int)
	for _, f := range findings {
		if f.Severity != alert.Critical {
			continue
		}
		if !securityEventChecks[f.Check] {
			continue
		}
		account := extractAccountFromFinding(f)
		if account != "" {
			accountCriticals[account]++
		}
	}

	// If 3+ accounts have critical security events, it's a coordinated attack
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
			Message:  fmt.Sprintf("Possible coordinated attack: %d accounts have critical security events", affectedAccounts),
			Details:  fmt.Sprintf("Affected accounts: %s", strings.Join(accountNames, ", ")),
		})
	}

	// Check for same malware type across accounts
	malwareByCheck := make(map[string][]string)
	for _, f := range findings {
		if f.Check == "new_executable_in_config" || f.Check == "backdoor_binary" ||
			f.Check == "webshell" || f.Check == "new_webshell_file" {
			account := extractAccountFromFinding(f)
			if account != "" {
				malwareByCheck[f.Check] = append(malwareByCheck[f.Check], account)
			}
		}
	}
	for check, accounts := range malwareByCheck {
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
