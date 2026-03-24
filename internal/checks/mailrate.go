package checks

import (
	"fmt"
	"strings"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
	"github.com/pidginhost/cpanel-security-monitor/internal/config"
	"github.com/pidginhost/cpanel-security-monitor/internal/state"
)

const perAccountMailThreshold = 100 // emails per recent log window

// CheckMailPerAccount reads the tail of exim_mainlog and counts outbound
// emails per cPanel account. Alerts if a single account exceeds the threshold.
func CheckMailPerAccount(_ *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	lines := tailFile("/var/log/exim_mainlog", 500)

	// Count emails per sender domain/user
	// Exim log format: "... <= user@domain.com ..." for outgoing
	counts := make(map[string]int)
	for _, line := range lines {
		// Look for outgoing messages (<=)
		idx := strings.Index(line, " <= ")
		if idx < 0 {
			continue
		}

		// Extract sender address
		rest := line[idx+4:]
		fields := strings.Fields(rest)
		if len(fields) < 1 {
			continue
		}
		sender := fields[0]

		// Extract the domain part
		atIdx := strings.LastIndex(sender, "@")
		if atIdx < 0 {
			continue
		}
		domain := sender[atIdx+1:]

		// Skip system/bounce messages
		if domain == "" || sender == "<>" || strings.HasPrefix(sender, "cPanel") {
			continue
		}

		counts[domain]++
	}

	// Alert on accounts exceeding threshold
	for domain, count := range counts {
		if count >= perAccountMailThreshold {
			findings = append(findings, alert.Finding{
				Severity: alert.High,
				Check:    "mail_per_account",
				Message:  fmt.Sprintf("High email volume from %s: %d messages in recent log", domain, count),
				Details:  "Possible spam outbreak or compromised email account",
			})
		}
	}

	return findings
}
