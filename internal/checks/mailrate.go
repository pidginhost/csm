package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/eximlog"
	"github.com/pidginhost/csm/internal/state"
)

const perAccountMailThreshold = 100 // emails per recent log window

// mailLogTailLinesDefault is the built-in fallback for how many trailing
// lines of /var/log/exim_mainlog CheckMailPerAccount tails per cycle.
// Operator override: cfg.Thresholds.MailLogTailLines.
const mailLogTailLinesDefault = 500

// CheckMailPerAccount counts recent Exim arrivals per envelope-sender domain.
// Ownership requires the same verified submitter across the entire count.
func CheckMailPerAccount(ctx context.Context, cfg *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	tailLines := mailLogTailLinesDefault
	if cfg != nil && cfg.Thresholds.MailLogTailLines > 0 {
		tailLines = cfg.Thresholds.MailLogTailLines
	}
	lines := tailFile("/var/log/exim_mainlog", tailLines)

	// Keep the existing sender-domain volume calculation.
	type volume struct {
		count int
		owner string
	}
	counts := make(map[string]volume)
	for _, line := range lines {
		// Look for message arrivals (<=).
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

		identity := eximlog.Submitter(line)
		owner := ""
		if strings.Contains(identity, "@") {
			owner = MailOwner(identity)
		} else {
			owner = HostingAccountForUser(identity)
		}
		v := counts[domain]
		if v.count == 0 {
			v.owner = owner
		} else if v.owner != owner {
			v.owner = ""
		}
		v.count++
		counts[domain] = v
	}

	// Keep the sender-domain volume signal, including unverified messages.
	// Only a unanimous verified submitter establishes ownership of its count.
	for domain, v := range counts {
		if v.count >= perAccountMailThreshold {
			message := fmt.Sprintf("High email volume from %s: %d messages in recent log", domain, v.count)
			if v.owner != "" {
				message += fmt.Sprintf(" (account %s)", v.owner)
			}
			findings = append(findings, alert.Finding{
				Severity: alert.High,
				Check:    "mail_per_account",
				Message:  message,
				Details:  "Possible spam outbreak or compromised email account",
				Domain:   domain,
				TenantID: v.owner,
			})
		}
	}

	return findings
}
