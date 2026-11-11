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
		domain := ArrivalSenderDomain(line)
		if domain == "" {
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

// ArrivalSenderDomain returns the envelope-sender domain of an Exim arrival
// record, or "" for other records, bounces, cPanel system mail and senders
// without a domain.
func ArrivalSenderDomain(line string) string {
	_, sender, ok := eximlog.Arrival(line)
	if !ok || sender == "<>" || strings.HasPrefix(sender, "cPanel") {
		return ""
	}
	at := strings.LastIndex(sender, "@")
	if at < 0 {
		return ""
	}
	return sender[at+1:]
}
