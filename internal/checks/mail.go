package checks

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
	"github.com/pidginhost/cpanel-security-monitor/internal/config"
	"github.com/pidginhost/cpanel-security-monitor/internal/state"
)

func CheckMailQueue(cfg *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	// Get exim queue count
	out, err := exec.Command("exim", "-bpc").Output()
	if err != nil {
		return nil
	}

	count, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		return nil
	}

	if count >= cfg.Thresholds.MailQueueCrit {
		findings = append(findings, alert.Finding{
			Severity: alert.Critical,
			Check:    "mail_queue",
			Message:  fmt.Sprintf("Exim mail queue critical: %d messages", count),
			Details:  "Possible spam outbreak from compromised account",
		})
	} else if count >= cfg.Thresholds.MailQueueWarn {
		findings = append(findings, alert.Finding{
			Severity: alert.Warning,
			Check:    "mail_queue",
			Message:  fmt.Sprintf("Exim mail queue elevated: %d messages", count),
		})
	}

	return findings
}
