package checks

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

func CheckMailQueue(ctx context.Context, cfg *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	out, err := runCmd("exim", "-bpc")
	if err != nil || out == nil {
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
