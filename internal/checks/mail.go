package checks

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/systemdrun"
)

// eximQueueTimeout bounds the queue probe. `exim -bpc` walks the spool, so it
// is slower on a deep queue but never long-running.
const eximQueueTimeout = 30 * time.Second

var errEximNotInstalled = errors.New("exim is not installed")

func CheckMailQueue(ctx context.Context, cfg *config.Config, _ *state.Store) []alert.Finding {
	count, err := eximQueueCount(ctx)
	if err != nil {
		if errors.Is(err, errEximNotInstalled) {
			return nil
		}
		// A queue depth CSM cannot read is a monitoring blind spot, not a
		// clean bill of health. Reporting nothing here is what let a fully
		// broken probe run unnoticed on a production host for months.
		return []alert.Finding{{
			Severity: alert.Warning,
			Check:    "mail_queue_unavailable",
			Message:  "Exim mail queue depth could not be read",
			Details: fmt.Sprintf("Spam-outbreak detection via queue depth is inactive until this succeeds. %v",
				err),
		}}
	}

	if count >= cfg.Thresholds.MailQueueCrit {
		return []alert.Finding{{
			Severity: alert.Critical,
			Check:    "mail_queue",
			Message:  fmt.Sprintf("Exim mail queue critical: %d messages", count),
			Details:  "Possible spam outbreak from compromised account",
		}}
	}
	if count >= cfg.Thresholds.MailQueueWarn {
		return []alert.Finding{{
			Severity: alert.Warning,
			Check:    "mail_queue",
			Message:  fmt.Sprintf("Exim mail queue elevated: %d messages", count),
		}}
	}
	return nil
}

// eximQueueCount returns the number of messages in the Exim queue.
//
// exim opens its own main log for append on every invocation and aborts when it
// cannot. Under the daemon's ProtectSystem=strict sandbox /var/log is read-only,
// so a direct call fails with "Cannot open main log file" and yields no count at
// all. Running the probe as a transient unit hands it to PID 1, outside the
// sandbox. Hosts without systemd-run have no sandbox to escape and call exim
// directly.
func eximQueueCount(parent context.Context) (int, error) {
	eximPath, err := cmdExec.LookPath("exim")
	if err != nil {
		return 0, fmt.Errorf("%w: %v", errEximNotInstalled, err)
	}
	ctx, cancel := context.WithTimeout(parent, eximQueueTimeout)
	defer cancel()

	out, err := systemdrun.Run(ctx, cmdExec.LookPath, cmdExec.RunContextStdout, systemdrun.Options{
		Pipe:       true,
		RuntimeMax: eximQueueTimeout,
	}, eximPath, "-bpc")
	if err != nil {
		return 0, fmt.Errorf("exim -bpc: %w", err)
	}
	return parseEximQueueCount(out)
}

func parseEximQueueCount(out []byte) (int, error) {
	trimmed := strings.TrimSpace(string(out))
	count, err := strconv.Atoi(trimmed)
	if err != nil {
		return 0, fmt.Errorf("exim -bpc returned %q, not a queue count", truncateForDetail(trimmed))
	}
	return count, nil
}

// truncateForDetail keeps an unexpected command output short enough to sit in a
// finding's Details without pasting a whole error page into the alert.
func truncateForDetail(s string) string {
	const max = 120
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
