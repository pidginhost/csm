package daemon

import (
	"fmt"
	"os"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
)

// mailFilterEvidence records each outside redirect the mail filter audit
// reports as compromise evidence for its mailbox. The redirect keeps its own
// finding; the ledger adds it to the mailbox's other signs. The script stays
// in place as evidence.
func mailFilterEvidence(cfg *config.Config, findings []alert.Finding) []alert.Finding {
	var out []alert.Finding
	for _, f := range findings {
		if f.Check != "email_filter_exfil" || f.Mailbox == "" {
			continue
		}
		dest := checks.MailFilterDestination(f)
		if dest == "" {
			continue
		}
		at := f.Timestamp
		if at.IsZero() {
			at = time.Now()
		}
		// The file time dates the redirect against the mailbox's logins.
		var since time.Time
		if info, err := os.Lstat(f.FilePath); err == nil {
			since = info.ModTime()
			// An active link can predate the rule written through it.
			if info.Mode()&os.ModeSymlink != 0 {
				if target, err := os.Stat(f.FilePath); err == nil {
					since = maxTime(since, target.ModTime())
				}
			}
		}
		out = append(out, observeMailboxSignal(cfg, f.Mailbox, mailboxSignal{
			kind: signalRedirect, key: dest, at: at, since: since,
			detail: fmt.Sprintf("mail filter %s sends mail to %s", f.FilePath, dest),
		})...)
	}
	return out
}
