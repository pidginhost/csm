package daemon

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/store"
)

// compromiseEvidence says what a trigger saw. Sending evidence means abuse is
// already going out; login evidence means only that a password was cracked.
type compromiseEvidence uint8

const (
	evidenceSending compromiseEvidence = iota + 1
	evidenceLogin
)

// mailboxCompromise is one trigger's request to stop an abused credential.
// Subject is a mailbox ("user@domain"), a bare hosting account (no '@' or
// '.'), or a domain whose owning account is held.
type mailboxCompromise struct {
	Subject  string
	Check    string
	Reason   string
	Evidence compromiseEvidence
	At       time.Time
}

// mailBackend is the mail server's side of a suspension. suspend fills Kind,
// Account and Applied; the caller stamps the rest of the record.
type mailBackend interface {
	name() string
	suspend(c mailboxCompromise) (store.MailboxSuspension, error)
	release(rec store.MailboxSuspension, actor string) error
	active(recs []store.MailboxSuspension) (map[string]bool, error)
}

var activeMailBackend mailBackend = cpanelMailBackend{}

// respondToCompromise is the one entry point for stopping an abused mail
// credential. It honours the auto-response switch and dry-run, never repeats
// an active suspension, and after a release acts again only on evidence
// dated after it.
func respondToCompromise(cfg *config.Config, c mailboxCompromise) (stopped bool, findings []alert.Finding) {
	now := time.Now()
	stamp := now.Format("2006-01-02 15:04:05")
	if cfg == nil || !cfg.AutoResponse.Enabled {
		fmt.Fprintf(os.Stderr, "[%s] auto-suspend: would suspend %s (auto_response disabled)\n", stamp, c.Subject)
		return false, nil
	}
	if cfg.AutoResponseDryRunEnabled() {
		fmt.Fprintf(os.Stderr, "[%s] auto-suspend: would suspend %s (dry-run)\n", stamp, c.Subject)
		actionlog.Write(actionlog.Record{Op: dryRunMailOp(c.Subject), Target: c.Subject, Reason: c.Reason, Result: actionlog.DryRun})
		return false, nil
	}

	backend := activeMailBackend
	id := store.MailboxSuspensionID(backend.name(), c.Subject)
	db := store.Global()
	if db != nil {
		prev, ok, err := db.GetMailboxSuspension(id)
		switch {
		case err != nil:
			fmt.Fprintf(os.Stderr, "[%s] auto-suspend: reading suspension record for %s: %v\n", stamp, c.Subject, err)
		case ok && prev.ReleasedAt == nil:
			return true, nil
		case ok && !c.At.After(*prev.ReleasedAt):
			fmt.Fprintf(os.Stderr, "[%s] auto-suspend: %s was released at %s, after this evidence; not suspending again\n",
				stamp, c.Subject, prev.ReleasedAt.Format(time.RFC3339))
			return false, nil
		}
	}

	rec, err := backend.suspend(c)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] auto-suspend: could not stop %s: %v\n", stamp, c.Subject, err)
		return false, nil
	}
	rec.ID, rec.Backend, rec.Subject = id, backend.name(), c.Subject
	rec.Check, rec.Reason, rec.SuspendedAt = c.Check, c.Reason, now
	if db != nil {
		if err := db.PutMailboxSuspension(rec); err != nil {
			fmt.Fprintf(os.Stderr, "[%s] auto-suspend: recording suspension of %s: %v\n", stamp, c.Subject, err)
		}
	}
	return true, nil
}

// dryRunMailOp names the operation a dry run would have performed.
func dryRunMailOp(subject string) string {
	if strings.Contains(subject, "@") {
		return "respond.suspend_mailbox"
	}
	return "respond.hold_outgoing_mail"
}
