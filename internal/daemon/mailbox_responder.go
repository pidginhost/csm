package daemon

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
	"github.com/pidginhost/csm/internal/store"
	"github.com/pidginhost/csm/internal/webui"
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
	Previous store.MailboxSuspension
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

// Keep the server mutation, record update and evidence reset in one critical
// section. References include waiters so a lock cannot be replaced underneath
// them; idle subjects do not accumulate in this map.
var mailResponseLocks = struct {
	sync.Mutex
	entries map[string]*mailResponseLock
}{entries: make(map[string]*mailResponseLock)}

type mailResponseLock struct {
	mu   sync.Mutex
	refs int
}

func lockMailResponse(key string) func() {
	mailResponseLocks.Lock()
	l := mailResponseLocks.entries[key]
	if l == nil {
		l = &mailResponseLock{}
		mailResponseLocks.entries[key] = l
	}
	l.refs++
	mailResponseLocks.Unlock()
	l.mu.Lock()
	return func() {
		l.mu.Unlock()
		mailResponseLocks.Lock()
		l.refs--
		if l.refs == 0 {
			delete(mailResponseLocks.entries, key)
		}
		mailResponseLocks.Unlock()
	}
}

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
	unlock := lockMailResponse(id)
	defer unlock()
	now = time.Now()
	db := store.Global()
	var uncertain store.MailboxSuspension
	if db != nil {
		prev, ok, err := db.GetMailboxSuspension(id)
		switch {
		case err != nil:
			fmt.Fprintf(os.Stderr, "[%s] auto-suspend: reading suspension record for %s: %v\n", stamp, c.Subject, err)
		case ok && prev.ReleasedAt == nil:
			// Trust the row only while the mail server agrees: a suspension
			// lifted outside CSM, or one whose state cannot be read, must
			// not stop a new response. Suspending again is idempotent.
			live, statusErr := backend.active([]store.MailboxSuspension{prev})
			still, known := live[prev.ID]
			if known && still {
				return true, nil
			}
			if statusErr != nil {
				fmt.Fprintf(os.Stderr, "[%s] auto-suspend: %v; suspending %s again\n", stamp, statusErr, c.Subject)
			}
			if !known {
				uncertain = prev
			}
		case ok && !c.At.After(*prev.ReleasedAt):
			fmt.Fprintf(os.Stderr, "[%s] auto-suspend: %s was released at %s, after this evidence; not suspending again\n",
				stamp, c.Subject, prev.ReleasedAt.Format(time.RFC3339))
			return false, nil
		}
	}

	c.Previous = uncertain
	applied, err := backend.suspend(c)
	if errors.Is(err, errMailAlreadyRestricted) {
		return true, nil
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] auto-suspend: could not stop %s: %v\n", stamp, c.Subject, err)
		if c.Evidence == evidenceLogin {
			return false, []alert.Finding{loginResponseFinding(c, store.MailboxSuspension{}, err)}
		}
		return false, nil
	}
	if uncertain.Account == applied.Account {
		parts := slices.Clone(uncertain.Applied)
		for _, part := range applied.Applied {
			if !slices.Contains(parts, part) {
				parts = append(parts, part)
			}
		}
		applied.Applied = parts
	}
	if slices.Contains(applied.Applied, store.AppliedHoldOutgoing) {
		applied.Kind = store.SuspensionKindAccount
	}
	rec := store.MailboxSuspension{
		ID:          id,
		Backend:     backend.name(),
		Subject:     c.Subject,
		Kind:        applied.Kind,
		Account:     applied.Account,
		Applied:     applied.Applied,
		Check:       c.Check,
		Reason:      c.Reason,
		SuspendedAt: now,
	}
	if db != nil {
		if err := db.PutMailboxSuspension(rec); err != nil {
			fmt.Fprintf(os.Stderr, "[%s] auto-suspend: recording suspension of %s: %v\n", stamp, c.Subject, err)
		}
	}
	if c.Evidence == evidenceLogin {
		return true, []alert.Finding{loginResponseFinding(c, rec, nil)}
	}
	return true, nil
}

// loginResponseFinding tells staff what CSM did about a cracked password and
// what they still have to do. Sending triggers need none: their own finding
// already says the mailbox is suspended.
func loginResponseFinding(c mailboxCompromise, rec store.MailboxSuspension, err error) alert.Finding {
	mailbox, domain, tenant := splitMailAccount(c.Subject)
	if rec.Account != "" {
		tenant = rec.Account
	} else if tenant == "" && domain != "" {
		tenant = lookupCPanelUser(domain)
	}
	f := alert.Finding{
		Severity:  alert.Critical,
		Check:     "email_mailbox_response",
		Mailbox:   mailbox,
		Domain:    domain,
		TenantID:  tenant,
		Timestamp: time.Now(),
	}
	switch {
	case err != nil:
		f.Message = fmt.Sprintf("Could not suspend %s after its password was cracked: %v", c.Subject, err)
		f.Details = "Protection could not be confirmed. Change its password now."
	case rec.Kind == store.SuspensionKindAccount && mailbox == "":
		f.Message = fmt.Sprintf("Outgoing mail held for cPanel account %s after its own password was cracked", rec.Account)
		f.Details = "That password unlocks every mailbox and the cPanel login. Change the cPanel password, then release the hold on the Email page, Suspended tab."
	default:
		f.Message = fmt.Sprintf("Mailbox %s suspended after its password was cracked", c.Subject)
		switch {
		case !slices.Contains(rec.Applied, store.AppliedSuspendLogin):
			f.Details = "Only outgoing mail is stopped; logins may still work."
		case !slices.Contains(rec.Applied, store.AppliedSuspendOutgoing):
			f.Details = "Only logins are stopped; outgoing mail was not suspended."
		default:
			f.Details = "Logins and outgoing mail are stopped."
		}
		f.Details += " Have the customer change the mailbox password, then release it on the Email page, Suspended tab."
	}
	return f
}

// hostHasMailBackend reports whether this host has a mail server CSM can
// suspend accounts on. var so tests can stand in for a cPanel host.
var hostHasMailBackend = func() bool { return platform.Detect().IsCPanel() }

// stolenLoginResponses suspends the mailbox behind each Critical login after
// brute force. High findings (an established multi-mailbox source, spray
// advisories) stay alert-only.
func stolenLoginResponses(cfg *config.Config, findings []alert.Finding) []alert.Finding {
	var out []alert.Finding
	for _, f := range findings {
		if f.Check != "mail_account_compromised" || f.Severity != alert.Critical {
			continue
		}
		subject := loginMailbox(f.Mailbox)
		if subject == "" || !hostHasMailBackend() {
			continue
		}
		_, response := respondToCompromise(cfg, mailboxCompromise{
			Subject: subject, Check: f.Check, Reason: f.Message, Evidence: evidenceLogin, At: f.Timestamp,
		})
		out = append(out, response...)
	}
	return out
}

// dryRunMailOp names the operation a dry run would have performed.
func dryRunMailOp(subject string) string {
	if strings.Contains(subject, "@") {
		return "respond.suspend_mailbox"
	}
	return "respond.hold_outgoing_mail"
}

// loginMailbox turns cPanel's alternative login forms, user+domain and
// user%domain, into the mailbox address they name.
func loginMailbox(name string) string {
	if strings.Contains(name, "@") {
		return name
	}
	if i := strings.LastIndexAny(name, "+%"); i > 0 && strings.Contains(name[i+1:], ".") {
		return name[:i] + "@" + name[i+1:]
	}
	return name
}

// releasedOutsideCSM marks a suspension the mail server no longer applies,
// lifted by someone outside CSM.
const releasedOutsideCSM = "outside CSM"

var errSuspensionAlreadyReleased = errors.New("mailbox suspension already released")

// mailboxSuspensionStatus is a stored suspension with its live state.
type mailboxSuspensionStatus struct {
	store.MailboxSuspension
	Active        bool
	StatusUnknown bool
}

// listMailboxSuspensions returns every stored suspension with the mail
// server's live state. One the server no longer applies is marked released
// outside CSM; one whose state cannot be read stays as it was.
func listMailboxSuspensions() ([]mailboxSuspensionStatus, error) {
	db := store.Global()
	if db == nil {
		return nil, errors.New("state store not open")
	}
	rows, err := db.ListMailboxSuspensions()
	if err != nil {
		return nil, err
	}
	var open []store.MailboxSuspension
	for _, r := range rows {
		if r.ReleasedAt == nil {
			open = append(open, r)
		}
	}
	live := map[string]bool{}
	if len(open) > 0 {
		var statusErr error
		if live, statusErr = activeMailBackend.active(open); statusErr != nil {
			fmt.Fprintf(os.Stderr, "[%s] mailbox suspensions: %v\n", time.Now().Format("2006-01-02 15:04:05"), statusErr)
		}
	}
	out := make([]mailboxSuspensionStatus, 0, len(rows))
	for _, r := range rows {
		unlock := lockMailResponse(r.ID)
		current, found, readErr := db.GetMailboxSuspension(r.ID)
		if readErr != nil {
			unlock()
			return nil, readErr
		}
		if !found {
			unlock()
			continue
		}
		st := mailboxSuspensionStatus{MailboxSuspension: current}
		if current.ReleasedAt == nil {
			active, known := live[r.ID]
			switch {
			case !current.SuspendedAt.Equal(r.SuspendedAt):
				// The batched status predates a new suspension. Never apply
				// it to that generation, even if it reported no restrictions.
				st.StatusUnknown = true
			case !known:
				st.StatusUnknown = true
			case active:
				st.Active = true
			default:
				now := time.Now()
				if err := finishMailboxRelease(db, current, now, releasedOutsideCSM); err != nil {
					st.StatusUnknown = true
					break
				}
				at := now
				st.ReleasedAt, st.ReleasedBy = &at, releasedOutsideCSM
			}
		}
		unlock()
		out = append(out, st)
	}
	return out, nil
}

// releaseMailboxSuspension lifts a suspension CSM made, at an operator's
// request, and forgets the sending evidence behind it so sends from before
// the release cannot suspend the mailbox again.
func releaseMailboxSuspension(id, actor string) error {
	unlock := lockMailResponse(id)
	defer unlock()
	db := store.Global()
	if db == nil {
		return errors.New("state store not open")
	}
	rec, ok, err := db.GetMailboxSuspension(id)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%w: %s", store.ErrMailboxSuspensionNotFound, id)
	}
	if rec.ReleasedAt != nil {
		return errSuspensionAlreadyReleased
	}
	backend := activeMailBackend
	if rec.Backend != backend.name() {
		return fmt.Errorf("suspension was made through %s; this host uses %s", rec.Backend, backend.name())
	}
	if err := backend.release(rec, actor); err != nil {
		return err
	}
	return finishMailboxRelease(db, rec, time.Now(), actor)
}

// The caller holds the subject lock through both evidence and record updates.
func finishMailboxRelease(db *store.DB, rec store.MailboxSuspension, now time.Time, actor string) error {
	if err := forgetSenderEvidence(rec.Subject, now); err != nil {
		return err
	}
	forgetCloudRelayEvidence(rec.Subject)
	if err := db.MarkMailboxSuspensionReleased(rec.ID, now, actor); err != nil {
		return err
	}
	if !strings.Contains(rec.Subject, "@") && strings.Contains(rec.Subject, ".") {
		// The spam-outbreak governor held this domain; restart its dedup
		// window so the same blast does not hold it again at once.
		recordRecentOutgoingMailHold(rec.Subject)
	}
	return nil
}

// mailboxSuspensionsAPI serves the web UI's suspension list and Release.
type mailboxSuspensionsAPI struct{}

func (mailboxSuspensionsAPI) ListSuspensions() ([]webui.MailboxSuspensionRow, error) {
	rows, err := listMailboxSuspensions()
	if err != nil {
		return nil, err
	}
	out := make([]webui.MailboxSuspensionRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, webui.MailboxSuspensionRow{MailboxSuspension: r.MailboxSuspension, Active: r.Active, StatusUnknown: r.StatusUnknown})
	}
	return out, nil
}

func (mailboxSuspensionsAPI) ReleaseSuspension(id, actor string) error {
	err := releaseMailboxSuspension(id, actor)
	if errors.Is(err, errSuspensionAlreadyReleased) {
		return webui.ErrSuspensionReleased
	}
	return err
}
