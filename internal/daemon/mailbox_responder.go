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
	Ref      string
	Check    string
	Reason   string
	Evidence compromiseEvidence
	At       time.Time
	Previous store.MailboxSuspension
}

// mailBackend is the mail server's side of a suspension. suspend fills Kind,
// Account, Ref and Applied; the caller stamps the rest of the record.
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
// dated after it. It reports whether sending from the subject is stopped.
func respondToCompromise(cfg *config.Config, c mailboxCompromise) bool {
	// The detection withdraws the mailbox's login standing whatever the
	// response mode does on the mail server: whoever cracked it may have
	// earned standing on it.
	mailboxResponseStanding.Load().Revoke(c.Subject)
	now := time.Now()
	stamp := now.Format("2006-01-02 15:04:05")
	if cfg == nil || !cfg.AutoResponse.Enabled {
		fmt.Fprintf(os.Stderr, "[%s] auto-suspend: would suspend %s (auto_response disabled)\n", stamp, c.Subject)
		return false
	}
	if cfg.AutoResponseDryRunEnabled() {
		fmt.Fprintf(os.Stderr, "[%s] auto-suspend: would suspend %s (dry-run)\n", stamp, c.Subject)
		recordMailDryRun(c)
		return false
	}
	// An account's outgoing hold for a domain is not a mailbox suspension.
	if strings.Contains(c.Subject, "@") && !cfg.SuspendMailboxesEnabled() {
		fmt.Fprintf(os.Stderr, "[%s] auto-suspend: would suspend %s (auto_response.suspend_mailboxes off)\n", stamp, c.Subject)
		return false
	}

	id, ref, err := mailResponseTarget(c.Subject)
	c.Ref = ref
	var result mailResponseResult
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] auto-suspend: could not resolve %s: %v\n", stamp, c.Subject, err)
		result.err = err
		result.record.Backend = activeMailBackend.name()
	} else {
		unlock := lockMailResponse(id)
		defer unlock()
		result = applyMailResponse(store.Global(), id, c)
	}
	return result.stopped
}

func recordMailDryRun(c mailboxCompromise) {
	actionlog.Write(actionlog.Record{Op: dryRunMailOp(c.Subject), Target: c.Subject, Reason: c.Reason, Result: actionlog.DryRun})
}

func mailResponseTarget(subject string) (id, ref string, err error) {
	id = store.MailboxSuspensionID(activeMailBackend.name(), subject)
	if b, ok := activeMailBackend.(stalwartMailBackend); ok {
		ref, err = b.resolve(subject)
		if err == nil {
			id = stalwartSuspensionID(ref)
		}
	}
	return id, ref, err
}

type mailResponseResult struct {
	record   store.MailboxSuspension
	stopped  bool
	changed  bool
	recorded bool
	err      error
	// withheld names the allowance that kept the mailbox open.
	withheld string
}

// The caller holds the target's lifecycle lock through the server and store updates.
func applyMailResponse(db *store.DB, id string, c mailboxCompromise) mailResponseResult {
	stamp := time.Now().Format("2006-01-02 15:04:05")
	backend := activeMailBackend
	var uncertain store.MailboxSuspension
	var previous store.MailboxSuspension
	if db != nil {
		prev, ok, err := db.GetMailboxSuspension(id)
		if err == nil && ok {
			previous = prev
		}
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
				return mailResponseResult{stopped: true, record: prev}
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
			return mailResponseResult{}
		}
	}

	if db != nil && strings.Contains(c.Subject, "@") {
		mailboxCapMu.Lock()
		defer mailboxCapMu.Unlock()
		// Count at lock acquisition: status reads and other suspensions
		// may have completed while this caller waited.
		if label, capped := capMailboxSuspension(db, id, c, time.Now()); capped {
			fmt.Fprintf(os.Stderr, "[%s] auto-suspend: %s not suspended: %s reached its hourly limit\n", stamp, c.Subject, label)
			return mailResponseResult{withheld: label}
		}
	}
	c.Previous = uncertain
	applied, err := backend.suspend(c)
	if errors.Is(err, errMailAlreadyRestricted) {
		return mailResponseResult{stopped: true}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] auto-suspend: could not stop %s: %v\n", stamp, c.Subject, err)
		return mailResponseResult{record: store.MailboxSuspension{Backend: backend.name()}, err: err}
	}
	mailboxApplied := applied.Kind == store.SuspensionKindMailbox
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
		Ref:         applied.Ref,
		Applied:     applied.Applied,
		Check:       c.Check,
		Reason:      c.Reason,
		SuspendedAt: time.Now(),
	}
	rec.RecentMailboxSuspensions = updatedMailboxSuspensionHistory(previous, rec, mailboxApplied)
	result := mailResponseResult{stopped: true, changed: true, record: rec}
	if db != nil {
		if err := db.PutMailboxSuspension(rec); err != nil {
			fmt.Fprintf(os.Stderr, "[%s] auto-suspend: recording suspension of %s: %v\n", stamp, c.Subject, err)
		} else {
			result.recorded = true
		}
	}
	return result
}

func mailRestrictionDetails(rec store.MailboxSuspension) string {
	switch {
	case slices.Contains(rec.Applied, store.AppliedDisableSignIn):
		return "Sign-ins are stopped, which also stops sending. Sessions that are already open stay open until they end."
	case slices.Contains(rec.Applied, store.AppliedHoldOutgoing):
		return fmt.Sprintf("Outgoing mail is held for cPanel account %s. Review its mailbox login restrictions.", rec.Account)
	case !slices.Contains(rec.Applied, store.AppliedSuspendLogin):
		return "Only outgoing mail is stopped; logins may still work."
	case !slices.Contains(rec.Applied, store.AppliedSuspendOutgoing):
		return "Only logins are stopped; outgoing mail was not suspended."
	default:
		return "Logins and outgoing mail are stopped."
	}
}

// hostHasMailBackend reports whether this host has a mail server CSM can
// suspend accounts on. selectMailBackend replaces it on a Stalwart host. var
// so tests can stand in for a cPanel host.
var hostHasMailBackend = func() bool { return platform.Detect().IsCPanel() }

// stolenLoginResponses records each Critical login after brute force as
// crack evidence in its mailbox's ledger; with another sign the evidence
// incident suspends the mailbox. High findings (login standing, an
// established multi-mailbox source, spray advisories) add nothing. A bare
// login names no mailbox the ledger can hold, so it only alerts.
func stolenLoginResponses(cfg *config.Config, findings []alert.Finding) []alert.Finding {
	var out []alert.Finding
	for _, f := range findings {
		if f.Check != "mail_account_compromised" || f.Severity != alert.Critical || !trustedMailLogin(f.Observation) {
			continue
		}
		subject := f.Mailbox
		// These spellings belong to cPanel. On Stalwart a bare login
		// containing '+' or '%' must not name another account's mailbox.
		if activeMailBackend.name() == "cpanel" {
			subject = loginMailbox(subject)
		}
		if subject == "" {
			continue
		}
		// Whoever cracked the mailbox may have earned standing on it.
		mailboxResponseStanding.Load().Revoke(subject)
		out = append(out, observeMailboxSignal(cfg, subject, mailboxSignal{
			kind: signalCrack, key: f.SourceIP, at: f.Timestamp,
			detail: "login from " + f.SourceIP + " after failed logins",
		})...)
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
// outside CSM; one whose state cannot be read stays as it was. Only the
// backend that made a row can read it: after the host's mail server changes,
// the other backend's rows show an unknown state.
func listMailboxSuspensions() ([]mailboxSuspensionStatus, error) {
	db := store.Global()
	if db == nil {
		return nil, errors.New("state store not open")
	}
	rows, err := db.ListMailboxSuspensions()
	if err != nil {
		return nil, err
	}
	backend := activeMailBackend
	var open []store.MailboxSuspension
	for _, r := range rows {
		if r.ReleasedAt == nil && r.Backend == backend.name() {
			open = append(open, r)
		}
	}
	live := map[string]bool{}
	if len(open) > 0 {
		var statusErr error
		if live, statusErr = backend.active(open); statusErr != nil {
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
				at, err := finishMailboxRelease(db, current, releasedOutsideCSM)
				if err != nil {
					st.StatusUnknown = true
					break
				}
				st.ReleasedAt, st.ReleasedBy = &at, releasedOutsideCSM
			}
		}
		unlock()
		out = append(out, st)
	}
	return out, nil
}

// releaseMailboxSuspension lifts a suspension CSM made, at an operator's
// request, and forgets the evidence behind it so signs from before the
// release cannot suspend the mailbox again.
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
	if err = backend.release(rec, actor); err != nil {
		return err
	}
	_, err = finishMailboxRelease(db, rec, actor)
	return err
}

// The caller holds the subject lock through both evidence and record updates.
func finishMailboxRelease(db *store.DB, rec store.MailboxSuspension, actor string) (time.Time, error) {
	addressID := evidenceAddressLock(rec.Backend, rec.Subject)
	if addressID != rec.ID {
		// Stalwart releases by account ID. Evidence and observational
		// reports are keyed by the address even if its lookup fails.
		unlock := lockMailResponse(addressID)
		defer unlock()
	}
	now := time.Now()
	if err := forgetSenderEvidence(rec.Subject, now); err != nil {
		return time.Time{}, err
	}
	forgetCloudRelayEvidence(rec.Subject)
	if err := db.MarkMailboxSuspensionReleased(rec.ID, now, actor); err != nil {
		return time.Time{}, err
	}
	bulkRecipientWindows.Delete(store.MailboxEvidenceKey(rec.Subject))
	if !strings.Contains(rec.Subject, "@") && strings.Contains(rec.Subject, ".") {
		// The spam-outbreak governor held this domain; restart its dedup
		// window so the same blast does not hold it again at once.
		recordRecentOutgoingMailHold(rec.Subject)
	}
	return now, nil
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
