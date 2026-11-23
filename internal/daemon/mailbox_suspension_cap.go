package daemon

import (
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/store"
)

// A detection storm must not suspend every mailbox of a hosting account.
// Past this many mailbox suspensions in the window one account's mailboxes
// stay open and the operator gets one Critical notice for the hour.
// Mailboxes no hosting account owns share their domain's allowance.
const (
	mailboxSuspensionsPerHour = 3
	mailboxSuspensionWindow   = time.Hour
	// Names listed in one notice; the incidents name the rest.
	mailboxCapNoticeNames = 20
)

// mailboxCapMu is held from counting an allowance through recording the
// suspension, so concurrent suspensions cannot both pass the last slot.
var mailboxCapMu sync.Mutex

type mailboxCapNotice struct {
	since     time.Time
	label     string
	account   string
	domain    string
	suspended []string
	withheld  []string
	pending   bool
}

var mailboxCapNotices = struct {
	sync.Mutex
	m map[string]*mailboxCapNotice
}{m: map[string]*mailboxCapNotice{}}

// mailboxSuspensionBucket names the allowance a mailbox draws on: its
// hosting account, or its domain when no account owns it.
func mailboxSuspensionBucket(subject, account string) (key, label string) {
	if account != "" {
		return "account:" + account, "hosting account " + account
	}
	domain := strings.ToLower(extractDomainFromEmail(subject))
	return "domain:" + domain, "domain " + domain
}

func mailboxSuspensionHistory(r store.MailboxSuspension) []store.MailboxSuspensionEvent {
	if r.RecentMailboxSuspensions != nil {
		return r.RecentMailboxSuspensions
	}
	// Older rows have no separate history. A mixed response can include
	// mailbox restrictions even though its kind names the account hold.
	if r.Kind == store.SuspensionKindMailbox || slices.Contains(r.Applied, store.AppliedSuspendLogin) ||
		slices.Contains(r.Applied, store.AppliedSuspendOutgoing) || slices.Contains(r.Applied, store.AppliedDisableSignIn) {
		return []store.MailboxSuspensionEvent{{Subject: r.Subject, Account: r.Account, SuspendedAt: r.SuspendedAt}}
	}
	return nil
}

func updatedMailboxSuspensionHistory(previous, current store.MailboxSuspension, mailboxApplied bool) []store.MailboxSuspensionEvent {
	key, _ := mailboxSuspensionBucket(current.Subject, current.Account)
	history := make([]store.MailboxSuspensionEvent, 0)
	for _, event := range mailboxSuspensionHistory(previous) {
		if current.SuspendedAt.Sub(event.SuspendedAt) >= mailboxSuspensionWindow {
			continue
		}
		if k, _ := mailboxSuspensionBucket(event.Subject, event.Account); mailboxApplied && k == key {
			continue
		}
		history = append(history, event)
	}
	if mailboxApplied {
		history = append(history, store.MailboxSuspensionEvent{Subject: current.Subject, Account: current.Account, SuspendedAt: current.SuspendedAt})
	}
	return history
}

// capMailboxSuspension reports whether suspending c.Subject would exceed its
// allowance, and records a refusal for the hourly notice. The caller holds
// mailboxCapMu. A store that cannot be read imposes no cap.
func capMailboxSuspension(db *store.DB, id string, c mailboxCompromise, now time.Time) (string, bool) {
	account := ""
	if activeMailBackend.name() == "cpanel" {
		account = lookupCPanelUser(extractDomainFromEmail(c.Subject))
	}
	key, label := mailboxSuspensionBucket(c.Subject, account)
	rows, err := db.ListMailboxSuspensions()
	if err != nil {
		return "", false
	}
	var recent []string
	for _, r := range rows {
		for _, event := range mailboxSuspensionHistory(r) {
			age := now.Sub(event.SuspendedAt)
			if age < 0 || age >= mailboxSuspensionWindow {
				continue
			}
			if k, _ := mailboxSuspensionBucket(event.Subject, event.Account); k != key {
				continue
			}
			// Stalwart aliases share an ID; a reassigned address has a new
			// one. Repeating a counted suspension never consumes a slot,
			// even if the stored history already exceeds the allowance.
			if r.ID == id {
				return "", false
			}
			recent = append(recent, event.Subject)
			break
		}
	}
	if len(recent) < mailboxSuspensionsPerHour {
		return "", false
	}
	noteWithheldSuspension(key, label, account, recent, c.Subject, now)
	return label, true
}

func noteWithheldSuspension(key, label, account string, suspended []string, mailbox string, now time.Time) {
	mailboxCapNotices.Lock()
	defer mailboxCapNotices.Unlock()
	for k, n := range mailboxCapNotices.m {
		if now.Sub(n.since) >= mailboxSuspensionWindow {
			delete(mailboxCapNotices.m, k)
		}
	}
	n := mailboxCapNotices.m[key]
	if n == nil {
		n = &mailboxCapNotice{since: now, label: label, account: account, domain: extractDomainFromEmail(mailbox), suspended: suspended, pending: true}
		mailboxCapNotices.m[key] = n
	}
	if n.pending && len(n.withheld) < mailboxCapNoticeNames && !slices.Contains(n.withheld, mailbox) {
		n.withheld = append(n.withheld, mailbox)
	}
}

// drainMailboxCapNotices returns each account's notice once an hour.
func drainMailboxCapNotices() []alert.Finding {
	mailboxCapNotices.Lock()
	defer mailboxCapNotices.Unlock()
	var out []alert.Finding
	for _, n := range mailboxCapNotices.m {
		if !n.pending {
			continue
		}
		n.pending = false
		f := alert.Finding{
			Severity: alert.Critical,
			Check:    "email_mailbox_suspension_paused",
			Message:  fmt.Sprintf("Mailbox suspensions paused for %s after %d in the last hour", n.label, len(n.suspended)),
			Details: "Suspended in the last hour: " + strings.Join(n.suspended, ", ") +
				"\nNot suspended: " + strings.Join(n.withheld, ", ") +
				"\n\nCSM suspends no more mailboxes here until fewer than " + fmt.Sprint(mailboxSuspensionsPerHour) +
				" suspensions fall within the last hour. Each mailbox it held back is in its own finding. Review them and change the passwords of the mailboxes left open.",
			TenantID:  n.account,
			Timestamp: time.Now(),
		}
		if n.account == "" {
			f.Domain = n.domain
		}
		out = append(out, f)
	}
	return out
}

// resetMailboxCapNotices forgets every notice. Tests only.
func resetMailboxCapNotices() {
	mailboxCapNotices.Lock()
	defer mailboxCapNotices.Unlock()
	mailboxCapNotices.m = map[string]*mailboxCapNotice{}
}
