package daemon

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/store"
)

const (
	// A message to this many recipients is a mailing, not correspondence.
	bulkRecipientsPerMessage = 50
	// Recipients across one rolling hour of authenticated sends.
	bulkRecipientsPerHour = 200
)

// recipientMinutes counts a mailbox's recipients per minute over the last
// hour in fixed space, however many messages it sends.
type recipientMinutes struct {
	clearedAt time.Time
	minute    [60]int64
	count     [60]int
	last      time.Time
}

// bulkRecipientWindows holds the recipient hour per authenticated mailbox.
var bulkRecipientWindows sync.Map // map[string]*recipientMinutes

// add counts n recipients in the rolling hour ending at the latest send.
// Buffered log reads can deliver records out of order.
func (w *recipientMinutes) add(at time.Time, n int) int {
	w.last = maxTime(w.last, at)
	cutoff := w.last.Unix()/60 - 60
	minute := at.Unix() / 60
	if minute <= cutoff {
		return 0
	}
	i := at.UTC().Minute()
	if w.minute[i] != minute {
		w.minute[i], w.count[i] = minute, 0
	}
	w.count[i] += n
	total := 0
	for i, seen := range w.minute {
		if seen > cutoff {
			total += w.count[i]
		}
	}
	return total
}

func evictBulkRecipientWindows(now time.Time) {
	cutoff := now.Add(-time.Hour)
	bulkRecipientWindows.Range(func(key, val any) bool {
		unlock := lockMailResponse(evidenceAddressLock(activeMailBackend.name(), key.(string)))
		if val.(*recipientMinutes).last.Before(cutoff) {
			bulkRecipientWindows.CompareAndDelete(key, val)
		}
		unlock()
		return true
	})
}

// Release discards the window while holding the address lock. Reload its
// durable cutoff on first use so buffered arrivals cannot rebuild the hour.
func countMailboxRecipients(mailbox string, at time.Time, n int) (int, time.Time) {
	unlock := lockMailResponse(evidenceAddressLock(activeMailBackend.name(), mailbox))
	defer unlock()
	val, found := bulkRecipientWindows.Load(mailbox)
	var w *recipientMinutes
	if found {
		w = val.(*recipientMinutes)
	} else {
		w = &recipientMinutes{}
		if db := store.Global(); db != nil {
			e, err := db.GetMailboxEvidence(mailbox)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[%s] Warning: reading mailbox release cutoff for %s: %v\n", ts(), mailbox, err)
				return 0, at
			}
			w.clearedAt = e.ClearedAt
		}
		bulkRecipientWindows.Store(mailbox, w)
	}
	if !at.After(w.clearedAt) {
		return 0, at
	}
	total := w.add(at, n)
	return total, w.last
}

// observeBulkRecipients records an authenticated mailing as compromise
// evidence: one message to many recipients, or many recipients within an
// hour. Mailboxes in high_volume_senders send mailings by design.
func observeBulkRecipients(cfg *config.Config, user string, recipients []string, now time.Time) []alert.Finding {
	if len(recipients) == 0 || isHighVolumeSender(user, cfg.EmailProtection.HighVolumeSenders) {
		return nil
	}
	distinct := make(map[string]struct{}, len(recipients))
	for _, r := range recipients {
		distinct[strings.ToLower(r)] = struct{}{}
	}
	n := len(distinct)
	hour, hourEnd := countMailboxRecipients(store.MailboxEvidenceKey(user), now, n)

	var detail string
	switch {
	case n >= bulkRecipientsPerMessage:
		detail = fmt.Sprintf("one message to %d recipients", n)
	case hour >= bulkRecipientsPerHour:
		now = hourEnd
		detail = fmt.Sprintf("%d recipients within an hour", hour)
	default:
		return nil
	}
	mailbox, domain, _ := splitMailAccount(user)
	summary := []alert.Finding{{
		Severity:  alert.Warning,
		Check:     "email_bulk_recipients",
		Message:   fmt.Sprintf("Email account %s sent %s", user, detail),
		Details:   "Recorded as compromise evidence for the mailbox. A mailbox that sends mailings by design belongs in email_protection.high_volume_senders.",
		Mailbox:   mailbox,
		Domain:    domain,
		Timestamp: now,
	}}
	stampMailAccountOwner(summary, user)
	return observeMailboxSignal(cfg, user, mailboxSignal{kind: signalBulkRecipients, at: now, detail: "sent " + detail, summary: summary[0]})
}
