package daemon

import (
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
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
	mu     sync.Mutex
	minute [60]int64
	count  [60]int
	last   time.Time
}

// bulkRecipientWindows holds the recipient hour per authenticated mailbox.
var bulkRecipientWindows sync.Map // map[string]*recipientMinutes

func lockRecipientMinutes(user string) *recipientMinutes {
	for {
		val, _ := bulkRecipientWindows.LoadOrStore(user, &recipientMinutes{})
		w := val.(*recipientMinutes)
		w.mu.Lock()
		// Re-check under the lock so eviction cannot delete the entry
		// between the load and the update.
		if current, ok := bulkRecipientWindows.Load(user); ok && current == val {
			return w
		}
		w.mu.Unlock()
	}
}

// add counts n recipients at now and returns the hour's total.
func (w *recipientMinutes) add(now time.Time, n int) int {
	m := now.Unix() / 60
	i := m % 60
	if w.minute[i] != m {
		w.minute[i], w.count[i] = m, 0
	}
	w.count[i] += n
	w.last = maxTime(w.last, now)
	total := 0
	for j, at := range w.minute {
		if at > m-60 && at <= m {
			total += w.count[j]
		}
	}
	return total
}

func evictBulkRecipientWindows(now time.Time) {
	cutoff := now.Add(-time.Hour)
	bulkRecipientWindows.Range(func(key, val any) bool {
		w := val.(*recipientMinutes)
		w.mu.Lock()
		if w.last.Before(cutoff) {
			bulkRecipientWindows.CompareAndDelete(key, val)
		}
		w.mu.Unlock()
		return true
	})
}

// observeBulkRecipients records an authenticated mailing as compromise
// evidence: one message to many recipients, or many recipients within an
// hour. Mailboxes in high_volume_senders send mailings by design.
func observeBulkRecipients(cfg *config.Config, user string, recipients []string, now time.Time) []alert.Finding {
	var distinct []string
	for _, r := range recipients {
		if r = strings.ToLower(r); !slices.Contains(distinct, r) {
			distinct = append(distinct, r)
		}
	}
	n := len(distinct)
	if n == 0 || isHighVolumeSender(user, cfg.EmailProtection.HighVolumeSenders) {
		return nil
	}
	w := lockRecipientMinutes(user)
	hour := w.add(now, n)
	w.mu.Unlock()

	var detail string
	switch {
	case n >= bulkRecipientsPerMessage:
		detail = fmt.Sprintf("one message to %d recipients", n)
	case hour >= bulkRecipientsPerHour:
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
