package daemon

import (
	"slices"
	"strings"
	"time"
)

const (
	// smtpAuthPairWindow bounds the gap between Dovecot's verdict and the
	// MTA's failure line for one request. Dovecot delays failure replies by
	// auth_failure_delay (2 s by default) after logging the verdict.
	smtpAuthPairWindow = 30 * time.Second
	// smtpAuthPairMaxPending caps unmatched verdicts kept per client.
	smtpAuthPairMaxPending = 16
)

type smtpPendingVerdict struct {
	at, loggedAt time.Time
	account      string
	exist        mailboxExistence
	batch        *smtpVerdictBatch // shared once pending answers disagree
}

// smtpVerdictBatch holds the distinct names Dovecot rejected for one client
// while its pending answers named different mailboxes, until a failure feeds
// them to the spray memory. Guarded by the tracker's mutex.
type smtpVerdictBatch struct{ names []string }

func (b *smtpVerdictBatch) add(name string) {
	if slices.Contains(b.names, name) {
		return
	}
	if len(b.names) >= smtpAuthPairMaxPending {
		b.names = slices.Delete(b.names, 0, 1)
	}
	b.names = append(b.names, name)
}

// take returns the names not fed yet, so each counts once per batch.
func (b *smtpVerdictBatch) take() []string {
	names := b.names
	b.names = nil
	return names
}

// NoteDovecotRejection keeps a sessionless Dovecot rejection until the MTA's
// failure line for the same client claims it. Callers filter infra, private
// and loopback addresses first.
func (t *smtpAuthTracker) NoteDovecotRejection(ip, account string, exist mailboxExistence, loggedAt time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	pending, exists := t.pendingVerdicts[ip]
	if !exists && len(t.pendingVerdicts) >= t.maxTracked {
		t.prunePairing(now)
		if len(t.pendingVerdicts) >= t.maxTracked {
			// Dropping a verdict only withholds evidence.
			return
		}
	}
	if t.pendingVerdicts == nil {
		t.pendingVerdicts = make(map[string][]smtpPendingVerdict)
	}
	for len(pending) > 0 && pending[0].at.Before(now.Add(-smtpAuthPairWindow)) {
		pending = pending[1:]
	}
	// Every passdb in a chain answers for the same request, so pending
	// answers for one mailbox share what any of them learned about it.
	// Answers for different mailboxes say nothing about either, but each
	// name they rejected is kept for the spray memory. Pending answers
	// always agree with each other, so the oldest speaks for all.
	var batch *smtpVerdictBatch
	if len(pending) > 0 {
		batch = pending[0].batch
		if batch == nil && pending[0].account != account {
			batch = &smtpVerdictBatch{}
			batch.add(normalizeSprayMailbox(pending[0].account))
		}
	}
	if batch != nil {
		batch.add(normalizeSprayMailbox(account))
		account, exist = "", mailboxExistenceUnknown
	} else if len(pending) > 0 {
		exist = combineMailboxExistence(exist, pending[0].exist)
	}
	// Preserve ambiguity even when the queue drops an older answer or a
	// different request finishes first.
	for i := range pending {
		pending[i].account, pending[i].exist, pending[i].batch = account, exist, batch
	}
	if len(pending) >= smtpAuthPairMaxPending {
		pending = pending[1:]
	}
	t.pendingVerdicts[ip] = append(pending, smtpPendingVerdict{at: now, loggedAt: loggedAt, account: account, exist: exist, batch: batch})
}

// NoteAuthTrouble marks Dovecot client addresses or Postfix process tags.
// Their failures inside the pairing window are not credential evidence.
// Process tags and canonical IP addresses cannot collide.
func (t *smtpAuthTracker) NoteAuthTrouble(keys ...string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	for _, key := range keys {
		if _, exists := t.authTrouble[key]; !exists && len(t.authTrouble) >= t.maxTracked {
			t.prunePairing(now)
			if len(t.authTrouble) >= t.maxTracked {
				// Losing a mark could turn an outage into evidence, so
				// withhold all pairing until the marks would have expired.
				t.authTroubleOverflowUntil = now.Add(smtpAuthPairWindow)
				continue
			}
		}
		if t.authTrouble == nil {
			t.authTrouble = make(map[string]time.Time)
		}
		t.authTrouble[key] = now
	}
}

// PairMTAFailure claims the oldest pending rejection for ip. There is no
// request ID in these lines, and concurrent requests can finish out of order,
// so account attribution requires all pending answers to agree; when they do
// not, batch holds the names they rejected. Dovecot client errors and Postfix
// process errors withhold evidence for the window.
func (t *smtpAuthTracker) PairMTAFailure(ip, process string, loggedAt time.Time) (account string, exist mailboxExistence, batch *smtpVerdictBatch, ok bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	cutoff := now.Add(-smtpAuthPairWindow)
	pending := t.pendingVerdicts[ip]
	for len(pending) > 0 {
		p := pending[0]
		badLogTime := !p.loggedAt.IsZero() && !loggedAt.IsZero() &&
			(loggedAt.Before(p.loggedAt) || loggedAt.Sub(p.loggedAt) > smtpAuthPairWindow)
		if !p.at.Before(cutoff) && !badLogTime {
			break
		}
		pending = pending[1:]
	}
	if len(pending) == 0 {
		delete(t.pendingVerdicts, ip)
		return "", mailboxExistenceUnknown, nil, false
	}
	account, exist, batch = pending[0].account, pending[0].exist, pending[0].batch
	if len(pending) == 1 {
		delete(t.pendingVerdicts, ip)
	} else {
		t.pendingVerdicts[ip] = pending[1:]
	}
	if !now.After(t.authTroubleOverflowUntil) {
		return "", mailboxExistenceUnknown, nil, false
	}
	for _, key := range []string{ip, process} {
		if at, marked := t.authTrouble[key]; marked && !at.Before(cutoff) {
			return "", mailboxExistenceUnknown, nil, false
		}
	}
	return account, exist, batch, true
}

// smtpAuthLogTime keeps buffered file input from extending the pairing
// window. Bare messages have no source time; their receipt-time bound still
// applies. Traditional syslog omits the year and uses the host's timezone.
func smtpAuthLogTime(line string, now time.Time) time.Time {
	if end := strings.IndexAny(line, " \t"); end > 0 {
		if at, err := time.Parse(time.RFC3339Nano, line[:end]); err == nil {
			return at
		}
	}
	if len(line) < len(time.Stamp) {
		return time.Time{}
	}
	at, err := time.ParseInLocation(time.Stamp, line[:len(time.Stamp)], now.Location())
	if err != nil {
		return time.Time{}
	}
	at = time.Date(now.Year(), at.Month(), at.Day(), at.Hour(), at.Minute(), at.Second(), 0, now.Location())
	// A December line read in January belongs to the previous year. Allow
	// a day's clock skew rather than mistaking it for a year-old message.
	if at.After(now.AddDate(0, 0, 1)) {
		at = at.AddDate(-1, 0, 0)
	}
	return at
}

// prunePairing drops expired verdicts and error marks. Caller holds t.mu.
func (t *smtpAuthTracker) prunePairing(now time.Time) {
	cutoff := now.Add(-smtpAuthPairWindow)
	for ip, pending := range t.pendingVerdicts {
		if pending[len(pending)-1].at.Before(cutoff) {
			delete(t.pendingVerdicts, ip)
		}
	}
	for ip, at := range t.authTrouble {
		if at.Before(cutoff) {
			delete(t.authTrouble, ip)
		}
	}
}
