package daemon

import "time"

const (
	// smtpAuthPairWindow bounds the gap between Dovecot's verdict and the
	// MTA's failure line for one request. Dovecot delays failure replies by
	// auth_failure_delay (2 s by default) after logging the verdict.
	smtpAuthPairWindow = 30 * time.Second
	// smtpAuthPairMaxPending caps unmatched verdicts kept per client.
	smtpAuthPairMaxPending = 16
)

type smtpPendingVerdict struct {
	at      time.Time
	account string
}

// NoteDovecotRejection keeps a sessionless Dovecot rejection until the MTA's
// failure line for the same client claims it. Callers filter infra, private
// and loopback addresses first.
func (t *smtpAuthTracker) NoteDovecotRejection(ip, account string) {
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
	if len(pending) >= smtpAuthPairMaxPending {
		pending = pending[1:]
	}
	t.pendingVerdicts[ip] = append(pending, smtpPendingVerdict{at: now, account: account})
}

// NoteDovecotTrouble marks clients whose requests hit a Dovecot error. Their
// MTA failures inside the pairing window are not credential evidence.
func (t *smtpAuthTracker) NoteDovecotTrouble(ips []string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	for _, ip := range ips {
		if _, exists := t.authTrouble[ip]; !exists && len(t.authTrouble) >= t.maxTracked {
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
		t.authTrouble[ip] = now
	}
}

// PairMTAFailure claims the oldest pending rejection for ip when the MTA logs
// that request's failure. It reports the rejected account and whether the
// failure is credential evidence: a fresh rejection, and no Dovecot error for
// the client inside the window. One failure claims one verdict, so a request
// that several databases rejected counts once.
func (t *smtpAuthTracker) PairMTAFailure(ip string) (account string, ok bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	cutoff := now.Add(-smtpAuthPairWindow)
	pending := t.pendingVerdicts[ip]
	for len(pending) > 0 && pending[0].at.Before(cutoff) {
		pending = pending[1:]
	}
	if len(pending) == 0 {
		delete(t.pendingVerdicts, ip)
		return "", false
	}
	claimed := pending[0]
	if len(pending) == 1 {
		delete(t.pendingVerdicts, ip)
	} else {
		t.pendingVerdicts[ip] = pending[1:]
	}
	if now.Before(t.authTroubleOverflowUntil) {
		return "", false
	}
	if at, marked := t.authTrouble[ip]; marked && !at.Before(cutoff) {
		return "", false
	}
	return claimed.account, true
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
