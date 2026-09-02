package daemon

import (
	"testing"
	"time"
)

// The SMTP account-spray tracker keyed on the raw set_id, so "User@X.RO",
// "user@x.ro" and " user@x.ro" were three accounts: a spray across case
// variants of one mailbox never reached the distinct-IP threshold.
func TestSMTPAccountSprayKeyIsCaseInsensitive(t *testing.T) {
	tr := newSMTPAuthTracker(100, 100, 2, 10*time.Minute, 60*time.Minute, 0, 0, 100, time.Now)
	tr.Record("203.0.113.61", "User@X.RO")
	tr.Record("203.0.113.62", "user@x.ro")
	tr.Record("203.0.113.63", " user@x.ro ")

	tr.mu.Lock()
	defer tr.mu.Unlock()
	if len(tr.accounts) != 1 {
		keys := make([]string, 0, len(tr.accounts))
		for k := range tr.accounts {
			keys = append(keys, k)
		}
		t.Fatalf("case variants of one mailbox tracked as %d accounts: %q", len(tr.accounts), keys)
	}
	for _, a := range tr.accounts {
		if len(a.ips) != 3 {
			t.Fatalf("account entry holds %d source IPs, want 3", len(a.ips))
		}
	}
}
