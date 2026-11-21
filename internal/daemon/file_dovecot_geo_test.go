package daemon

import (
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/store"
)

// A Dovecot login read from a mail log file may be a line any local user
// wrote. It may alert, but it neither changes the mailbox's login history
// nor adds compromise evidence that could suspend the mailbox.
func TestFileDovecotLoginLeavesMailboxStateAlone(t *testing.T) {
	db, calls := evidenceCase(t)
	withGeoCountries(t, map[string]string{"203.0.113.5": "RO", "198.51.100.7": "CN", "198.51.100.8": "BR"})
	cfg := eximAutoHoldConfig()
	const mb = "real@victim.example"
	for range geoMinLoginCount {
		parseDovecotLogLine(geoDovecotLine(time.Now(), "203.0.113.5", mb), cfg, true)
	}
	before, _ := db.GetGeoHistory(mb)
	t.Cleanup(func() {
		unverifiedGeoAlerts.mu.Lock()
		delete(unverifiedGeoAlerts.at, store.MailboxEvidenceKey(mb))
		unverifiedGeoAlerts.mu.Unlock()
	})
	if got := parseDovecotLogLine(geoDovecotLine(time.Now(), "198.51.100.7", mb), cfg, false); len(got) != 1 || got[0].Check != "email_suspicious_geo" {
		t.Fatalf("file login from a new country gave %+v, want one email_suspicious_geo alert", got)
	}
	// Forged lines cannot flood the alert: one per mailbox per cooldown.
	if got := parseDovecotLogLine(geoDovecotLine(time.Now(), "198.51.100.8", mb), cfg, false); len(got) != 0 {
		t.Fatalf("second file login within the cooldown gave %+v, want no alert", got)
	}
	if after, _ := db.GetGeoHistory(mb); !reflect.DeepEqual(before, after) {
		t.Fatalf("file logins changed login history: %+v -> %+v", before, after)
	}
	if len(*calls) != 0 {
		t.Fatalf("file logins suspended the mailbox: %v", *calls)
	}
	e, err := db.UpdateMailboxEvidence(mb, func(*store.MailboxEvidence) {})
	if err != nil || len(e.Signals) != 0 {
		t.Fatalf("file logins added compromise evidence: %+v, %v", e.Signals, err)
	}
	// Nor can they start the recorded cooldown and silence a real alert.
	if got := parseDovecotLogLine(geoDovecotLine(time.Now(), "198.51.100.7", mb), cfg, true); len(got) != 1 || got[0].Check != "email_suspicious_geo" {
		t.Fatalf("a trusted login from a new country gave %+v, want one email_suspicious_geo alert", got)
	}
	e, err = db.UpdateMailboxEvidence(mb, func(*store.MailboxEvidence) {})
	if err != nil || len(e.Signals) != 1 || e.Signals[0].Key != "CN" {
		t.Fatalf("a trusted login from a new country recorded %+v, %v; want one CN signal", e.Signals, err)
	}
}
