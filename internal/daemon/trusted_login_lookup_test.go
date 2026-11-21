package daemon

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/store"
)

// The reputation excuse asks for a recent mail login the daemon recorded:
// only trusted logins reach the known-customer set.
func TestTrustedMailLoginSince(t *testing.T) {
	d := New(&config.Config{}, nil, nil, "")
	now := time.Now()
	d.knownCustomers.NoteTrusted("203.0.113.60", knownCustomerIMAP, "a@example.test", now.Add(-time.Hour), syslogFed)
	d.knownCustomers.NoteTrusted("203.0.113.61", knownCustomerFTP, "acct", now.Add(-time.Hour), syslogFed)
	d.knownCustomers.NoteTrusted("203.0.113.62", knownCustomerSMTP, "b@example.test", now.Add(-48*time.Hour), serviceLog)
	since := now.Add(-24 * time.Hour)
	for ip, want := range map[string]bool{"203.0.113.60": true, "203.0.113.61": false, "203.0.113.62": false, "203.0.113.63": false} {
		if got := d.trustedMailLoginSince(ip, since); got != want {
			t.Errorf("%s: trusted mail login %v, want %v", ip, got, want)
		}
	}
}

// An FTP login read from the system log file is not a customer login; one
// pure-ftpd wrote to the journal is.
func TestFileFTPLoginIsNotACustomer(t *testing.T) {
	d := New(&config.Config{}, nil, nil, "")
	login := func(ip string, producer string) alert.Finding {
		return alert.Finding{Check: "ftp_login", SourceIP: ip, LoginAccount: "acct", Timestamp: time.Now(),
			Observation: alert.Observation{Producer: producer, Stream: "s", Cursor: "1"}}
	}
	d.noteFTPCustomers([]alert.Finding{
		login("203.0.113.64", string(checks.ProducerFTPLog)),
		login("203.0.113.65", string(checks.ProducerFTPScan)),
		login("203.0.113.66", string(checks.ProducerFTPJournal)),
	})
	for ip, want := range map[string]bool{"203.0.113.64": false, "203.0.113.65": false, "203.0.113.66": true} {
		if _, got := d.knownCustomers.Lookup(ip); got != want {
			t.Errorf("%s: known customer %v, want %v", ip, got, want)
		}
	}
}

// Non-mail customer history cannot erase or renew a real mail login.
func TestTrustedMailLoginKeepsIndependentTime(t *testing.T) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	for _, other := range []string{knownCustomerCpanel, knownCustomerFTP} {
		for _, mailFirst := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/mailFirst=%v", other, mailFirst), func(t *testing.T) {
				k, clock := knownCustomersAt(now)
				d := &Daemon{knownCustomers: k}
				const ip = "203.0.113.79"
				mail := func() { k.NoteTrusted(ip, knownCustomerIMAP, "alice@example.test", now.Add(-time.Hour), syslogFed) }
				nonmail := func() { k.NoteTrusted(ip, other, "alice", now, serviceLog) }
				if mailFirst {
					mail()
					nonmail()
				} else {
					nonmail()
					mail()
				}
				if !d.trustedMailLoginSince(ip, now.Add(-24*time.Hour)) {
					t.Fatal("non-mail history hid recent mail login")
				}
				// Exercise the persisted representation as well as the live lookup.
				saved, _ := k.Changes()
				data, err := json.Marshal(saved)
				if err != nil {
					t.Fatal(err)
				}
				var decoded map[string]store.KnownCustomer
				if err := json.Unmarshal(data, &decoded); err != nil {
					t.Fatal(err)
				}
				restored := newKnownCustomers(clock.Now)
				restored.Load(decoded)
				d.knownCustomers = restored
				if !d.trustedMailLoginSince(ip, now.Add(-24*time.Hour)) {
					t.Fatal("restart lost mail login")
				}
				clock.advance(24 * time.Hour)
				restored.NoteTrusted(ip, other, "alice", clock.Now(), serviceLog)
				if d.trustedMailLoginSince(ip, clock.Now().Add(-24*time.Hour)) {
					t.Fatal("non-mail login renewed expired mail exemption")
				}
			})
		}
	}
}

// Older saved summaries may contain forged syslog logins; they are not proof
// of a mail login observed through the trusted reader.
func TestTrustedMailLoginRejectsLegacySummary(t *testing.T) {
	now := time.Now()
	k := newKnownCustomers(func() time.Time { return now })
	k.Load(map[string]store.KnownCustomer{"203.0.113.80": {Kind: knownCustomerIMAP, Account: "alice@example.test", At: now, Syslog: true}})
	d := &Daemon{knownCustomers: k}
	if d.trustedMailLoginSince("203.0.113.80", now.Add(-24*time.Hour)) {
		t.Fatal("legacy syslog summary granted mail exemption")
	}
	k.NoteTrusted("203.0.113.80", knownCustomerIMAP, "alice@example.test", now, syslogFed)
	if !d.trustedMailLoginSince("203.0.113.80", now.Add(-24*time.Hour)) {
		t.Fatal("trusted login did not grant exemption")
	}
}

// A preferred cPanel summary can age out while mail logins remain current.
func TestTrustedMailLoginSurvivesSummaryExpiry(t *testing.T) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	k, clock := knownCustomersAt(now)
	const ip = "203.0.113.82"
	k.NoteTrusted(ip, knownCustomerCpanel, "alice", now.Add(-knownCustomerTTL+12*time.Hour), serviceLog)
	k.NoteTrusted(ip, knownCustomerIMAP, "alice@example.test", now, syslogFed)
	clock.advance(20 * time.Hour)
	k.Purge()
	d := &Daemon{knownCustomers: k}
	since := clock.Now().Add(-24 * time.Hour)
	if !d.trustedMailLoginSince(ip, since) {
		t.Fatal("summary expiry removed current mail history")
	}
	saved, _ := k.Changes()
	restored := newKnownCustomers(clock.Now)
	restored.Load(saved)
	d.knownCustomers = restored
	if !d.trustedMailLoginSince(ip, since) {
		t.Fatal("load discarded current mail history")
	}
	clock.advance(knownCustomerTTL)
	restored.Purge()
	if len(restored.entries) != 0 {
		t.Fatal("expired history retained")
	}
}

func TestTrustedMailLoginRejectsFutureSavedTime(t *testing.T) {
	now := time.Now()
	k := newKnownCustomers(func() time.Time { return now })
	k.Load(map[string]store.KnownCustomer{"203.0.113.83": {Kind: knownCustomerIMAP, At: now, MailAt: now.Add(time.Hour), Syslog: true}})
	d := &Daemon{knownCustomers: k}
	if d.trustedMailLoginSince("203.0.113.83", now.Add(-24*time.Hour)) {
		t.Fatal("future saved time granted reputation exemption")
	}
}
