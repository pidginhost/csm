package daemon

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/store"
)

func TestKnownCustomersAccountRotationAtGlobalCap(t *testing.T) {
	now := time.Now()
	k, _ := knownCustomersAt(now)
	// Separate accounts and networks fill the host budget legitimately.
	for i := 0; i < maxServiceCustomers; i++ {
		ip := fmt.Sprintf("2001:db8:%x::1", i)
		account := fmt.Sprintf("user%d", i)
		if i < maxKnownCustomerIPsPerAccount {
			account = "rotating"
		}
		k.Note(ip, knownCustomerCpanel, account, now.Add(-time.Hour), serviceLog)
	}
	k.Note("2001:db8:ffff::1", knownCustomerCpanel, "rotating", now, serviceLog)
	if len(k.entries) != maxServiceCustomers {
		t.Fatalf("one account rotation evicted unrelated customers: %d remain", len(k.entries))
	}
	if _, ok := k.Lookup("2001:db8:64::1"); !ok {
		t.Fatal("unrelated customer lost at the global cap")
	}
}

func TestKnownCustomersAccountlessLoginsAreBounded(t *testing.T) {
	now := time.Now()
	k, _ := knownCustomersAt(now)
	for i := 0; i < 2*maxKnownCustomerIPsPerAccount; i++ {
		k.Note(fmt.Sprintf("2001:db8:%x::1", i), knownCustomerFTP, "", now, serviceLog)
	}
	if len(k.entries) != maxKnownCustomerIPsPerAccount {
		t.Fatalf("unnamed logins bypassed the account budget: %d", len(k.entries))
	}
}

// One IPv6 /64 is one host: rotating privacy addresses and accounts give one
// entry, and any address in the /64 is that customer.
func TestKnownCustomersIPv6NetworkIsOneEntry(t *testing.T) {
	now := time.Now()
	k, _ := knownCustomersAt(now)
	for i := 0; i < 2*maxKnownCustomerIPsPerAccount; i++ {
		k.Note(fmt.Sprintf("2001:db8:1::%x", i), knownCustomerIMAP, fmt.Sprintf("user%d", i), now.Add(time.Duration(i)*time.Millisecond), serviceLog)
	}
	if len(k.entries) != 1 {
		t.Fatalf("one /64 holds %d entries, want 1", len(k.entries))
	}
	if hit := mustLookup(t, k, "2001:db8:1::ffff"); hit.IP != "2001:db8:1::/64" || hit.Account != fmt.Sprintf("user%d", 2*maxKnownCustomerIPsPerAccount-1) {
		t.Fatalf("Lookup = %+v, want the /64 with its newest login", hit)
	}
	if _, ok := k.Lookup("2001:db8:1:1::1"); ok {
		t.Fatal("a neighbouring /64 matched")
	}
}

func TestKnownCustomersUnsavedChurnNeedsNoDeletes(t *testing.T) {
	now := time.Now()
	k, _ := knownCustomersAt(now)
	for i := 0; i < 4*maxKnownCustomerIPsPerAccount; i++ {
		k.Note(fmt.Sprintf("2001:db8:%x::1", i), knownCustomerIMAP, "alice", now, serviceLog)
	}
	upserts, deletes := k.Changes()
	if len(upserts) != maxKnownCustomerIPsPerAccount || len(deletes) != 0 {
		t.Fatalf("unsaved churn: upserts=%d deletes=%d", len(upserts), len(deletes))
	}
}

func TestKnownCustomersShutdownSavesLateLogin(t *testing.T) {
	d := newTestDaemon(t)
	db, restore := openTestBoltStore(t, t.TempDir())
	t.Cleanup(restore)
	d.persistKnownCustomers() // The periodic writer can finish before log readers.
	d.knownCustomers.Note("203.0.113.8", knownCustomerIMAP, "alice", time.Now(), serviceLog)
	d.flushPendingAlertsOnShutdown()
	saved, err := db.LoadKnownCustomers()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := saved["203.0.113.8"]; !ok {
		t.Fatal("shutdown lost a login read after the periodic writer stopped")
	}
}

func TestKnownCustomersFTPUsesAccountAndLogTime(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	k, _ := knownCustomersAt(now)
	d := &Daemon{knownCustomers: k}
	for i := 1; i <= maxKnownCustomerIPsPerAccount+1; i++ {
		line := fmt.Sprintf("%s host pure-ftpd[1]: (?@203.0.113.%d) [INFO] alice is now logged in", now.Add(-time.Hour).Format(time.RFC3339), i)
		d.noteFTPCustomers(parseFTPLogLine(line, &config.Config{}))
	}
	hit := mustLookup(t, k, "203.0.113.65")
	if hit.Account != "alice" || !hit.At.Equal(now.Add(-time.Hour)) {
		t.Fatalf("FTP lost its logged identity or time: %+v", hit)
	}
	if n, _ := k.Within(netip.MustParsePrefix("203.0.113.0/24"), 0, nil); n != maxKnownCustomerIPsPerAccount {
		t.Fatalf("FTP account holds %d addresses", n)
	}
	old := fmt.Sprintf("%s host pure-ftpd[1]: (?@198.51.100.1) [INFO] bob is now logged in", now.Add(-knownCustomerTTL-time.Hour).Format(time.RFC3339))
	d.noteFTPCustomers(parseFTPLogLine(old, &config.Config{}))
	if _, ok := k.Lookup("198.51.100.1"); ok {
		t.Fatal("old FTP history was renewed on read")
	}
}

func TestKnownCustomersRequeueRetainsStoredDeletion(t *testing.T) {
	now := time.Now()
	k, _ := knownCustomersAt(now)
	k.Load(map[string]store.KnownCustomer{"203.0.113.1": {Kind: knownCustomerIMAP, Account: "alice", At: now.Add(-time.Hour)}})
	k.Note("203.0.113.1", knownCustomerIMAP, "alice", now, serviceLog)
	upserts, deletes := k.Changes()
	k.mu.Lock()
	k.removeLocked(netip.MustParseAddr("203.0.113.1"))
	k.mu.Unlock()
	k.requeue(upserts, deletes)
	upserts, deletes = k.Changes()
	if len(upserts) != 0 || len(deletes) != 1 || deletes[0] != "203.0.113.1" {
		t.Fatalf("failed save resurrected a removed customer: %v, %v", upserts, deletes)
	}
}

func TestKnownCustomersFailedDeletionSurvivesReadmission(t *testing.T) {
	now := time.Now()
	k, _ := knownCustomersAt(now)
	const ip = "203.0.113.1"
	addr := netip.MustParseAddr(ip)
	k.Load(map[string]store.KnownCustomer{ip: {Kind: knownCustomerIMAP, Account: "alice", At: now.Add(-time.Hour)}})
	k.removeLocked(addr)
	upserts, deletes := k.Changes()
	k.requeue(upserts, deletes)
	k.Note(ip, knownCustomerIMAP, "alice", now, serviceLog)
	k.removeLocked(addr)
	upserts, deletes = k.Changes()
	if len(upserts) != 0 || len(deletes) != 1 || deletes[0] != ip {
		t.Fatalf("failed deletion was lost after another login and eviction: %v, %v", upserts, deletes)
	}
}

func TestKnownCustomersBufferedLoginsKeepEventTime(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	d := New(&config.Config{}, nil, nil, "")
	d.staleSession401 = newStaleSession401s()
	d.hijackDetector = NewPasswordHijackDetector(d.currentCfg(), d.alertCh, d.stopCh)
	for _, age := range []time.Duration{time.Hour, knownCustomerTTL + time.Hour} {
		at := now.Add(-age)
		for i, proto := range []string{"cpanel", "postfix", "imap", "exim"} {
			ip := fmt.Sprintf("203.0.113.%d", i+1)
			k, _ := knownCustomersAt(now)
			d.knownCustomers = k
			d.smtpAuthTracker.SetKnownCustomers(k)
			d.mailAuthTracker.SetKnownCustomers(k)
			switch proto {
			case "cpanel":
				line := strings.Replace(sessionNewLine("cpaneld", ip, "alice"), "2026-11-05 09:00:00 +0000", at.Format("2006-01-02 15:04:05 -0700"), 1)
				d.cpanelSessionLogHandler(line, d.currentCfg())
			case "postfix":
				line := at.Format(time.RFC3339) + " host postfix/smtpd[1]: 4ABC123: client=unknown[" + ip + "], sasl_method=PLAIN, sasl_username=alice@example.com"
				d.handleMailLine(line, alert.Observation{}, d.currentCfg())
			case "imap":
				line := at.Format(time.RFC3339) + " host dovecot: imap-login: Logged in: user=<alice@example.com>, method=PLAIN, rip=" + ip + ", lip=192.0.2.1, mpid=1, TLS"
				d.handleMailLine(line, alert.Observation{}, d.currentCfg())
			case "exim":
				line := at.Format("2006-01-02 15:04:05") + " 1abc23-000456-AB <= alice@example.com H=mail.example.com [" + ip + "] P=esmtpsa A=dovecot_login:alice@example.com S=100"
				d.handleEximLine(line, alert.Observation{}, d.currentCfg())
			}
			hit, ok := k.Lookup(ip)
			if age < knownCustomerTTL {
				if !ok || !hit.At.Equal(at) {
					t.Errorf("%s lost the login time: %+v, %v; want %v", proto, hit, ok, at)
				}
			} else if ok {
				t.Errorf("%s renewed an expired login: %+v", proto, hit)
			}
		}
	}
}

func TestKnownCustomersLoadPersistsGroupEvictions(t *testing.T) {
	now := time.Now()
	k, _ := knownCustomersAt(now)
	saved := make(map[string]store.KnownCustomer)
	for i := 0; i < 2*maxKnownCustomerIPsPerAccount; i++ {
		ip := netip.MustParseAddr(fmt.Sprintf("2001:db8:%x::", i)).String()
		saved[ip] = store.KnownCustomer{
			Kind: knownCustomerIMAP, Account: "alice", Syslog: true,
			At: now.Add(-time.Duration(i) * time.Minute),
		}
	}
	k.Load(saved)
	upserts, deletes := k.Changes()
	if len(upserts) != 0 || len(deletes) != maxKnownCustomerIPsPerAccount || len(k.entries) != maxKnownCustomerIPsPerAccount {
		t.Fatalf("loaded cap: entries=%d upserts=%d deletes=%d", len(k.entries), len(upserts), len(deletes))
	}
	for _, ip := range deletes {
		delete(saved, ip)
	}
	restarted, _ := knownCustomersAt(now)
	restarted.Load(saved)
	for i := 0; i < 2*maxKnownCustomerIPsPerAccount; i++ {
		_, ok := restarted.Lookup(fmt.Sprintf("2001:db8:%x::1", i))
		if ok != (i < maxKnownCustomerIPsPerAccount) {
			t.Errorf("restart kept wrong login %d: %v", i, ok)
		}
	}
}

func TestKnownCustomersConcurrentSaveAndLogin(t *testing.T) {
	now := time.Now()
	k, _ := knownCustomersAt(now)
	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wg.Go(func() {
			for i := 0; i < 100; i++ {
				ip := fmt.Sprintf("2001:db8:%x:%x::1", worker, i)
				k.Note(ip, knownCustomerSMTP, fmt.Sprintf("user%d", worker), now, serviceLog)
				k.Lookup(ip)
				k.Within(netip.MustParsePrefix("2001:db8::/32"), 2, nil)
				if worker == 0 {
					upserts, deletes := k.Changes()
					k.requeue(upserts, deletes)
					k.Purge()
				}
			}
		})
	}
	wg.Wait()
	upserts, _ := k.Changes()
	if len(k.entries) != 4*maxKnownCustomerIPsPerAccount || len(upserts) != len(k.entries) {
		t.Fatalf("concurrent save lost live entries: entries=%d upserts=%d", len(k.entries), len(upserts))
	}
	for raw, saved := range upserts {
		if got := mustLookup(t, k, raw); got.Account != saved.Account || !got.At.Equal(saved.At) {
			t.Errorf("save did not snapshot current login: %+v vs %+v", saved, got)
		}
	}
}
