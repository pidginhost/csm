package daemon

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/store"
)

// v6Network is the i-th /64 under a documentation /32, with host bits set so
// the stored key differs from the noted address.
func v6Network(block, i int) string {
	return fmt.Sprintf("2001:db8:%x:%x::7", block, i)
}

func countSyslog(k *knownCustomers) (syslog int) {
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, c := range k.entries {
		if c.Syslog {
			syslog++
		}
	}
	return syslog
}

// Note, Lookup and Load agree on one key per IPv6 /64.
func TestKnownCustomersIPv6StoredPerNetwork(t *testing.T) {
	now := time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)
	k, _ := knownCustomersAt(now)
	k.Note("2001:db8:1::5", knownCustomerIMAP, "alice@example.com", now, syslogFed)
	upserts, _ := k.Changes()
	if _, ok := upserts["2001:db8:1::"]; !ok || len(upserts) != 1 {
		t.Fatalf("stored keys = %v, want the /64 only", upserts)
	}
	if hit := mustLookup(t, k, "2001:db8:1::ffff"); hit.IP != "2001:db8:1::/64" {
		t.Fatalf("Lookup = %+v", hit)
	}

	restarted, _ := knownCustomersAt(now)
	restarted.Load(map[string]store.KnownCustomer{"2001:db8:3::7": {Kind: knownCustomerIMAP, Account: "bob@example.com", At: now, Syslog: true}})
	if hit := mustLookup(t, restarted, "2001:db8:3::1"); hit.IP != "2001:db8:3::/64" {
		t.Fatalf("loaded host address is not its /64: %+v", hit)
	}
	upserts, deletes := restarted.Changes()
	if _, ok := upserts["2001:db8:3::"]; !ok || len(deletes) != 1 || deletes[0] != "2001:db8:3::7" {
		t.Fatalf("load rewrite = %v, %v; want the /64 key written and the host key deleted", upserts, deletes)
	}
}

// When the set is full, the largest account groups lose entries first, so a
// flood evicts only its own groups.
func TestKnownCustomersFullSetTrimsLargestGroups(t *testing.T) {
	now := time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)
	older := now.Add(-24 * time.Hour)

	t.Run("one FTP account from one /64", func(t *testing.T) {
		k, _ := knownCustomersAt(now)
		for i := 0; i < 1000; i++ {
			k.Note(v6Network(1, i), knownCustomerFTP, fmt.Sprintf("user%d", i), older, syslogFed)
		}
		for i := 0; i < maxKnownCustomers; i++ {
			a := netip.MustParseAddr("2001:db8:66::").As16()
			a[12], a[13], a[14], a[15] = byte(i>>24), byte(i>>16), byte(i>>8), byte(i)
			k.Note(netip.AddrFrom16(a).String(), knownCustomerFTP, "mallory", now, syslogFed)
		}
		for i := 0; i < 1000; i++ {
			if _, ok := k.Lookup(v6Network(1, i)); !ok {
				t.Fatalf("older customer %d evicted by one account's flood", i)
			}
		}
		if len(k.entries) != 1001 {
			t.Fatalf("set holds %d, want the 1000 customers and one /64", len(k.entries))
		}
	})

	t.Run("one stolen credential from one /64", func(t *testing.T) {
		k, _ := knownCustomersAt(now)
		k.Note("2001:db8:a::1", knownCustomerIMAP, "alice@example.com", older, syslogFed)
		for i := 1; i <= maxKnownCustomerIPsPerAccount; i++ {
			k.Note(fmt.Sprintf("2001:db8:b::%x", i), knownCustomerIMAP, "alice@example.com", now, syslogFed)
		}
		if hit, ok := k.Lookup("2001:db8:a::1"); !ok || hit.Account != "alice@example.com" {
			t.Fatalf("the owner's /64 was lost: %+v, %v", hit, ok)
		}
	})

	for _, tc := range []struct {
		name string
		kind string
		src  loginSource
		cap  int
	}{
		{"mailboxes over syslog", knownCustomerIMAP, syslogFed, maxSyslogCustomers},
		{"accounts in session_log", knownCustomerCpanel, serviceLog, maxKnownCustomers},
	} {
		t.Run("800 "+tc.name+" at 64 addresses each", func(t *testing.T) {
			k, _ := knownCustomersAt(now)
			const existing = 2000
			for i := 0; i < existing; i++ {
				k.Note(v6Network(1, i), tc.kind, fmt.Sprintf("customer%d", i), older, tc.src)
			}
			for m := 0; m < 800; m++ {
				for i := 0; i < maxKnownCustomerIPsPerAccount; i++ {
					k.Note(v6Network(0x100+m, i), tc.kind, fmt.Sprintf("flood%d", m), now.Add(time.Duration(i)*time.Second), tc.src)
				}
			}
			for i := 0; i < existing; i++ {
				if _, ok := k.Lookup(v6Network(1, i)); !ok {
					t.Fatalf("customer %d outside the flood was evicted", i)
				}
			}
			if len(k.entries) > tc.cap {
				t.Fatalf("set holds %d, over its cap %d", len(k.entries), tc.cap)
			}
			k.mu.Lock()
			defer k.mu.Unlock()
			for m := 0; m < 800; m++ {
				if n := len(k.groups[customerGroup{syslog: bool(tc.src), account: fmt.Sprintf("flood%d", m)}]); n == 0 || n > maxKnownCustomerIPsPerAccount {
					t.Fatalf("flood group %d holds %d", m, n)
				}
			}
		})
	}
}

// Any local user can write syslog with logger. A forged flood stays within
// the syslog half and cannot push out or relabel logins read from session_log
// or the Exim mainlog.
func TestKnownCustomersSyslogFloodKeepsServiceLogins(t *testing.T) {
	// With few service logins the flood fills its half; with more than half
	// the set held by service logins, the flood still only evicts itself.
	for _, service := range []int{3000, 30000} {
		t.Run(fmt.Sprintf("%d service logins", service), func(t *testing.T) {
			now := time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)
			k, _ := knownCustomersAt(now)
			serviceKinds := []string{knownCustomerCpanel, knownCustomerWebmail, knownCustomerSMTP}
			for i := 0; i < service; i++ {
				k.Note(v6Network(1, i), serviceKinds[i%3], fmt.Sprintf("user%d", i), now.Add(-time.Hour), serviceLog)
			}
			syslogKinds := []string{knownCustomerFTP, knownCustomerIMAP, knownCustomerPOP, knownCustomerSMTP}
			for i := 0; i < service; i++ { // the same addresses, forged newer
				k.Note(v6Network(1, i), syslogKinds[i%4], "forged", now, syslogFed)
			}
			for i := 0; i < 60000; i++ {
				k.Note(v6Network(0x1000+i/0x10000, i%0x10000), syslogKinds[i%4], fmt.Sprintf("forged%d", i), now, syslogFed)
			}
			for i := 0; i < service; i++ {
				hit, ok := k.Lookup(v6Network(1, i))
				if !ok || hit.Kind != serviceKinds[i%3] || hit.Account != fmt.Sprintf("user%d", i) || customerFromSyslog(t, k, v6Network(1, i)) {
					t.Fatalf("service login %d lost or relabelled: %+v, %v", i, hit, ok)
				}
			}
			syslog := countSyslog(k)
			if syslog > maxSyslogCustomers || len(k.entries) > maxKnownCustomers {
				t.Fatalf("syslog logins hold %d of %d, over a cap", syslog, len(k.entries))
			}
			// A trim leaves 95% of the cap it hit, plus the newest login.
			if floor := min(maxSyslogCustomers*95/100+1, maxKnownCustomers*95/100+1-service); syslog < floor {
				t.Fatalf("syslog logins hold %d, want at least %d", syslog, floor)
			}
		})
	}
}

// Pending deletes are bounded between saves; a key past the bound stays on
// disk until a later load drops it again.
func TestKnownCustomersPendingDeletesBounded(t *testing.T) {
	now := time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)
	k, _ := knownCustomersAt(now)
	saved := make(map[string]store.KnownCustomer, maxKnownCustomers+100)
	for i := 0; i < maxKnownCustomers+100; i++ {
		saved[fmt.Sprintf("bad-%d", i)] = store.KnownCustomer{Kind: knownCustomerFTP, At: now}
	}
	k.Load(saved)
	if _, deletes := k.Changes(); len(deletes) != maxKnownCustomers {
		t.Fatalf("pending deletes = %d, want %d", len(deletes), maxKnownCustomers)
	}
}
