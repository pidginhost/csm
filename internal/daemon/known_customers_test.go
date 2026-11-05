package daemon

import (
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/blockdigest"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/store"
)

// sessionNewLine is a session_log record of a new cPanel or webmail session,
// shaped as cpsrvd writes it.
func sessionNewLine(tag, ip, account string) string {
	return fmt.Sprintf("[2026-11-05 09:00:00 +0000] info [%s] %s NEW %s:Qw3Er5Ty7Ui9Op1A address=%s,app=%s,creator=%s,method=handle_form_login,path=form,possessed=0",
		tag, ip, account, ip, tag, account)
}

func TestParseSessionNew(t *testing.T) {
	for _, tc := range []struct {
		line, app, ip, account string
	}{
		{sessionNewLine("cpaneld", "203.0.113.10", "alice"), "cpaneld", "203.0.113.10", "alice"},
		{sessionNewLine("webmaild", "2001:db8::10", "office@example.com"), "webmaild", "2001:db8::10", "office@example.com"},
		{"[2026-11-05 09:00:00 +0000] info [cpaneld] 198.51.100.10 NEW bob:tok", "cpaneld", "198.51.100.10", "bob"},
	} {
		app, ip, account, ok := parseSessionNew(tc.line)
		if !ok || app != tc.app || ip != tc.ip || account != tc.account {
			t.Errorf("parseSessionNew(%q) = %q, %q, %q, %v; want %q, %q, %q, true",
				tc.line, app, ip, account, ok, tc.app, tc.ip, tc.account)
		}
	}
}

// Only the canonical position counts: an attacker who can put text into a
// session_log line (a login name, an address field) must not be able to
// supply the tag, the address or the NEW verb.
func TestParseSessionNewRejectsForgedFields(t *testing.T) {
	const ts = "[2026-11-05 09:00:00 +0000] "
	for name, line := range map[string]string{
		"tag after NEW":           ts + "info [whostmgrd] 203.0.113.11 NEW [cpaneld] alice:tok",
		"webmail tag after NEW":   ts + "info [security] 203.0.113.11 NEW [webmaild]:tok address=203.0.113.11",
		"tag inside account":      ts + "info [whostmgrd] 203.0.113.12 NEW x[cpaneld]:tok address=203.0.113.12",
		"tag inside address":      ts + "info [whostmgrd] 203.0.113.13 NEW root:tok address=[cpaneld] 203.0.113.99 NEW alice:tok",
		"tag in timestamp slot":   "[cpaneld] 203.0.113.14 NEW alice:tok",
		"no level token":          ts + "[cpaneld] 203.0.113.14 NEW alice:tok",
		"no timestamp":            "info [cpaneld] 203.0.113.14 NEW alice:tok",
		"hostname first":          ts + "info [cpaneld] host.example.com NEW alice:tok",
		"bad address":             ts + "info [cpaneld] 203.0.113.256 NEW alice:tok",
		"missing NEW":             ts + "info [cpaneld] 203.0.113.15 alice:tok address=203.0.113.15",
		"NEW not after address":   ts + "info [cpaneld] 203.0.113.15 PURGE alice:tok NEW bob:tok",
		"empty account":           ts + "info [cpaneld] 203.0.113.16 NEW :tok address=203.0.113.16",
		"no session token":        ts + "info [cpaneld] 203.0.113.16 NEW alice address=203.0.113.16",
		"empty session token":     ts + "info [cpaneld] 203.0.113.16 NEW alice: address=203.0.113.16",
		"truncated after NEW":     ts + "info [cpaneld] 203.0.113.16 NEW",
		"PURGE":                   ts + "info [cpaneld] 203.0.113.17 PURGE alice:tok logout",
		"EXPIRED":                 ts + "info [webmaild] 203.0.113.18 EXPIRED office@example.com:tok",
		"LOGOUT":                  ts + "info [cpaneld] 203.0.113.19 LOGOUT alice:tok",
		"other service":           ts + "info [whostmgrd] 203.0.113.20 NEW root:tok address=203.0.113.20",
		"tag glued to next field": ts + "info [cpaneld]203.0.113.21 NEW alice:tok",
	} {
		if app, ip, account, ok := parseSessionNew(line); ok {
			t.Errorf("%s: parseSessionNew(%q) = %q, %q, %q, true; want rejected", name, line, app, ip, account)
		}
	}
}

func knownCustomersAt(t0 time.Time) (*knownCustomers, *staticClock) {
	clock := &staticClock{t: t0}
	return newKnownCustomers(clock.Now), clock
}

func mustLookup(t *testing.T, k *knownCustomers, ip string) blockdigest.CustomerHit {
	t.Helper()
	hit, ok := k.Lookup(ip)
	if !ok {
		t.Fatalf("Lookup(%q) found nothing", ip)
	}
	return hit
}

func sameHit(a, b blockdigest.CustomerHit) bool {
	return a.IP == b.IP && a.Kind == b.Kind && a.Account == b.Account && a.At.Equal(b.At)
}

func TestKnownCustomersNoteLookup(t *testing.T) {
	now := time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)
	k, clock := knownCustomersAt(now)

	for i, kind := range []string{knownCustomerCpanel, knownCustomerWebmail, knownCustomerSMTP, knownCustomerIMAP, knownCustomerFTP} {
		ip := fmt.Sprintf("203.0.113.%d", 10+i)
		k.Note(ip, kind, " Alice@Example.COM ", now.Add(-time.Hour))
		want := blockdigest.CustomerHit{IP: ip, Kind: kind, Account: "alice@example.com", At: now.Add(-time.Hour)}
		if got := mustLookup(t, k, ip); !sameHit(got, want) {
			t.Errorf("%s: Lookup = %+v, want %+v", kind, got, want)
		}
	}

	// One spelling per address, whichever form the log used.
	k.Note("2001:DB8::5", knownCustomerIMAP, "bob@example.com", now)
	for _, spelling := range []string{"2001:db8::5", "2001:DB8::5", "2001:db8:0::5"} {
		if got := mustLookup(t, k, spelling); got.IP != "2001:db8::5" {
			t.Errorf("Lookup(%q).IP = %q, want 2001:db8::5", spelling, got.IP)
		}
	}
	k.Note("::ffff:198.51.100.7", knownCustomerSMTP, "carol@example.com", now)
	for _, spelling := range []string{"198.51.100.7", "::ffff:198.51.100.7"} {
		if got := mustLookup(t, k, spelling); got.IP != "198.51.100.7" {
			t.Errorf("Lookup(%q).IP = %q, want 198.51.100.7", spelling, got.IP)
		}
	}

	// Never stored: unusable, zoned, loopback, private and infra addresses.
	// Loopback and private are built from bytes; the repo keeps address
	// literals to the documentation ranges.
	k.isInfra = func(ip string) bool { return ip == "198.51.100.200" }
	ignored := []string{
		"", "not-an-ip", "203.0.113.256", "2001:db8::9%eth0",
		netip.AddrFrom4([4]byte{127, 0, 0, 1}).String(),
		netip.IPv6Loopback().String(),
		netip.AddrFrom4([4]byte{10, 1, 2, 3}).String(),
		netip.AddrFrom4([4]byte{192, 168, 1, 2}).String(),
		netip.AddrFrom16([16]byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5}).String(),
		"::ffff:" + netip.AddrFrom4([4]byte{10, 1, 2, 3}).String(),
		"198.51.100.200",
	}
	before := len(k.entries)
	for _, ip := range ignored {
		k.Note(ip, knownCustomerFTP, "dave", now)
		if _, ok := k.Lookup(ip); ok {
			t.Errorf("Note stored %q", ip)
		}
	}
	if len(k.entries) != before {
		t.Fatalf("ignored addresses grew the set from %d to %d", before, len(k.entries))
	}

	// A login stamped in the future counts as now; one older than the TTL is
	// not a customer login any more.
	k.Note("203.0.113.30", knownCustomerFTP, "", now.Add(48*time.Hour))
	if got := mustLookup(t, k, "203.0.113.30"); !got.At.Equal(now) {
		t.Errorf("future login At = %v, want clamped to %v", got.At, now)
	}
	k.Note("203.0.113.31", knownCustomerFTP, "", now.Add(-knownCustomerTTL))
	if _, ok := k.Lookup("203.0.113.31"); ok {
		t.Error("a login exactly one TTL old was stored")
	}

	// A late, older report does not replace the newer login.
	k.Note("203.0.113.10", knownCustomerSMTP, "mallory@example.com", now.Add(-2*time.Hour))
	if got := mustLookup(t, k, "203.0.113.10"); got.Kind != knownCustomerCpanel || got.Account != "alice@example.com" {
		t.Errorf("older login replaced the newer one: %+v", got)
	}
	// A newer one does.
	k.Note("203.0.113.10", knownCustomerWebmail, "erin@example.com", now)
	if got := mustLookup(t, k, "203.0.113.10"); got.Kind != knownCustomerWebmail || got.Account != "erin@example.com" || !got.At.Equal(now) {
		t.Errorf("newer login did not replace the entry: %+v", got)
	}

	// 30-day expiry: present just before, absent at the TTL, even before a
	// purge runs.
	clock.advance(knownCustomerTTL - time.Second)
	if _, ok := k.Lookup("203.0.113.10"); !ok {
		t.Fatal("entry expired before the TTL")
	}
	clock.advance(time.Second)
	if _, ok := k.Lookup("203.0.113.10"); ok {
		t.Fatal("entry still found at the TTL")
	}
	k.Purge()
	if len(k.entries) != 0 {
		t.Fatalf("Purge left %d expired entries", len(k.entries))
	}
}

func TestKnownCustomersPerAccountCap(t *testing.T) {
	now := time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)
	k, _ := knownCustomersAt(now)
	start := now.Add(-time.Hour)

	k.Note("198.51.100.1", knownCustomerIMAP, "bob@example.com", start)
	k.Note("198.51.100.2", knownCustomerSMTP, "bob@example.com", start)
	for i := 1; i <= maxKnownCustomerIPsPerAccount+1; i++ {
		// One mailbox, however the log spelled it.
		account := "alice@example.com"
		if i%2 == 0 {
			account = "ALICE@example.com"
		}
		k.Note(fmt.Sprintf("203.0.113.%d", i), knownCustomerIMAP, account, start.Add(time.Duration(i)*time.Second))
	}
	if _, ok := k.Lookup("203.0.113.1"); ok {
		t.Error("the oldest address of the account was kept")
	}
	for i := 2; i <= maxKnownCustomerIPsPerAccount+1; i++ {
		if _, ok := k.Lookup(fmt.Sprintf("203.0.113.%d", i)); !ok {
			t.Errorf("203.0.113.%d dropped; only the oldest should go", i)
		}
	}
	if n, _ := k.Within(netip.MustParsePrefix("203.0.113.0/24"), 0); n != maxKnownCustomerIPsPerAccount {
		t.Errorf("account holds %d addresses, want %d", n, maxKnownCustomerIPsPerAccount)
	}
	for _, ip := range []string{"198.51.100.1", "198.51.100.2"} {
		if _, ok := k.Lookup(ip); !ok {
			t.Errorf("another account lost %s", ip)
		}
	}

	// An address that moves to another account frees its old slot.
	k.Note("203.0.113.2", knownCustomerIMAP, "bob@example.com", now)
	k.Note("203.0.113.200", knownCustomerIMAP, "alice@example.com", now)
	if _, ok := k.Lookup("203.0.113.3"); !ok {
		t.Error("a moved address still counted against its old account")
	}

	// Logins without an account name have no per-account cap.
	for i := 1; i <= maxKnownCustomerIPsPerAccount+10; i++ {
		k.Note(fmt.Sprintf("2001:db8:2::%x", i), knownCustomerFTP, "", start)
	}
	if n, _ := k.Within(netip.MustParsePrefix("2001:db8:2::/64"), 0); n != maxKnownCustomerIPsPerAccount+10 {
		t.Errorf("unnamed logins kept %d addresses, want %d", n, maxKnownCustomerIPsPerAccount+10)
	}
}

// knownCustomerTestAddr is the i-th address of a documentation /96.
func knownCustomerTestAddr(i int) string {
	a := netip.MustParseAddr("2001:db8:100::").As16()
	a[12], a[13], a[14], a[15] = byte(i>>24), byte(i>>16), byte(i>>8), byte(i)
	return netip.AddrFrom16(a).String()
}

func TestKnownCustomersGlobalCapEvictsOldest(t *testing.T) {
	now := time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)
	k, _ := knownCustomersAt(now)
	for i := 0; i < maxKnownCustomers; i++ {
		k.Note(knownCustomerTestAddr(i), knownCustomerFTP, "", now.Add(-time.Duration(maxKnownCustomers-i)*time.Second))
	}
	if len(k.entries) != maxKnownCustomers {
		t.Fatalf("set holds %d, want %d before the cap", len(k.entries), maxKnownCustomers)
	}
	// Re-noting a held address is no insert and evicts nothing.
	k.Note(knownCustomerTestAddr(0), knownCustomerFTP, "", now.Add(-time.Duration(maxKnownCustomers)*time.Second))
	if len(k.entries) != maxKnownCustomers {
		t.Fatalf("an update evicted: %d entries", len(k.entries))
	}

	k.Note(knownCustomerTestAddr(maxKnownCustomers), knownCustomerFTP, "", now)
	keep := maxKnownCustomers * 95 / 100
	if len(k.entries) != keep+1 {
		t.Fatalf("set holds %d after the cap, want %d", len(k.entries), keep+1)
	}
	evicted := maxKnownCustomers - keep
	for _, i := range []int{0, 1, evicted - 1} {
		if _, ok := k.Lookup(knownCustomerTestAddr(i)); ok {
			t.Errorf("old entry %d kept", i)
		}
	}
	for _, i := range []int{evicted, evicted + 1, maxKnownCustomers - 1, maxKnownCustomers} {
		if _, ok := k.Lookup(knownCustomerTestAddr(i)); !ok {
			t.Errorf("recent entry %d evicted", i)
		}
	}
	if len(k.accounts) != 0 {
		t.Errorf("unnamed logins indexed %d accounts", len(k.accounts))
	}
}

func TestKnownCustomersWithin(t *testing.T) {
	now := time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)
	k, clock := knownCustomersAt(now)
	for i := 1; i <= 10; i++ {
		k.Note(fmt.Sprintf("203.0.113.%d", i), knownCustomerCpanel, fmt.Sprintf("user%d", i), now.Add(time.Duration(i-20)*time.Minute))
	}
	k.Note("203.0.113.100", knownCustomerFTP, "", now.Add(-knownCustomerTTL+time.Hour))
	k.Note("198.51.100.1", knownCustomerCpanel, "other", now)
	for i := 1; i <= 6; i++ {
		k.Note(fmt.Sprintf("2001:db8:1::%d", i), knownCustomerIMAP, "office@example.com", now.Add(time.Duration(i-20)*time.Minute))
	}
	k.Note("2001:db8:1:1::1", knownCustomerIMAP, "office@example.com", now)
	clock.advance(2 * time.Hour) // 203.0.113.100 is now past the TTL

	n, sample := k.Within(netip.MustParsePrefix("203.0.113.77/24"), 3)
	if n != 10 {
		t.Errorf("/24 count = %d, want 10", n)
	}
	var ips []string
	for _, h := range sample {
		ips = append(ips, h.IP)
	}
	if want := []string{"203.0.113.10", "203.0.113.9", "203.0.113.8"}; !slices.Equal(ips, want) {
		t.Errorf("/24 sample = %v, want the most recent %v", ips, want)
	}
	if want := (blockdigest.CustomerHit{IP: "203.0.113.10", Kind: knownCustomerCpanel, Account: "user10", At: now.Add(-10 * time.Minute)}); len(sample) == 0 || !sameHit(sample[0], want) {
		t.Errorf("sample[0] = %+v, want %+v", sample, want)
	}

	n, sample = k.Within(netip.MustParsePrefix("2001:db8:1::/64"), 5)
	if n != 6 || len(sample) != 5 {
		t.Errorf("/64 = %d with %d samples, want 6 with 5", n, len(sample))
	}
	if n, sample = k.Within(netip.MustParsePrefix("2001:db8:1::/64"), 0); n != 6 || sample != nil {
		t.Errorf("limit 0 = %d, %v; want 6 and no sample", n, sample)
	}
	if n, sample = k.Within(netip.MustParsePrefix("192.0.2.0/24"), 5); n != 0 || len(sample) != 0 {
		t.Errorf("empty prefix = %d, %v", n, sample)
	}
	if n, _ = k.Within(netip.Prefix{}, 5); n != 0 {
		t.Errorf("invalid prefix counted %d", n)
	}
}

// A failed save must not lose what it carried: the next save retries it.
func TestKnownCustomersRequeueAfterFailedSave(t *testing.T) {
	now := time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)
	k, clock := knownCustomersAt(now)
	k.Note("203.0.113.1", knownCustomerFTP, "", now.Add(-knownCustomerTTL+time.Minute))
	k.Note("203.0.113.2", knownCustomerFTP, "", now)
	k.Changes()

	clock.advance(time.Minute)
	k.Purge() // 203.0.113.1 expires
	k.Note("203.0.113.2", knownCustomerSMTP, "alice@example.com", clock.t)
	upserts, deletes := k.Changes()
	if len(upserts) != 1 || len(deletes) != 1 {
		t.Fatalf("Changes = %v, %v; want one upsert and one delete", upserts, deletes)
	}
	k.requeue(upserts, deletes)
	again, againDeletes := k.Changes()
	if len(again) != 1 || again["203.0.113.2"].Kind != knownCustomerSMTP || !slices.Equal(againDeletes, []string{"203.0.113.1"}) {
		t.Fatalf("after requeue Changes = %v, %v", again, againDeletes)
	}
	if up, del := k.Changes(); len(up)+len(del) != 0 {
		t.Fatalf("Changes did not clear: %v, %v", up, del)
	}
}

func TestKnownCustomersPersistRoundTrip(t *testing.T) {
	now := time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	k, _ := knownCustomersAt(now)
	k.Note("203.0.113.10", knownCustomerCpanel, "alice", now.Add(-time.Hour))
	k.Note("2001:db8::10", knownCustomerWebmail, "office@example.com", now.Add(-2*time.Hour))
	if err = db.SaveKnownCustomers(k.Changes()); err != nil {
		t.Fatal(err)
	}
	loopback := netip.AddrFrom4([4]byte{127, 0, 0, 1}).String()
	if err = db.SaveKnownCustomers(map[string]store.KnownCustomer{
		"not-an-ip":    {Kind: knownCustomerFTP, At: now},
		loopback:       {Kind: knownCustomerFTP, At: now},
		"203.0.113.20": {Kind: knownCustomerSMTP, Account: "old@example.com", At: now.Add(-knownCustomerTTL - time.Hour)},
		"203.0.113.30": {Kind: knownCustomerIMAP, Account: "f@example.com", At: now.Add(24 * time.Hour)},
		"2001:DB8::40": {Kind: knownCustomerIMAP, Account: "C@Example.com", At: now.Add(-time.Minute)},
	}, nil); err != nil {
		t.Fatal(err)
	}

	saved, err := db.LoadKnownCustomers()
	if err != nil {
		t.Fatal(err)
	}
	k2, _ := knownCustomersAt(now)
	k2.Load(saved)

	for _, want := range []blockdigest.CustomerHit{
		{IP: "203.0.113.10", Kind: knownCustomerCpanel, Account: "alice", At: now.Add(-time.Hour)},
		{IP: "2001:db8::10", Kind: knownCustomerWebmail, Account: "office@example.com", At: now.Add(-2 * time.Hour)},
		{IP: "203.0.113.30", Kind: knownCustomerIMAP, Account: "f@example.com", At: now},
		{IP: "2001:db8::40", Kind: knownCustomerIMAP, Account: "c@example.com", At: now.Add(-time.Minute)},
	} {
		if got := mustLookup(t, k2, want.IP); !sameHit(got, want) {
			t.Errorf("loaded %+v, want %+v", got, want)
		}
	}
	for _, ip := range []string{loopback, "203.0.113.20"} {
		if _, ok := k2.Lookup(ip); ok {
			t.Errorf("load kept %s", ip)
		}
	}
	if len(k2.entries) != 4 {
		t.Fatalf("loaded %d entries, want 4", len(k2.entries))
	}

	// The next save rewrites only what load changed and drops what it skipped.
	upserts, deletes := k2.Changes()
	var up []string
	for ip := range upserts {
		up = append(up, ip)
	}
	slices.Sort(up)
	if want := []string{"2001:db8::40", "203.0.113.30"}; !slices.Equal(up, want) {
		t.Errorf("upserts after load = %v, want %v", up, want)
	}
	slices.Sort(deletes)
	wantDeletes := []string{loopback, "2001:DB8::40", "203.0.113.20", "not-an-ip"}
	slices.Sort(wantDeletes)
	if want := wantDeletes; !slices.Equal(deletes, want) {
		t.Errorf("deletes after load = %v, want %v", deletes, want)
	}
	if err = db.SaveKnownCustomers(upserts, deletes); err != nil {
		t.Fatal(err)
	}
	if saved, err = db.LoadKnownCustomers(); err != nil || len(saved) != 4 {
		t.Fatalf("bucket after cleanup = %d entries (%v), want 4", len(saved), err)
	}
}

func TestSessionLogRecordsCustomers(t *testing.T) {
	resetPurgeTrackerState()
	cfg := &config.Config{InfraIPs: []string{"198.51.100.0/24"}}
	d := New(cfg, nil, nil, "")
	d.hijackDetector = NewPasswordHijackDetector(cfg, d.alertCh, d.stopCh)
	d.staleSession401 = newStaleSession401s()

	before := time.Now()
	for _, line := range []string{
		sessionNewLine("cpaneld", "203.0.113.21", "alice"),
		sessionNewLine("webmaild", "2001:db8::21", "Office@Example.com"),
		sessionNewLine("cpaneld", "198.51.100.21", "bob"),
		"[2026-11-05 09:00:00 +0000] info [cpaneld] 203.0.113.22 PURGE carol:tok logout",
		"[2026-11-05 09:00:00 +0000] info [whostmgrd] 203.0.113.23 NEW root:tok address=203.0.113.23",
	} {
		d.cpanelSessionLogHandler(line, cfg)
	}
	after := time.Now()

	for ip, want := range map[string]blockdigest.CustomerHit{
		"203.0.113.21": {IP: "203.0.113.21", Kind: knownCustomerCpanel, Account: "alice"},
		"2001:db8::21": {IP: "2001:db8::21", Kind: knownCustomerWebmail, Account: "office@example.com"},
	} {
		got := mustLookup(t, d.knownCustomers, ip)
		if got.IP != want.IP || got.Kind != want.Kind || got.Account != want.Account || got.At.Before(before) || got.At.After(after) {
			t.Errorf("Lookup(%s) = %+v, want %+v at the time of the line", ip, got, want)
		}
	}
	for _, ip := range []string{"198.51.100.21", "203.0.113.22", "203.0.113.23"} {
		if hit, ok := d.knownCustomers.Lookup(ip); ok {
			t.Errorf("recorded %s: %+v", ip, hit)
		}
	}
}

func TestMailSuccessRecordsCustomer(t *testing.T) {
	cfg := &config.Config{}
	d := New(cfg, nil, nil, "")
	obs := alert.Observation{}

	d.handleEximLine(eximLoginLine("203.0.113.31", "alice@example.com"), obs, cfg)
	d.handleMailLine(postfixLoginLine("203.0.113.32", "bob@example.com"), obs, cfg)
	d.handleMailLine("Nov  5 09:00:00 host dovecot: imap-login: Logged in: user=<carol@example.com>, method=PLAIN, rip=2001:db8::33, lip=192.0.2.1, mpid=1, TLS", obs, cfg)
	d.handleMailLine("Nov  5 09:00:00 host dovecot[42]: pop3-login: Login: user=<dave@example.com>, method=PLAIN, rip=203.0.113.34, lip=192.0.2.1, mpid=2, TLS", obs, cfg)

	// Failed logins never make a customer.
	d.handleEximLine(makeEximDovecotFailLine("203.0.113.41", "alice@example.com"), obs, cfg)
	d.handleMailLine(fmt.Sprintf(postfixFailFmt, "203.0.113.42", "bob@example.com"), obs, cfg)
	d.handleMailLine("Nov  5 09:00:00 host dovecot: imap-login: Login aborted: Logged out (auth failed, 1 attempts in 2 secs): user=<carol@example.com>, method=PLAIN, rip=203.0.113.43, lip=192.0.2.1, TLS", obs, cfg)

	for ip, want := range map[string]blockdigest.CustomerHit{
		"203.0.113.31": {IP: "203.0.113.31", Kind: knownCustomerSMTP, Account: "alice@example.com"},
		"203.0.113.32": {IP: "203.0.113.32", Kind: knownCustomerSMTP, Account: "bob@example.com"},
		"2001:db8::33": {IP: "2001:db8::33", Kind: knownCustomerIMAP, Account: "carol@example.com"},
		"203.0.113.34": {IP: "203.0.113.34", Kind: knownCustomerIMAP, Account: "dave@example.com"},
	} {
		if got := mustLookup(t, d.knownCustomers, ip); got.IP != want.IP || got.Kind != want.Kind || got.Account != want.Account {
			t.Errorf("Lookup(%s) = %+v, want %+v", ip, got, want)
		}
	}
	for _, ip := range []string{"203.0.113.41", "203.0.113.42", "203.0.113.43"} {
		if hit, ok := d.knownCustomers.Lookup(ip); ok {
			t.Errorf("failed login recorded %s: %+v", ip, hit)
		}
	}
}

func TestFTPLoginFindingRecordsCustomer(t *testing.T) {
	d := newTestDaemon(t)
	cfg := d.currentCfg()
	at := time.Now().Add(-time.Hour).Truncate(time.Second)

	d.dispatchBatch([]alert.Finding{
		{Severity: alert.Warning, Check: "ftp_login", SourceIP: "203.0.113.51", Message: "FTP login from non-infra IP: 203.0.113.51", Timestamp: at},
		{Severity: alert.Critical, Check: "ftp_login_after_bruteforce", SourceIP: "2001:db8::52", TenantID: "Alice", Message: "FTP login succeeded from brute-force source 2001:db8::52 after 9 failed attempts", Timestamp: at},
		{Severity: alert.High, Check: "ftp_auth_failure_realtime", SourceIP: "203.0.113.53", Message: "FTP authentication failed from 203.0.113.53", Timestamp: at},
	})
	for _, want := range []blockdigest.CustomerHit{
		{IP: "203.0.113.51", Kind: knownCustomerFTP, At: at},
		{IP: "2001:db8::52", Kind: knownCustomerFTP, Account: "alice", At: at},
	} {
		if got := mustLookup(t, d.knownCustomers, want.IP); !sameHit(got, want) {
			t.Errorf("Lookup = %+v, want %+v", got, want)
		}
	}
	if _, ok := d.knownCustomers.Lookup("203.0.113.53"); ok {
		t.Error("a failed FTP login was recorded")
	}

	// The startup scan reads the logins made while the daemon was down; the
	// realtime watcher starts at the end of the log and never sees them.
	d.respondToInitialScan(cfg, []alert.Finding{
		{Severity: alert.Warning, Check: "ftp_login", SourceIP: "203.0.113.56", Message: "FTP login from non-infra IP: 203.0.113.56", Timestamp: at},
	})
	if got := mustLookup(t, d.knownCustomers, "203.0.113.56"); !sameHit(got, blockdigest.CustomerHit{IP: "203.0.113.56", Kind: knownCustomerFTP, At: at}) {
		t.Errorf("initial scan login = %+v", got)
	}

	// The realtime watcher's own lines: a login counts, and a failed login
	// whose attempted name carries the success text does not.
	login := "Nov  5 09:00:00 host pure-ftpd: (?@203.0.113.55) [INFO] alice is now logged in"
	d.dispatchBatch(parseFTPLogLine(login, cfg))
	if _, ok := d.knownCustomers.Lookup("203.0.113.55"); !ok {
		t.Error("a realtime FTP login was not recorded")
	}
	forged := "Nov  5 09:00:00 host pure-ftpd: (?@203.0.113.54) [WARNING] Authentication failed for user [x is now logged in]"
	d.dispatchBatch(parseFTPLogLine(forged, cfg))
	if hit, ok := d.knownCustomers.Lookup("203.0.113.54"); ok {
		t.Errorf("a failed FTP login naming the success text was recorded: %+v", hit)
	}
}
