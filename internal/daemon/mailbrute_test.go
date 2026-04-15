package daemon

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// staticClock already exists in smtpbrute_test.go — reuse it (same package).
// Do NOT redefine it.

func newTestMailTracker(t *testing.T, clock *staticClock) *mailAuthTracker {
	t.Helper()
	return newMailAuthTracker(
		5,              // perIPThreshold
		8,              // subnetThreshold
		12,             // accountSprayThreshold
		10*time.Minute, // window
		60*time.Minute, // suppression
		20000,          // maxTracked
		clock.Now,
	)
}

func TestMailAuthTracker_InitialSizeIsZero(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	if got := tr.Size(); got != 0 {
		t.Errorf("Size() = %d, want 0", got)
	}
}

func TestMailAuthTracker_NoFindingBelowPerIPThreshold(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	for i := 0; i < 4; i++ {
		if got := tr.Record("203.0.113.5", ""); got != nil {
			t.Fatalf("record %d: got %v, want nil", i, got)
		}
	}
}

func TestMailAuthTracker_EmitsMailBruteForceAtThreshold(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	var last []alert.Finding
	for i := 0; i < 5; i++ {
		last = tr.Record("203.0.113.5", "")
	}
	if len(last) == 0 {
		t.Fatalf("expected finding on 5th record, got nil")
	}
	var f *alert.Finding
	for i := range last {
		if last[i].Check == "mail_bruteforce" {
			f = &last[i]
			break
		}
	}
	if f == nil {
		t.Fatalf("no mail_bruteforce finding in %v", last)
	}
	if f.Severity != alert.Critical {
		t.Errorf("severity = %v, want Critical", f.Severity)
	}
	// Round-trip: message must be compatible with internal/checks.extractIPFromFinding.
	if !strings.HasPrefix(f.Message, "Mail auth brute force from ") {
		t.Errorf("message %q must begin with canonical prefix", f.Message)
	}
	idx := strings.LastIndex(f.Message, " from ")
	if idx < 0 {
		t.Fatalf("message %q has no ' from ' separator", f.Message)
	}
	rest := f.Message[idx+len(" from "):]
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		t.Fatalf("message %q: nothing after ' from '", f.Message)
	}
	candidate := strings.TrimRight(fields[0], ",:;)([]")
	if ip := net.ParseIP(candidate); ip == nil || ip.String() != "203.0.113.5" {
		t.Errorf("round-trip IP extraction from %q yielded %q, want 203.0.113.5", f.Message, candidate)
	}
}

func TestMailAuthTracker_NoDuplicatePerIPFindingsInSuppressionWindow(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	for i := 0; i < 5; i++ {
		tr.Record("203.0.113.5", "")
	}
	for i := 0; i < 10; i++ {
		clock.advance(1 * time.Second)
		out := tr.Record("203.0.113.5", "")
		for _, f := range out {
			if f.Check == "mail_bruteforce" {
				t.Fatalf("duplicate mail_bruteforce finding during suppression at iteration %d", i)
			}
		}
	}
}

func TestMailAuthTracker_SuppressionExpires_ReFires(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	for i := 0; i < 5; i++ {
		tr.Record("203.0.113.5", "")
	}
	clock.advance(61 * time.Minute)
	var fired bool
	for i := 0; i < 5; i++ {
		for _, f := range tr.Record("203.0.113.5", "") {
			if f.Check == "mail_bruteforce" {
				fired = true
			}
		}
	}
	if !fired {
		t.Fatalf("expected re-fire after suppression window")
	}
}

func TestMailAuthTracker_WindowExpiryResetsCount(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	for i := 0; i < 4; i++ {
		tr.Record("203.0.113.5", "")
	}
	clock.advance(11 * time.Minute)
	for i := 0; i < 4; i++ {
		if out := tr.Record("203.0.113.5", ""); len(out) != 0 {
			t.Fatalf("unexpected finding after window reset: %v", out)
		}
	}
}

func TestMailAuthTracker_MultipleIPsIndependent(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	for i := 0; i < 4; i++ {
		tr.Record("203.0.113.5", "")
		tr.Record("198.51.100.7", "")
	}
	if got := tr.Record("203.0.113.5", ""); len(got) == 0 {
		t.Errorf("203.0.113.5 should fire at 5th record")
	}
	if got := tr.Record("198.51.100.7", ""); len(got) == 0 {
		t.Errorf("198.51.100.7 should fire at 5th record independently")
	}
}

func TestMailAuthTracker_EmptyIPIgnored(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	for i := 0; i < 20; i++ {
		if out := tr.Record("", ""); out != nil {
			t.Fatalf("empty IP must return nil, got %v", out)
		}
	}
	if tr.Size() != 0 {
		t.Errorf("Size() = %d, want 0 for empty-IP-only input", tr.Size())
	}
}

func TestMailAuthTracker_SubnetSprayThreshold(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	var fired *alert.Finding
	for i := 1; i <= 8; i++ {
		ip := fmt.Sprintf("203.0.113.%d", i)
		for _, f := range tr.Record(ip, "") {
			if f.Check == "mail_subnet_spray" {
				cp := f
				fired = &cp
			}
		}
	}
	if fired == nil {
		t.Fatalf("expected mail_subnet_spray after 8 unique IPs in /24")
	}
	if fired.Severity != alert.Critical {
		t.Errorf("severity = %v, want Critical", fired.Severity)
	}
	if !strings.HasPrefix(fired.Message, "Mail password spray from ") {
		t.Errorf("message %q must begin with canonical prefix", fired.Message)
	}
	idx := strings.LastIndex(fired.Message, " from ")
	if idx < 0 {
		t.Fatalf("message %q has no ' from ' separator", fired.Message)
	}
	rest := fired.Message[idx+len(" from "):]
	fields := strings.Fields(rest)
	candidate := strings.TrimRight(fields[0], ",:;)([]")
	_, ipnet, err := net.ParseCIDR(candidate)
	if err != nil {
		t.Errorf("round-trip CIDR extraction from %q failed on %q: %v", fired.Message, candidate, err)
	} else if ipnet.String() != "203.0.113.0/24" {
		t.Errorf("round-trip CIDR extraction yielded %q, want 203.0.113.0/24", ipnet.String())
	}
}

func TestMailAuthTracker_SubnetSpraySuppression(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	for i := 1; i <= 8; i++ {
		tr.Record(fmt.Sprintf("203.0.113.%d", i), "")
	}
	for i := 9; i <= 20; i++ {
		out := tr.Record(fmt.Sprintf("203.0.113.%d", i), "")
		for _, f := range out {
			if f.Check == "mail_subnet_spray" {
				t.Fatalf("duplicate mail_subnet_spray finding in suppression window at i=%d", i)
			}
		}
	}
}

func TestMailAuthTracker_SubnetSprayIPv6Skipped(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	for i := 0; i < 20; i++ {
		out := tr.Record(fmt.Sprintf("2001:db8::%x", i+1), "")
		for _, f := range out {
			if f.Check == "mail_subnet_spray" {
				t.Fatalf("subnet spray finding unexpectedly emitted for IPv6 at i=%d", i)
			}
		}
	}
}

func TestMailAuthTracker_AccountSprayThreshold(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	var fired *alert.Finding
	for i := 1; i <= 12; i++ {
		ip := fmt.Sprintf("203.0.%d.1", i)
		for _, f := range tr.Record(ip, "victim@example.com") {
			if f.Check == "mail_account_spray" {
				cp := f
				fired = &cp
			}
		}
	}
	if fired == nil {
		t.Fatalf("expected mail_account_spray finding after 12 unique IPs")
	}
	if fired.Severity != alert.High {
		t.Errorf("severity = %v, want High (visibility only)", fired.Severity)
	}
	if !strings.Contains(fired.Message, "victim@example.com") {
		t.Errorf("message %q missing account", fired.Message)
	}
}

func TestMailAuthTracker_AccountSpray_EmptyAccountIgnored(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	for i := 1; i <= 20; i++ {
		ip := fmt.Sprintf("203.0.%d.1", i)
		out := tr.Record(ip, "")
		for _, f := range out {
			if f.Check == "mail_account_spray" {
				t.Fatalf("account spray must not fire without account, got %v", f)
			}
		}
	}
}

func TestMailAuthTracker_RecordSuccess_NoCompromiseIfIPWasNotFailing(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	out := tr.RecordSuccess("203.0.113.5", "alice@example.com")
	for _, f := range out {
		if f.Check == "mail_account_compromised" {
			t.Fatalf("should not fire when no prior failures for account, got %v", f)
		}
	}
}

func TestMailAuthTracker_RecordSuccess_NoCompromiseIfAccountUnknown(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	// Record failures for a DIFFERENT account — must not trigger compromise
	// on alice's successful login.
	for i := 0; i < 3; i++ {
		tr.Record("203.0.113.5", "bob@example.com")
	}
	out := tr.RecordSuccess("203.0.113.5", "alice@example.com")
	for _, f := range out {
		if f.Check == "mail_account_compromised" {
			t.Fatalf("compromise must not fire cross-account, got %v", f)
		}
	}
}

func TestMailAuthTracker_RecordSuccess_NoCompromiseIfDifferentIP(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	for i := 0; i < 3; i++ {
		tr.Record("203.0.113.5", "alice@example.com")
	}
	// Legitimate login from a different IP after someone else's brute force.
	out := tr.RecordSuccess("198.51.100.99", "alice@example.com")
	for _, f := range out {
		if f.Check == "mail_account_compromised" {
			t.Fatalf("compromise must not fire when success IP != failure IP, got %v", f)
		}
	}
}

func TestMailAuthTracker_RecordSuccess_FiresCompromiseWhenIPWasFailing(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	for i := 0; i < 3; i++ {
		tr.Record("203.0.113.5", "alice@example.com")
	}
	out := tr.RecordSuccess("203.0.113.5", "alice@example.com")
	var fired *alert.Finding
	for i := range out {
		if out[i].Check == "mail_account_compromised" {
			cp := out[i]
			fired = &cp
		}
	}
	if fired == nil {
		t.Fatalf("expected mail_account_compromised finding; out=%v", out)
	}
	if fired.Severity != alert.Critical {
		t.Errorf("severity = %v, want Critical", fired.Severity)
	}
	if !strings.Contains(fired.Message, "203.0.113.5") || !strings.Contains(fired.Message, "alice@example.com") {
		t.Errorf("message %q must contain both IP and account", fired.Message)
	}
	// Round-trip: must be compatible with extractIPFromFinding (" from " separator).
	idx := strings.LastIndex(fired.Message, " from ")
	if idx < 0 {
		t.Fatalf("message %q has no ' from ' separator", fired.Message)
	}
	rest := fired.Message[idx+len(" from "):]
	fields := strings.Fields(rest)
	candidate := strings.TrimRight(fields[0], ",:;)([]")
	if ip := net.ParseIP(candidate); ip == nil || ip.String() != "203.0.113.5" {
		t.Errorf("round-trip IP extraction from %q yielded %q, want 203.0.113.5", fired.Message, candidate)
	}
}

func TestMailAuthTracker_RecordSuccess_SuppressesDuplicates(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	for i := 0; i < 3; i++ {
		tr.Record("203.0.113.5", "alice@example.com")
	}
	_ = tr.RecordSuccess("203.0.113.5", "alice@example.com") // first fire
	out := tr.RecordSuccess("203.0.113.5", "alice@example.com")
	for _, f := range out {
		if f.Check == "mail_account_compromised" {
			t.Fatalf("duplicate compromise finding within suppression window, got %v", f)
		}
	}
}

func TestMailAuthTracker_RecordSuccess_EmptyIPOrAccountIgnored(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	for _, tc := range []struct{ ip, account string }{
		{"", "alice@example.com"},
		{"203.0.113.5", ""},
		{"", ""},
	} {
		if out := tr.RecordSuccess(tc.ip, tc.account); out != nil {
			t.Errorf("empty IP/account must return nil; ip=%q account=%q got %v", tc.ip, tc.account, out)
		}
	}
}

func TestMailAuthTracker_PurgeRemovesExpired(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	tr.Record("203.0.113.5", "victim@example.com")
	if tr.Size() == 0 {
		t.Fatalf("expected non-zero size after Record")
	}
	clock.advance(70 * time.Minute) // past window and suppression
	tr.Purge()
	if got := tr.Size(); got != 0 {
		t.Errorf("Size() after Purge = %d, want 0", got)
	}
}

func TestMailAuthTracker_MaxTrackedBatchEviction(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	const maxTracked = 100
	tr := newMailAuthTracker(5, 8, 12, 10*time.Minute, 60*time.Minute, maxTracked, clock.Now)

	// Fill 110 IPs in the same /24 so the subnet count stays predictable
	// (one subnet entry) and doesn't inflate Size beyond control.
	for i := 0; i < 110; i++ {
		clock.advance(1 * time.Millisecond)
		tr.Record(fmt.Sprintf("203.0.113.%d", (i%250)+1), "")
	}

	// The hard invariant is total <= maxTracked. The 95% eviction target is a
	// batch-efficiency detail: after an eviction pass the total drops to ~95,
	// but subsequent inserts can grow it back up to maxTracked before the next
	// pass fires. Check the observable contract, not the internal watermark.
	tr.mu.Lock()
	total := len(tr.ips) + len(tr.subnets) + len(tr.accounts)
	tr.mu.Unlock()
	if total > maxTracked {
		t.Errorf("total tracked = %d after batch eviction, want <= %d", total, maxTracked)
	}
	// Sanity: not over-evicted to nothing.
	if total < 80 {
		t.Errorf("total tracked = %d, want close to %d (not over-evicted)", total, maxTracked)
	}
}

func TestMailAuthTracker_MaxTrackedEvictsAccountsAndSubnets(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	const maxTracked = 100
	// Thresholds are 50 so detection signals don't fire during the 110 inserts —
	// only eviction logic is exercised.
	tr := newMailAuthTracker(50, 50, 50, 10*time.Minute, 60*time.Minute, maxTracked, clock.Now)

	// Workload dominated by ACCOUNTS (one attacker IP attacking 110 mailboxes,
	// also accidentally creates 1 subnet). This stresses the bug where the
	// loop guard only checked len(t.ips) and never evicted accounts.
	for i := 0; i < 110; i++ {
		clock.advance(1 * time.Millisecond)
		tr.Record("203.0.113.5", fmt.Sprintf("victim%d@example.com", i))
	}

	tr.mu.Lock()
	total := len(tr.ips) + len(tr.subnets) + len(tr.accounts)
	tr.mu.Unlock()
	// Hard invariant: total must never exceed the cap.
	if total > maxTracked {
		t.Errorf("total tracked = %d, want <= %d (account/subnet eviction must work)", total, maxTracked)
	}
	// Sanity: not over-evicted to nothing.
	if total < 80 {
		t.Errorf("total tracked = %d, want close to %d (not over-evicted)", total, maxTracked)
	}
}

func TestMailAuthTracker_ConcurrentNoRace(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	var wg sync.WaitGroup
	for g := 0; g < 50; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				tr.Record(fmt.Sprintf("203.0.%d.%d", id%250+1, i%250+1), "")
			}
		}(g)
	}
	wg.Wait()
	tr.Purge() // must not race
}

func TestExtractMailLoginEvent_IMAPFailure(t *testing.T) {
	line := `Apr 14 12:00:00 host dovecot: imap-login: Aborted login (auth failed, 1 attempts in 2 secs): user=<alice@x.ro>, method=PLAIN, rip=1.2.3.4, lip=1.1.1.1, TLS`
	ip, account, success := extractMailLoginEvent(line)
	if ip != "1.2.3.4" || account != "alice@x.ro" || success {
		t.Errorf("got (%q, %q, %v), want (1.2.3.4, alice@x.ro, false)", ip, account, success)
	}
}

func TestExtractMailLoginEvent_POP3Failure(t *testing.T) {
	line := `Apr 14 12:00:00 host dovecot: pop3-login: Aborted login (auth failed, 1 attempts): user=<bob@x.ro>, method=PLAIN, rip=5.6.7.8`
	ip, account, success := extractMailLoginEvent(line)
	if ip != "5.6.7.8" || account != "bob@x.ro" || success {
		t.Errorf("got (%q, %q, %v), want (5.6.7.8, bob@x.ro, false)", ip, account, success)
	}
}

func TestExtractMailLoginEvent_ManageSieveFailure(t *testing.T) {
	line := `Apr 14 12:00:00 host dovecot: managesieve-login: Aborted login (auth failed): user=<c@x.ro>, method=PLAIN, rip=9.9.9.9`
	ip, account, success := extractMailLoginEvent(line)
	if ip != "9.9.9.9" || account != "c@x.ro" || success {
		t.Errorf("got (%q, %q, %v), want (9.9.9.9, c@x.ro, false)", ip, account, success)
	}
}

func TestExtractMailLoginEvent_IMAPSuccess(t *testing.T) {
	line := `Apr 14 12:00:05 host dovecot: imap-login: Login: user=<alice@x.ro>, method=PLAIN, rip=1.2.3.4, lip=..., TLS`
	ip, account, success := extractMailLoginEvent(line)
	if ip != "1.2.3.4" || account != "alice@x.ro" || !success {
		t.Errorf("got (%q, %q, %v), want (1.2.3.4, alice@x.ro, true)", ip, account, success)
	}
}

func TestExtractMailLoginEvent_Garbage(t *testing.T) {
	for _, line := range []string{
		"",
		"totally unrelated log line",
		"Apr 14 12:00:00 dovecot: imap-login: STARTTLS", // no login event
	} {
		ip, account, success := extractMailLoginEvent(line)
		if ip != "" || account != "" || success {
			t.Errorf("line %q: got (%q, %q, %v), want empty", line, ip, account, success)
		}
	}
}

func TestIsMailAuthLine_Variants(t *testing.T) {
	for _, tc := range []struct {
		line string
		want bool
	}{
		{"dovecot: imap-login: Aborted login", true},
		{"dovecot: pop3-login: Login:", true},
		{"dovecot: managesieve-login: Aborted login", true},
		{"dovecot: lmtp: whatever", false},
		{"exim: some other line", false},
		{"", false},
	} {
		if got := isMailAuthLine(tc.line); got != tc.want {
			t.Errorf("isMailAuthLine(%q) = %v, want %v", tc.line, got, tc.want)
		}
	}
}
