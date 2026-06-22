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

func TestMailAuthTracker_RecordSuccess_IgnoresExpiredSameAccountFailure(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	tr.Record("203.0.113.5", "alice@example.com")

	clock.advance(11 * time.Minute)
	for i := 0; i < 3; i++ {
		tr.Record("203.0.113.5", "bob@example.com")
	}

	out := tr.RecordSuccess("203.0.113.5", "alice@example.com")
	for _, f := range out {
		if f.Check == "mail_account_compromised" {
			t.Fatalf("expired alice failure must not combine with fresh bob failures, got %v", f)
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

func TestMailAuthTracker_NoBruteForceWhenSuccessDominant(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	// Busy legit NAT office: the same mailbox logs in successfully from another
	// device while one stale saved password keeps failing. Matched successes at
	// least matching failures means a real client, not a brute-forcer.
	for i := 0; i < 6; i++ {
		tr.RecordSuccess("203.0.113.5", "stale-device@example.com")
	}
	for i := 0; i < 5; i++ { // reaches perIPThreshold
		for _, f := range tr.Record("203.0.113.5", "stale-device@example.com") {
			if f.Check == "mail_bruteforce" {
				t.Fatalf("mail_bruteforce must not fire for success-dominant IP (iter %d)", i)
			}
		}
	}
}

func TestMailAuthTracker_BruteForceFiresWhenFailureDominant(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	// One stray success does not excuse a failure-dominant IP: an attacker that
	// guessed once after many failures is still a brute-forcer.
	tr.RecordSuccess("203.0.113.5", "alice@example.com")
	var fired bool
	for i := 0; i < 5; i++ {
		for _, f := range tr.Record("203.0.113.5", "alice@example.com") {
			if f.Check == "mail_bruteforce" {
				fired = true
			}
		}
	}
	if !fired {
		t.Fatalf("mail_bruteforce must still fire when failures dominate despite one success")
	}
}

func TestMailAuthTracker_BruteForceFiresWhenSuccessDominantHasAccountlessFailures(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 6, 20, 6, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	ip := "203.0.113.6"
	acct := "alice@example.com"
	for i := 0; i < 5; i++ {
		tr.RecordSuccess(ip, acct)
	}
	for i := 0; i < 4; i++ {
		tr.Record(ip, acct)
	}
	out := tr.Record(ip, "")
	var fired bool
	for _, f := range out {
		if f.Check == "mail_bruteforce" {
			fired = true
		}
	}
	if !fired {
		t.Fatalf("accountless failures must not be hidden by success-dominant named failures, got %v", out)
	}
}

func TestMailAuthTracker_BruteForceFiresWhenSuccessesAreUnrelated(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	for i := 0; i < 6; i++ {
		tr.RecordSuccess("203.0.113.5", "known@example.com")
	}
	var fired bool
	for i := 0; i < 5; i++ {
		for _, f := range tr.Record("203.0.113.5", "victim@example.com") {
			if f.Check == "mail_bruteforce" {
				fired = true
			}
		}
	}
	if !fired {
		t.Fatalf("unrelated successful mailbox must not hide brute-force failures")
	}
}

func TestMailAuthTracker_NoCompromiseWhenSuccessDominant(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	// Legit owner IP: logs in successfully all day, occasionally mistypes the
	// password. A success after a couple of mistypes from an IP that succeeds
	// far more than it fails is not a takeover.
	for i := 0; i < 5; i++ {
		tr.RecordSuccess("203.0.113.5", "alice@example.com")
	}
	for i := 0; i < 2; i++ {
		tr.Record("203.0.113.5", "alice@example.com")
	}
	out := tr.RecordSuccess("203.0.113.5", "alice@example.com")
	for _, f := range out {
		if f.Check == "mail_account_compromised" {
			t.Fatalf("mail_account_compromised must not fire for success-dominant legit IP, got %v", f)
		}
	}
}

func TestMailAuthTracker_CompromiseFiresWhenSuccessPaddingIsUnrelated(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	for i := 0; i < 6; i++ {
		tr.RecordSuccess("203.0.113.5", fmt.Sprintf("known%d@example.com", i))
	}
	for i := 0; i < 3; i++ {
		tr.Record("203.0.113.5", "victim@example.com")
	}
	out := tr.RecordSuccess("203.0.113.5", "victim@example.com")
	var fired bool
	for _, f := range out {
		if f.Check == "mail_account_compromised" {
			fired = true
		}
	}
	if !fired {
		t.Fatalf("unrelated successful mailbox must not hide account compromise, got %v", out)
	}
}

func TestMailAuthTracker_NoCompromiseAfterSingleTargetMistypeWithOtherFailures(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	tr.Record("203.0.113.5", "alice@example.com")
	for i := 0; i < 3; i++ {
		tr.Record("203.0.113.5", "bob@example.com")
	}
	out := tr.RecordSuccess("203.0.113.5", "alice@example.com")
	for _, f := range out {
		if f.Check == "mail_account_compromised" {
			t.Fatalf("one target-account failure must not combine with other accounts, got %v", f)
		}
	}
}

func TestMailAuthTracker_NoCompromiseAfterSingleMistype(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	tr.Record("203.0.113.5", "alice@example.com")
	out := tr.RecordSuccess("203.0.113.5", "alice@example.com")
	for _, f := range out {
		if f.Check == "mail_account_compromised" {
			t.Fatalf("one failed login followed by success must not flag compromise, got %v", f)
		}
	}
}

// establishGoodSource logs successful auths spread over time so (ip, account)
// becomes an established legitimate sender, then leaves the clock at a fresh
// point. Five successes land at +0,+20,+40,+60,+80 minutes; the clock ends at
// +100 minutes. goodFirst stays at +0, goodLast at +80.
func establishGoodSource(tr *mailAuthTracker, clock *staticClock, ip, account string) {
	for i := 0; i < 5; i++ {
		tr.RecordSuccess(ip, account)
		clock.advance(20 * time.Minute)
	}
}

func TestMailAuthTracker_NoCompromiseFromEstablishedGoodSource(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 6, 20, 6, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	ip := "203.0.113.7"
	acct := "comenzi@example.ro"
	// Customer's working POP3 profile authenticates successfully over hours.
	establishGoodSource(tr, clock, ip, acct)
	// A second device with a misconfigured profile (wrong/old password) sends a
	// burst of auth failures inside the 10m window.
	for i := 0; i < 6; i++ {
		tr.Record(ip, acct)
		clock.advance(30 * time.Second)
	}
	// The working profile authenticates successfully again. This is not a
	// takeover: the IP has owned the mailbox for hours.
	out := tr.RecordSuccess(ip, acct)
	for _, f := range out {
		if f.Check == "mail_account_compromised" {
			t.Fatalf("established good source must not flag compromise, got %v", f)
		}
	}
}

func TestMailAuthTracker_CompromiseFiresOnFirstSuccessBreakthrough(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 6, 20, 6, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	ip := "203.0.113.8"
	acct := "victim@example.ro"
	// Attacker IP with no prior successful history for the mailbox: failures
	// followed by the first-ever success is a genuine guessing breakthrough.
	for i := 0; i < 4; i++ {
		tr.Record(ip, acct)
		clock.advance(30 * time.Second)
	}
	out := tr.RecordSuccess(ip, acct)
	var fired bool
	for _, f := range out {
		if f.Check == "mail_account_compromised" {
			fired = true
		}
	}
	if !fired {
		t.Fatalf("first-success breakthrough from a novel IP must still flag compromise, got %v", out)
	}
}

func TestMailAuthTracker_CompromiseSuccessDoesNotEstablishGoodSource(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 6, 20, 6, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	ip := "203.0.113.9"
	acct := "victim@example.ro"
	for i := 0; i < 3; i++ {
		tr.Record(ip, acct)
		clock.advance(30 * time.Second)
	}
	out := tr.RecordSuccess(ip, acct)
	var compromised bool
	for _, f := range out {
		if f.Check == "mail_account_compromised" {
			compromised = true
		}
	}
	if !compromised {
		t.Fatalf("expected first breakthrough to flag compromise, got %v", out)
	}

	clock.advance(11 * time.Minute)
	var brute bool
	for i := 0; i < 5; i++ {
		for _, f := range tr.Record(ip, acct) {
			if f.Check == "mail_bruteforce" {
				brute = true
			}
		}
	}
	if !brute {
		t.Fatalf("a compromise success must not seed good-source suppression")
	}
}

func TestMailAuthTracker_CompromiseFiresWhenGoodSourceStale(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 6, 20, 6, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	ip := "203.0.113.10"
	acct := "dormant@example.ro"
	establishGoodSource(tr, clock, ip, acct)
	// More than the good-source TTL passes with no successful login. The old
	// standing must not whitelist a later guessing breakthrough.
	clock.advance(mailGoodSourceTTL + time.Hour)
	for i := 0; i < 3; i++ {
		tr.Record(ip, acct)
		clock.advance(30 * time.Second)
	}
	out := tr.RecordSuccess(ip, acct)
	var fired bool
	for _, f := range out {
		if f.Check == "mail_account_compromised" {
			fired = true
		}
	}
	if !fired {
		t.Fatalf("stale good standing must not suppress a fresh breakthrough, got %v", out)
	}
}

func TestMailAuthTracker_NoBruteForceFromEstablishedGoodSource(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 6, 20, 6, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	ip := "203.0.113.11"
	acct := "comenzi@example.ro"
	establishGoodSource(tr, clock, ip, acct)
	var fired, suspected bool
	for i := 0; i < 6; i++ {
		for _, f := range tr.Record(ip, acct) {
			switch f.Check {
			case "mail_bruteforce":
				fired = true
			case "mail_bruteforce_suspected":
				suspected = true
			}
		}
		clock.advance(30 * time.Second)
	}
	if fired {
		t.Fatalf("established good source must not trigger mail_bruteforce for its own mailbox")
	}
	if !suspected {
		t.Fatalf("established good source failure should surface mail_bruteforce_suspected")
	}
}

func TestMailAuthTracker_GoodSourceWindowBoundary(t *testing.T) {
	start := time.Date(2026, 6, 20, 6, 0, 0, 0, time.UTC)
	t.Run("before boundary fires", func(t *testing.T) {
		clock := &staticClock{t: start}
		tr := newTestMailTracker(t, clock)
		ip := "203.0.113.13"
		acct := "owner@example.ro"
		tr.RecordSuccess(ip, acct)
		clock.advance(10*time.Minute - time.Nanosecond)
		var fired bool
		for i := 0; i < 5; i++ {
			for _, f := range tr.Record(ip, acct) {
				if f.Check == "mail_bruteforce" {
					fired = true
				}
			}
		}
		if !fired {
			t.Fatalf("good source just before the window boundary must not suppress brute-force")
		}
	})
	t.Run("at boundary suppresses", func(t *testing.T) {
		clock := &staticClock{t: start}
		tr := newTestMailTracker(t, clock)
		ip := "203.0.113.14"
		acct := "owner@example.ro"
		tr.RecordSuccess(ip, acct)
		clock.advance(10 * time.Minute)
		var fired bool
		for i := 0; i < 5; i++ {
			for _, f := range tr.Record(ip, acct) {
				if f.Check == "mail_bruteforce" {
					fired = true
				}
			}
		}
		if fired {
			t.Fatalf("good source at the window boundary must suppress brute-force")
		}
	})
}

func TestMailAuthTracker_FreshGoodSourceDoesNotDowngradeSiblingFailure(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 6, 20, 6, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	ip := "203.0.113.16"

	tr.RecordSuccess(ip, "owner@example.ro")

	var block, suspected bool
	for i := 0; i < 5; i++ {
		for _, f := range tr.Record(ip, "manager@example.ro") {
			switch f.Check {
			case "mail_bruteforce":
				block = true
			case "mail_bruteforce_suspected":
				suspected = true
			}
		}
	}
	if !block {
		t.Fatalf("fresh same-window success must not downgrade sibling mailbox failures")
	}
	if suspected {
		t.Fatalf("fresh same-window success emitted mail_bruteforce_suspected")
	}
}

func TestMailAuthTracker_StaleGoodSourceDoesNotDowngradeSiblingFailure(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 6, 20, 6, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	ip := "203.0.113.19"
	establishGoodSource(tr, clock, ip, "owner@example.ro")
	clock.advance(mailGoodSourceTTL + time.Second)

	var block, suspected bool
	for i := 0; i < 5; i++ {
		for _, f := range tr.Record(ip, "manager@example.ro") {
			switch f.Check {
			case "mail_bruteforce":
				block = true
			case "mail_bruteforce_suspected":
				suspected = true
			}
		}
	}
	if !block {
		t.Fatalf("stale good-source history must not downgrade sibling mailbox failures")
	}
	if suspected {
		t.Fatalf("stale good-source history emitted mail_bruteforce_suspected")
	}
}

func TestMailAuthTracker_BruteForceFiresWhenEstablishedGoodSourceHasAccountlessFailures(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 6, 20, 6, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	ip := "203.0.113.15"
	acct := "owner@example.ro"
	establishGoodSource(tr, clock, ip, acct)
	for i := 0; i < 4; i++ {
		tr.Record(ip, acct)
	}
	out := tr.Record(ip, "")
	var fired bool
	for _, f := range out {
		if f.Check == "mail_bruteforce" {
			fired = true
		}
	}
	if !fired {
		t.Fatalf("accountless failures must not be hidden by established good-source failures, got %v", out)
	}
}

func TestMailAuthTracker_GoodSourceCrackInProgressStillBlocks(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 6, 20, 6, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	ip := "203.0.113.12"
	establishGoodSource(tr, clock, ip, "owner@example.ro")
	// The IP slips in a single success on a second mailbox, then keeps failing it.
	// Established standing on owner@ must not downgrade a mailbox the IP is itself
	// succeeding-then-failing on: that is a crack in progress, so brute-force must
	// still auto-block rather than drop to the advisory.
	tr.RecordSuccess(ip, "victim@example.ro")
	var fired bool
	for i := 0; i < 6; i++ {
		for _, f := range tr.Record(ip, "victim@example.ro") {
			if f.Check == "mail_bruteforce" {
				fired = true
			}
		}
		clock.advance(30 * time.Second)
	}
	if !fired {
		t.Fatalf("a good source failing a mailbox it also non-dominantly succeeds on is a crack in progress and must still auto-block")
	}
}

func TestMailAuthTracker_GoodSourceFreshSuccessBeforeFailureBurstStillBlocks(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 6, 20, 6, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	ip := "203.0.113.17"
	establishGoodSource(tr, clock, ip, "owner@example.ro")

	tr.RecordSuccess(ip, "victim@example.ro")
	clock.advance(time.Second)

	var block, suspected bool
	for i := 0; i < 5; i++ {
		for _, f := range tr.Record(ip, "victim@example.ro") {
			switch f.Check {
			case "mail_bruteforce":
				block = true
			case "mail_bruteforce_suspected":
				suspected = true
			}
		}
		clock.advance(30 * time.Second)
	}
	if !block {
		t.Fatalf("fresh success on the failing mailbox before a failure-dominant burst must still auto-block")
	}
	if suspected {
		t.Fatalf("fresh success on the failing mailbox emitted mail_bruteforce_suspected")
	}
}

func TestMailAuthTracker_EstablishedGoodCurrentSuccessFailureDominantStillBlocks(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 6, 20, 6, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	ip := "203.0.113.18"
	acct := "owner@example.ro"
	establishGoodSource(tr, clock, ip, acct)

	tr.RecordSuccess(ip, acct)
	clock.advance(time.Second)

	var block, suspected bool
	for i := 0; i < 5; i++ {
		for _, f := range tr.Record(ip, acct) {
			switch f.Check {
			case "mail_bruteforce":
				block = true
			case "mail_bruteforce_suspected":
				suspected = true
			}
		}
		clock.advance(30 * time.Second)
	}
	if !block {
		t.Fatalf("current non-dominant success on an established failing mailbox must still auto-block")
	}
	if suspected {
		t.Fatalf("current non-dominant success on an established failing mailbox emitted mail_bruteforce_suspected")
	}
}

// A real office/household IP that authenticates a working mailbox for hours, then
// has a second profile with a stale password fail against a confined set of its
// own mailboxes, is a misconfiguration, not a brute-force. It surfaces as
// mail_bruteforce_suspected (visibility) but must not 24h-block the customer.
func TestMailAuthTracker_EstablishedGoodSourceConfinedSiblingFailureAlertsOnly(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 6, 20, 6, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	ip := "198.51.100.20"
	establishGoodSource(tr, clock, ip, "olesia@example.ro")
	var block, suspected bool
	for i := 0; i < 6; i++ {
		for _, f := range tr.Record(ip, "manager@example.ro") {
			switch f.Check {
			case "mail_bruteforce":
				block = true
			case "mail_bruteforce_suspected":
				suspected = true
			}
		}
		clock.advance(30 * time.Second)
	}
	if block {
		t.Fatalf("established good source failing one confined sibling mailbox must not auto-block")
	}
	if !suspected {
		t.Fatalf("a confined failure from an established good source should surface mail_bruteforce_suspected")
	}
}

func TestMailAuthTracker_SuspectedSuppressionDoesNotBlockEscalation(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 6, 20, 6, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	ip := "198.51.100.22"
	establishGoodSource(tr, clock, ip, "owner@example.ro")

	var suspected bool
	for i := 0; i < 5; i++ {
		for _, f := range tr.Record(ip, "manager@example.ro") {
			if f.Check == "mail_bruteforce_suspected" {
				suspected = true
			}
		}
		clock.advance(30 * time.Second)
	}
	if !suspected {
		t.Fatalf("confined failure did not emit mail_bruteforce_suspected")
	}

	// Escalating to a second distinct mailbox exceeds the single-mailbox good
	// footprint; the suspected-advisory suppression clock must not stop that from
	// reaching the block path.
	var block bool
	for _, f := range tr.Record(ip, "sales@example.ro") {
		if f.Check == "mail_bruteforce" {
			block = true
		}
	}
	if !block {
		t.Fatalf("suspected advisory suppression must not block escalation to mail_bruteforce")
	}
}

// The downgrade is bounded: an established good source that sprays more distinct
// mailboxes than the confined limit is a foothold spraying, not a stale profile,
// and must still auto-block.
func TestMailAuthTracker_EstablishedGoodSourceSprayingManyMailboxesStillBlocks(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 6, 20, 6, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	ip := "198.51.100.21"
	establishGoodSource(tr, clock, ip, "owner@example.ro")
	var block bool
	for _, acct := range []string{"a@example.ro", "b@example.ro", "c@example.ro", "a@example.ro", "b@example.ro"} {
		for _, f := range tr.Record(ip, acct) {
			if f.Check == "mail_bruteforce" {
				block = true
			}
		}
		clock.advance(30 * time.Second)
	}
	if !block {
		t.Fatalf("an established good source spraying more than the confined mailbox limit must still auto-block")
	}
}

// A multi-tenant office/agency IP runs working profiles for several client
// mailboxes; a stale saved password then fails a set of those mailboxes no
// larger than its established good footprint. That is a misconfiguration, not a
// brute-force, even though it touches more than a couple of mailboxes, so it
// must surface as an advisory rather than locking the whole office out.
func TestMailAuthTracker_EstablishedMultiTenantConfinedFailuresAdvisory(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 6, 20, 6, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	ip := "198.51.100.40"
	mboxes := []string{"a@t1.ro", "b@t1.ro", "c@t2.ro", "d@t2.ro", "e@t3.ro"}
	for _, m := range mboxes {
		establishGoodSource(tr, clock, ip, m)
	}
	var block, suspected bool
	for _, m := range mboxes {
		for _, f := range tr.Record(ip, m) {
			switch f.Check {
			case "mail_bruteforce":
				block = true
			case "mail_bruteforce_suspected":
				suspected = true
			}
		}
		clock.advance(20 * time.Second)
	}
	if block {
		t.Fatalf("an established multi-mailbox source failing within its own good footprint must not auto-block")
	}
	if !suspected {
		t.Fatalf("confined failures across an established footprint should surface mail_bruteforce_suspected")
	}
}

// The footprint bound is real: a source established-good for a single mailbox
// must not get to fail more distinct mailboxes than that. One foothold buys at
// most one confined miss before the block path re-engages.
func TestMailAuthTracker_SingleFootprintCannotExceedItsGoodCount(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 6, 20, 6, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	ip := "198.51.100.41"
	establishGoodSource(tr, clock, ip, "owner@example.ro")
	for i := 0; i < 5; i++ {
		tr.Record(ip, "first@example.ro")
		clock.advance(20 * time.Second)
	}
	var block bool
	for _, f := range tr.Record(ip, "second@example.ro") {
		if f.Check == "mail_bruteforce" {
			block = true
		}
	}
	if !block {
		t.Fatalf("failing more distinct mailboxes than the established good footprint must auto-block")
	}
}

func TestMailAuthTracker_RecordSuccessRespectsMaxTracked(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	const maxTracked = 10
	tr := newMailAuthTracker(5, 8, 12, 10*time.Minute, 60*time.Minute, maxTracked, clock.Now)
	// Per-IP success tracking must stay bounded: a busy server sees far more
	// distinct successful-login IPs than failing ones, so successes cannot be
	// allowed to grow the tracker without limit.
	for i := 0; i < 200; i++ {
		tr.RecordSuccess(fmt.Sprintf("203.0.113.%d", i%256), fmt.Sprintf("u%d@example.com", i))
	}
	if got := tr.Size(); got > maxTracked {
		t.Errorf("Size() = %d, want <= %d", got, maxTracked)
	}
}

func TestMailAuthTracker_PurgeKeepsGoodSourceUntilTTL(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 6, 20, 6, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	tr.RecordSuccess("203.0.113.16", "owner@example.ro")

	clock.advance(71 * time.Minute)
	tr.Purge()
	if got := tr.Size(); got == 0 {
		t.Fatalf("good source was purged before TTL")
	}

	clock.advance(mailGoodSourceTTL)
	tr.Purge()
	if got := tr.Size(); got != 0 {
		t.Fatalf("Size() after good-source TTL = %d, want 0", got)
	}
}

func TestMailAuthTracker_BackendDegradedSuppressesBruteForce(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	// Auth backend is down (e.g. cPanel's dovecot auth daemon refusing
	// connections): every login fails regardless of credentials, so a per-IP
	// failure flood is not attacker evidence and must not auto-block.
	for i := 0; i < mailBackendDegradedThreshold; i++ {
		tr.RecordBackendFailure()
	}
	for i := 0; i < 8; i++ {
		for _, f := range tr.Record("203.0.113.5", "alice@example.com") {
			if f.Check == "mail_bruteforce" {
				t.Fatalf("mail_bruteforce must be suppressed while auth backend degraded (iter %d)", i)
			}
		}
	}
}

func TestMailAuthTracker_BruteForceFiresWhenBackendErrorsBelowThreshold(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	for i := 0; i < mailBackendDegradedThreshold-1; i++ {
		tr.RecordBackendFailure()
	}
	var fired bool
	for i := 0; i < 5; i++ {
		for _, f := range tr.Record("203.0.113.5", "") {
			if f.Check == "mail_bruteforce" {
				fired = true
			}
		}
	}
	if !fired {
		t.Fatalf("mail_bruteforce must fire when backend errors stay below the degraded threshold")
	}
}

func TestMailAuthTracker_BackendDegradedRecoversAfterWindow(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	for i := 0; i < mailBackendDegradedThreshold; i++ {
		tr.RecordBackendFailure()
	}
	clock.advance(11 * time.Minute) // backend errors age out of the window
	var fired bool
	for i := 0; i < 5; i++ {
		for _, f := range tr.Record("203.0.113.5", "") {
			if f.Check == "mail_bruteforce" {
				fired = true
			}
		}
	}
	if !fired {
		t.Fatalf("mail_bruteforce must resume once backend errors age out of the window")
	}
}

func TestMailAuthTracker_BackendDegradedSuppressesSubnetSpray(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	for i := 0; i < mailBackendDegradedThreshold; i++ {
		tr.RecordBackendFailure()
	}
	for i := 1; i <= 8; i++ {
		for _, f := range tr.Record(fmt.Sprintf("203.0.113.%d", i), "") {
			if f.Check == "mail_subnet_spray" {
				t.Fatalf("mail_subnet_spray must be suppressed while auth backend degraded")
			}
		}
	}
}

func TestMailAuthTracker_BackendDegradedEmitsWarningOnce(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	var warns int
	for i := 0; i < mailBackendDegradedThreshold+5; i++ {
		for _, f := range tr.RecordBackendFailure() {
			if f.Check == "mail_auth_backend_degraded" {
				if f.Severity != alert.Warning {
					t.Errorf("backend-degraded severity = %v, want Warning", f.Severity)
				}
				warns++
			}
		}
	}
	if warns != 1 {
		t.Fatalf("expected exactly one backend-degraded warning per suppression window, got %d", warns)
	}
}

func TestMailAuthTracker_BackendFailureStateBounded(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	for i := 0; i < mailBackendDegradedThreshold*100; i++ {
		tr.RecordBackendFailure()
	}
	tr.mu.Lock()
	got := len(tr.backendErr)
	tr.mu.Unlock()
	if got != mailBackendDegradedThreshold {
		t.Fatalf("backend failure timestamps = %d, want bounded at %d", got, mailBackendDegradedThreshold)
	}
}

func TestMailAuthTracker_PurgeRemovesExpiredBackendFailures(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	for i := 0; i < mailBackendDegradedThreshold; i++ {
		tr.RecordBackendFailure()
	}
	clock.advance(11 * time.Minute)
	tr.Purge()
	tr.mu.Lock()
	got := len(tr.backendErr)
	tr.mu.Unlock()
	if got != 0 {
		t.Fatalf("backend failure timestamps after purge = %d, want 0", got)
	}
}

func TestMailAuthTracker_BackendDownCheckSuppressesBruteForce(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	// Active probe reports the backend down (no log-derived errors needed).
	tr.SetBackendDownCheck(func() bool { return true })
	for i := 0; i < 8; i++ {
		for _, f := range tr.Record("203.0.113.5", "alice@example.com") {
			if f.Check == "mail_bruteforce" {
				t.Fatalf("mail_bruteforce must be suppressed when probe reports backend down")
			}
		}
	}
}

func TestMailAuthTracker_BackendDownCheckFalseStillFires(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	tr.SetBackendDownCheck(func() bool { return false })
	var fired bool
	for i := 0; i < 5; i++ {
		for _, f := range tr.Record("203.0.113.5", "") {
			if f.Check == "mail_bruteforce" {
				fired = true
			}
		}
	}
	if !fired {
		t.Fatalf("mail_bruteforce must fire when probe reports backend healthy")
	}
}

func TestIsMailAuthBackendError(t *testing.T) {
	down := `Jun 19 02:00:00 host dovecot[123]: auth-worker(office@x.ro,203.0.113.4)<1><a>: conn unix:...: ` +
		`socket error: Failed to connect to /usr/local/cpanel/var/cpdoveauthd.sock: connection refused`
	if !isMailAuthBackendError(down) {
		t.Error("cpdoveauthd connection-refused must be classified a backend error")
	}
	credFail := `Jun 19 02:00:00 host dovecot[123]: imap-login: Login aborted: Logged out ` +
		`(auth failed, 3 attempts in 5 secs): user=<a@x.ro>, method=PLAIN, rip=203.0.113.4`
	if isMailAuthBackendError(credFail) {
		t.Error("an ordinary credential auth failure must NOT be a backend error")
	}
	success := `Jun 19 02:00:00 host dovecot[123]: imap-login: Logged in: user=<a@x.ro>, method=PLAIN, rip=203.0.113.4`
	if isMailAuthBackendError(success) {
		t.Error("a successful login must not be a backend error")
	}
	spoofedFailure := `Jun 19 02:00:00 host dovecot[123]: imap-login: Login aborted: Logged out ` +
		`(auth failed, 1 attempts in 1 secs): user=<Failed to connect to cpdoveauthd.sock Temporary authentication failure>, method=PLAIN, rip=203.0.113.4`
	if isMailAuthBackendError(spoofedFailure) {
		t.Error("user-controlled login text must not be classified as a backend error")
	}
	postfixSpoof := `Jun 19 02:00:00 host postfix/smtpd[222]: warning: ` +
		`dovecot: auth-worker: Temporary authentication failure`
	if isMailAuthBackendError(postfixSpoof) {
		t.Error("non-dovecot service messages must not be classified as backend errors")
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

func TestMailAuthTracker_MaxTrackedKeepsActiveFailureAheadOfIdleGoodSources(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 6, 20, 6, 0, 0, 0, time.UTC)}
	const maxTracked = 10
	tr := newMailAuthTracker(5, 50, 50, 10*time.Minute, 60*time.Minute, maxTracked, clock.Now)
	for i := 0; i < maxTracked; i++ {
		tr.RecordSuccess(fmt.Sprintf("203.0.113.%d", i+1), fmt.Sprintf("u%d@example.ro", i))
		clock.advance(time.Millisecond)
	}

	var fired bool
	for i := 0; i < 5; i++ {
		clock.advance(time.Millisecond)
		for _, f := range tr.Record("198.51.100.44", "victim@example.ro") {
			if f.Check == "mail_bruteforce" {
				fired = true
			}
		}
	}
	if !fired {
		t.Fatalf("active failure tracking was evicted behind idle good sources")
	}
	if got := tr.Size(); got > maxTracked {
		t.Fatalf("Size() = %d, want <= %d", got, maxTracked)
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

func TestMailAuthTracker_StatsCountCallsAndEmits(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 6, 7, 5, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)

	for i := 0; i < 6; i++ {
		tr.Record("203.0.113.9", "victim@example.test")
		clock.t = clock.t.Add(time.Second)
	}

	calls, emits := tr.Stats()
	if calls != 6 {
		t.Errorf("record calls = %d, want 6", calls)
	}
	if emits != 1 {
		t.Errorf("findings emitted = %d, want 1", emits)
	}
}

func TestMailAuthTracker_StatsCountCompromiseEmits(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 6, 7, 5, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)

	for i := 0; i < 3; i++ {
		tr.Record("203.0.113.9", "victim@example.test")
		clock.t = clock.t.Add(time.Second)
	}

	out := tr.RecordSuccess("203.0.113.9", "victim@example.test")
	var fired bool
	for _, f := range out {
		if f.Check == "mail_account_compromised" {
			fired = true
		}
	}
	if !fired {
		t.Fatalf("expected mail_account_compromised finding, got %v", out)
	}
	calls, emits := tr.Stats()
	if calls != 3 {
		t.Errorf("record calls = %d, want 3", calls)
	}
	if emits != 1 {
		t.Errorf("findings emitted = %d, want 1", emits)
	}
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
	line := `Apr 14 12:00:05 host dovecot: imap-login: Logged in: user=<alice@x.ro>, method=PLAIN, rip=1.2.3.4, lip=..., TLS`
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

// TestExtractMailLoginEvent_RealDovecotFormat pins the parser against
// dovecot's actual wire format as observed on production cPanel hosts.
// IPs are RFC 5737 documentation ranges (203.0.113.0/24 = TEST-NET-3) and
// usernames are RFC 2606 example.com — no real customer data is embedded.
//
// If dovecot ever changes the success/failure markers, these fixtures
// catch the regression at the parser layer rather than waiting for
// production to silently stop emitting findings.
func TestExtractMailLoginEvent_RealDovecotFormat(t *testing.T) {
	cases := []struct {
		name        string
		line        string
		wantIP      string
		wantAccount string
		wantSuccess bool
	}{
		{
			name:        "imap success — typical TLS login from external IP",
			line:        `Apr 14 12:00:05 testhost dovecot[100]: imap-login: Logged in: user=<alice@example.com>, method=PLAIN, rip=203.0.113.5, lip=192.0.2.1, mpid=12345, TLS, session=<abc>`,
			wantIP:      "203.0.113.5",
			wantAccount: "alice@example.com",
			wantSuccess: true,
		},
		{
			name:        "pop3 success — typical TLS login from external IP",
			line:        `Apr 14 12:00:06 testhost dovecot[100]: pop3-login: Logged in: user=<bob@example.com>, method=PLAIN, rip=203.0.113.6, lip=192.0.2.1, mpid=12346, TLS, session=<def>`,
			wantIP:      "203.0.113.6",
			wantAccount: "bob@example.com",
			wantSuccess: true,
		},
		{
			name:        "managesieve success from loopback (typical local proxy)",
			line:        `Apr 14 12:00:07 testhost dovecot[100]: managesieve-login: Logged in: user=<carol@example.com>, method=PLAIN, rip=::1, lip=::1, mpid=12347, secured, session=<ghi>`,
			wantIP:      "::1",
			wantAccount: "carol@example.com",
			wantSuccess: true,
		},
		{
			name:        "imap failure — Login aborted: Logged out (auth failed)",
			line:        `Apr 14 12:00:08 testhost dovecot[100]: imap-login: Login aborted: Logged out (auth failed, 1 attempts in 3 secs) (auth_failed): user=<dave@example.com>, method=PLAIN, rip=203.0.113.7, lip=192.0.2.1, TLS, session=<jkl>`,
			wantIP:      "203.0.113.7",
			wantAccount: "dave@example.com",
			wantSuccess: false,
		},
		{
			name:        "pop3 failure — Login aborted: Connection closed (auth failed)",
			line:        `Apr 14 12:00:09 testhost dovecot[100]: pop3-login: Login aborted: Connection closed (auth failed, 1 attempts in 2 secs) (auth_failed): user=<eve@example.com>, method=PLAIN, rip=203.0.113.8, lip=192.0.2.1, session=<mno>`,
			wantIP:      "203.0.113.8",
			wantAccount: "eve@example.com",
			wantSuccess: false,
		},
		{
			name:        "imap failure — extra noise from Connection reset by peer in middle of message",
			line:        `Apr 14 12:00:10 testhost dovecot[100]: imap-login: Login aborted: Connection closed: read(size=372) failed: Connection reset by peer (auth failed, 1 attempts in 0 secs) (auth_failed): user=<frank@example.com>, method=PLAIN, rip=203.0.113.9, lip=192.0.2.1, TLS, session=<pqr>`,
			wantIP:      "203.0.113.9",
			wantAccount: "frank@example.com",
			wantSuccess: false,
		},
		{
			name:        "non-auth Login aborted — no auth attempts (must NOT match as failure)",
			line:        `Apr 14 12:00:11 testhost dovecot[100]: imap-login: Login aborted: Connection closed (no auth attempts in 0 secs) (no_auth_attempts): user=<>, rip=203.0.113.10, lip=192.0.2.1, session=<stu>`,
			wantIP:      "",
			wantAccount: "",
			wantSuccess: false,
		},
		{
			name:        "non-auth Login aborted — TLS handshake failure (must NOT match as failure)",
			line:        `Apr 14 12:00:12 testhost dovecot[100]: pop3-login: Login aborted: Connection closed: SSL_accept() failed: error:14209102 (disconnected during TLS handshake) (tls_handshake_not_finished): user=<>, rip=203.0.113.11, lip=192.0.2.1, TLS handshaking, session=<vwx>`,
			wantIP:      "",
			wantAccount: "",
			wantSuccess: false,
		},
		{
			name:        "non-auth Login aborted — no_auth_attempts with idle timeout (must NOT match)",
			line:        `Apr 14 12:00:13 testhost dovecot[100]: pop3-login: Login aborted: Connection closed (no auth attempts in 19 secs) (no_auth_attempts): user=<>, rip=203.0.113.12, lip=192.0.2.1, TLS, session=<yz>`,
			wantIP:      "",
			wantAccount: "",
			wantSuccess: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ip, account, success := extractMailLoginEvent(tc.line)
			if ip != tc.wantIP || account != tc.wantAccount || success != tc.wantSuccess {
				t.Errorf("got (%q, %q, %v), want (%q, %q, %v)",
					ip, account, success, tc.wantIP, tc.wantAccount, tc.wantSuccess)
			}
		})
	}
}

func TestIsMailAuthLine_Variants(t *testing.T) {
	for _, tc := range []struct {
		line string
		want bool
	}{
		{"dovecot: imap-login: Aborted login", true},
		{"dovecot[123]: imap-login: Aborted login", true},
		{"dovecot: pop3-login: Login:", true},
		{"dovecot[123]: pop3-login: Login:", true},
		{"dovecot: managesieve-login: Aborted login", true},
		{"dovecot[123]: managesieve-login: Aborted login", true},
		{"dovecot: lmtp: whatever", false},
		{"postfix/smtpd[222]: warning: dovecot: imap-login: Aborted login", false},
		{"mydovecot: imap-login: Aborted login", false},
		{"exim: some other line", false},
		{"", false},
	} {
		if got := isMailAuthLine(tc.line); got != tc.want {
			t.Errorf("isMailAuthLine(%q) = %v, want %v", tc.line, got, tc.want)
		}
	}
}
