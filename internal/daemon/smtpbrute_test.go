package daemon

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// staticClock returns a configurable fixed time.
type staticClock struct{ t time.Time }

func (c *staticClock) Now() time.Time          { return c.t }
func (c *staticClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTestTracker(t *testing.T, clock *staticClock) *smtpAuthTracker {
	t.Helper()
	return newSMTPAuthTracker(
		5,              // perIPThreshold
		8,              // subnetThreshold
		12,             // accountSprayThreshold
		10*time.Minute, // window
		60*time.Minute, // suppression
		20000,          // maxTracked
		clock.Now,
	)
}

func TestSMTPAuthTracker_InitialSizeIsZero(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestTracker(t, clock)
	if got := tr.Size(); got != 0 {
		t.Errorf("Size() = %d, want 0", got)
	}
}

func TestSMTPAuthTracker_NoFindingBelowPerIPThreshold(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestTracker(t, clock)
	for i := 0; i < 4; i++ {
		if got := tr.Record("203.0.113.5", ""); got != nil {
			t.Fatalf("record %d: got %v, want nil", i, got)
		}
	}
}

func TestSMTPAuthTracker_EmitsSMTPBruteForceAtThreshold(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestTracker(t, clock)
	var last []alert.Finding
	for i := 0; i < 5; i++ {
		last = tr.Record("203.0.113.5", "")
	}
	if len(last) == 0 {
		t.Fatalf("expected finding on 5th record, got nil")
	}
	var f *alert.Finding
	for i := range last {
		if last[i].Check == "smtp_bruteforce" {
			f = &last[i]
			break
		}
	}
	if f == nil {
		t.Fatalf("no smtp_bruteforce finding in %v", last)
	}
	if f.Severity != alert.Critical {
		t.Errorf("severity = %v, want Critical", f.Severity)
	}
	if !strings.Contains(f.Message, "203.0.113.5") {
		t.Errorf("message %q does not contain IP", f.Message)
	}
	// Round-trip check: message format must be compatible with
	// internal/checks.extractIPFromFinding, which splits on " from "
	// then TrimRight(",:;)([]") and net.ParseIP's the first field.
	// We replicate that logic here to pin the contract locally.
	if !strings.HasPrefix(f.Message, "SMTP brute force from ") {
		t.Errorf("message %q must begin with canonical prefix 'SMTP brute force from '", f.Message)
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

func TestSMTPAuthTracker_NoDuplicatePerIPFindingsInSuppressionWindow(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestTracker(t, clock)
	for i := 0; i < 5; i++ {
		tr.Record("203.0.113.5", "")
	}
	for i := 0; i < 10; i++ {
		clock.advance(1 * time.Second)
		out := tr.Record("203.0.113.5", "")
		for _, f := range out {
			if f.Check == "smtp_bruteforce" {
				t.Fatalf("duplicate smtp_bruteforce finding during suppression at iteration %d", i)
			}
		}
	}
}

func TestSMTPAuthTracker_SuppressionExpires_ReFires(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestTracker(t, clock)
	for i := 0; i < 5; i++ {
		tr.Record("203.0.113.5", "")
	}
	// Advance past suppression AND past window — counter must be fresh.
	clock.advance(61 * time.Minute)
	var fired bool
	for i := 0; i < 5; i++ {
		for _, f := range tr.Record("203.0.113.5", "") {
			if f.Check == "smtp_bruteforce" {
				fired = true
			}
		}
	}
	if !fired {
		t.Fatalf("expected re-fire after suppression window")
	}
}

func TestSMTPAuthTracker_WindowExpiryResetsCount(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestTracker(t, clock)
	for i := 0; i < 4; i++ {
		tr.Record("203.0.113.5", "")
	}
	// Window is 10 min; advance 11 min so prior 4 timestamps fall out.
	clock.advance(11 * time.Minute)
	for i := 0; i < 4; i++ {
		if out := tr.Record("203.0.113.5", ""); len(out) != 0 {
			t.Fatalf("unexpected finding after window reset: %v", out)
		}
	}
}

func TestSMTPAuthTracker_MultipleIPsIndependent(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestTracker(t, clock)
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

func TestSMTPAuthTracker_EmptyIPIgnored(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestTracker(t, clock)
	for i := 0; i < 20; i++ {
		if out := tr.Record("", ""); out != nil {
			t.Fatalf("empty IP must return nil, got %v", out)
		}
	}
	if tr.Size() != 0 {
		t.Errorf("Size() = %d, want 0 for empty-IP-only input", tr.Size())
	}
}

func TestSMTPAuthTracker_SubnetSprayThreshold(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestTracker(t, clock)
	var fired *alert.Finding
	// 8 unique IPs in 203.0.113.0/24, each doing 1 failure (below per-IP threshold).
	for i := 1; i <= 8; i++ {
		ip := fmt.Sprintf("203.0.113.%d", i)
		for _, f := range tr.Record(ip, "") {
			if f.Check == "smtp_subnet_spray" {
				cp := f
				fired = &cp
			}
		}
	}
	if fired == nil {
		t.Fatalf("expected smtp_subnet_spray finding after 8 unique IPs in /24")
	}
	if fired.Severity != alert.Critical {
		t.Errorf("severity = %v, want Critical", fired.Severity)
	}
	// Round-trip check: message format must be compatible with
	// internal/checks.extractCIDRFromFinding, which uses LastIndex(" from ")
	// then TrimRight(",:;)([]") and net.ParseCIDR.
	if !strings.HasPrefix(fired.Message, "SMTP password spray from ") {
		t.Errorf("message %q must begin with canonical prefix 'SMTP password spray from '", fired.Message)
	}
	idx := strings.LastIndex(fired.Message, " from ")
	if idx < 0 {
		t.Fatalf("message %q has no ' from ' separator", fired.Message)
	}
	rest := fired.Message[idx+len(" from "):]
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		t.Fatalf("message %q: nothing after ' from '", fired.Message)
	}
	candidate := strings.TrimRight(fields[0], ",:;)([]")
	_, ipnet, err := net.ParseCIDR(candidate)
	if err != nil {
		t.Errorf("round-trip CIDR extraction from %q failed on %q: %v", fired.Message, candidate, err)
	} else if ipnet.String() != "203.0.113.0/24" {
		t.Errorf("round-trip CIDR extraction yielded %q, want 203.0.113.0/24", ipnet.String())
	}
}

func TestSMTPAuthTracker_SubnetSpraySuppression(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestTracker(t, clock)
	for i := 1; i <= 8; i++ {
		tr.Record(fmt.Sprintf("203.0.113.%d", i), "")
	}
	// Adding more IPs inside the suppression window must not re-emit.
	for i := 9; i <= 20; i++ {
		out := tr.Record(fmt.Sprintf("203.0.113.%d", i), "")
		for _, f := range out {
			if f.Check == "smtp_subnet_spray" {
				t.Fatalf("duplicate smtp_subnet_spray finding in suppression window at i=%d", i)
			}
		}
	}
}

func TestSMTPAuthTracker_SubnetSprayIPv6Skipped(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestTracker(t, clock)
	for i := 0; i < 20; i++ {
		out := tr.Record(fmt.Sprintf("2001:db8::%x", i+1), "")
		for _, f := range out {
			if f.Check == "smtp_subnet_spray" {
				t.Fatalf("subnet spray finding unexpectedly emitted for IPv6 at i=%d", i)
			}
		}
	}
}

func TestSMTPAuthTracker_AccountSprayThreshold(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestTracker(t, clock)
	var fired *alert.Finding
	for i := 1; i <= 12; i++ {
		// Spread across different /24s so the subnet detector never fires.
		ip := fmt.Sprintf("203.0.%d.1", i)
		for _, f := range tr.Record(ip, "victim@example.com") {
			if f.Check == "smtp_account_spray" {
				cp := f
				fired = &cp
			}
		}
	}
	if fired == nil {
		t.Fatalf("expected smtp_account_spray finding after 12 unique IPs")
	}
	if fired.Severity != alert.High {
		t.Errorf("severity = %v, want High (visibility only)", fired.Severity)
	}
	if !strings.Contains(fired.Message, "victim@example.com") {
		t.Errorf("message %q missing account", fired.Message)
	}
}

func TestSMTPAuthTracker_AccountSpray_EmptyAccountIgnored(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestTracker(t, clock)
	for i := 1; i <= 20; i++ {
		ip := fmt.Sprintf("203.0.%d.1", i)
		out := tr.Record(ip, "")
		for _, f := range out {
			if f.Check == "smtp_account_spray" {
				t.Fatalf("account spray must not fire without account, got %v", f)
			}
		}
	}
}
