package daemon

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func testSprayConfig() sprayConfig {
	return sprayConfig{
		Mode:             sprayEnforce,
		Window:           7 * 24 * time.Hour,
		BreadthMailboxes: 2,
		MissingNetworks:  3,
		TrustAge:         10 * time.Minute,
		Suppression:      60 * time.Minute,
		MaxIPs:           1000,
	}
}

func newTestSpray(cfg sprayConfig) (*mailSpray, *staticClock) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	return newMailSpray(cfg, clock.Now), clock
}

// ageTrust gives ip aged trust on each mailbox: a clean login, then TrustAge.
func ageTrust(t *testing.T, m *mailSpray, clock *staticClock, ip string, mailboxes ...string) {
	t.Helper()
	for _, mb := range mailboxes {
		if clean, v := m.Success(ip, mb); !clean || v != nil {
			t.Fatalf("setup login %s on %s = (%v, %+v), want clean", ip, mb, clean, v)
		}
	}
	clock.advance(11 * time.Minute)
	if !m.TrustedAll(ip, mailboxes) {
		t.Fatalf("setup: %s holds no aged trust on %v", ip, mailboxes)
	}
}

// corroborate makes missing tried from two networks other than the caller's.
func corroborate(t *testing.T, m *mailSpray, missing string) {
	t.Helper()
	for _, ip := range []string{"198.51.100.1", "203.0.113.1"} {
		if v := m.Failure(ip, missing, mailboxMissing); v != nil {
			t.Fatalf("setup failure from %s = %+v, want nil", ip, v)
		}
	}
}

func wantRule(t *testing.T, v *sprayVerdict, rule sprayRule, block bool) {
	t.Helper()
	if v == nil {
		t.Fatalf("verdict = nil, want %s", rule)
	}
	if v.Rule != rule || v.Block != block {
		t.Fatalf("verdict = %s block=%v, want %s block=%v", v.Rule, v.Block, rule, block)
	}
}

func wantNoVerdict(t *testing.T, v *sprayVerdict) {
	t.Helper()
	if v != nil {
		t.Fatalf("verdict = %+v, want nil", v)
	}
}

func TestMailSpray_MissingMailboxNeedsCorroboration(t *testing.T) {
	m, _ := newTestSpray(testSprayConfig())
	const missing = "nobody@example.com"
	wantNoVerdict(t, m.Failure("198.51.100.1", missing, mailboxMissing))
	wantNoVerdict(t, m.Failure("203.0.113.1", missing, mailboxMissing))
	v := m.Failure("192.0.2.1", missing, mailboxMissing)
	wantRule(t, v, sprayRuleMissingMailbox, true)
	if v.Networks != 3 || v.Mailbox != missing {
		t.Fatalf("verdict networks=%d mailbox=%q, want 3 %q", v.Networks, v.Mailbox, missing)
	}
}

// 4e: an IP with trust gets one guess at a missing name, never two.
func TestMailSpray_MissingMailboxSkippedForTrustedIP(t *testing.T) {
	m, clock := newTestSpray(testSprayConfig())
	const ip = "192.0.2.10"
	ageTrust(t, m, clock, ip, "a@example.com")
	corroborate(t, m, "nobody@example.com")
	wantNoVerdict(t, m.Failure(ip, "nobody@example.com", mailboxMissing))
	wantRule(t, m.Failure(ip, "b@example.com", mailboxExistenceUnknown), sprayRuleBreadth, true)
}

func TestMailSpray_BreadthTwoUntrustedMailboxes(t *testing.T) {
	m, clock := newTestSpray(testSprayConfig())
	wantNoVerdict(t, m.Failure("192.0.2.1", "a@example.com", mailboxExists))
	v := m.Failure("192.0.2.1", "b@example.com", mailboxExists)
	wantRule(t, v, sprayRuleBreadth, true)
	if len(v.Targets) != 2 || v.Targets[0] != "a@example.com" || v.Targets[1] != "b@example.com" || v.Extra != 0 {
		t.Fatalf("targets = %v extra %d, want [a b] 0", v.Targets, v.Extra)
	}

	// Failures on a mailbox the IP holds aged trust for do not count.
	const trusted = "192.0.2.2"
	ageTrust(t, m, clock, trusted, "a@example.com")
	wantNoVerdict(t, m.Failure(trusted, "a@example.com", mailboxExists))
	wantNoVerdict(t, m.Failure(trusted, "a@example.com", mailboxExists))
	wantNoVerdict(t, m.Failure(trusted, "b@example.com", mailboxExists))
	wantRule(t, m.Failure(trusted, "c@example.com", mailboxExists), sprayRuleBreadth, true)
}

func TestMailSpray_BreadthWindow(t *testing.T) {
	for gap, fire := range map[time.Duration]bool{3 * 24 * time.Hour: true, 8 * 24 * time.Hour: false} {
		m, clock := newTestSpray(testSprayConfig())
		wantNoVerdict(t, m.Failure("192.0.2.1", "a@example.com", mailboxExists))
		clock.advance(gap)
		v := m.Failure("192.0.2.1", "b@example.com", mailboxExists)
		if fire {
			wantRule(t, v, sprayRuleBreadth, true)
		} else {
			wantNoVerdict(t, v)
		}
	}
}

// The operator's concern: a sprayer that guesses a password earns no trust.
func TestMailSpray_SuccessAfterSprayEarnsNoTrust(t *testing.T) {
	m, clock := newTestSpray(testSprayConfig())
	const ip = "192.0.2.1"
	wantNoVerdict(t, m.Failure(ip, "b@example.com", mailboxExists))
	clean, v := m.Success(ip, "a@example.com")
	if clean {
		t.Fatal("success after a failure on another mailbox reported clean")
	}
	wantRule(t, v, sprayRuleWeakCompromise, false)
	if v.Mailbox != "a@example.com" {
		t.Fatalf("verdict mailbox = %q, want a@example.com", v.Mailbox)
	}
	clock.advance(11 * time.Minute)
	if m.TrustedAll(ip, []string{"a@example.com"}) {
		t.Fatal("success after spray earned trust")
	}
	wantRule(t, m.Failure(ip, "c@example.com", mailboxExists), sprayRuleBreadth, true)
}

// 4b: trust only counts once it has aged past TrustAge.
func TestMailSpray_TrustAgesBeforeCounting(t *testing.T) {
	m, clock := newTestSpray(testSprayConfig())
	for _, ip := range []string{"192.0.2.1", "192.0.2.2"} {
		if clean, v := m.Success(ip, "a@example.com"); !clean || v != nil {
			t.Fatalf("clean login from %s = (%v, %+v)", ip, clean, v)
		}
	}
	clock.advance(time.Minute)
	wantNoVerdict(t, m.Failure("192.0.2.1", "a@example.com", mailboxExists))
	wantRule(t, m.Failure("192.0.2.1", "b@example.com", mailboxExists), sprayRuleBreadth, true)

	clock.advance(10 * time.Minute)
	wantNoVerdict(t, m.Failure("192.0.2.2", "a@example.com", mailboxExists))
	wantNoVerdict(t, m.Failure("192.0.2.2", "b@example.com", mailboxExists))
}

func TestMailSpray_LoginToTrustedMailboxNeverCompromise(t *testing.T) {
	m, clock := newTestSpray(testSprayConfig())
	const ip = "192.0.2.1"
	ageTrust(t, m, clock, ip, "a@example.com")
	wantNoVerdict(t, m.Failure(ip, "b@example.com", mailboxExists))
	if clean, v := m.Success(ip, "a@example.com"); !clean || v != nil {
		t.Fatalf("login to trusted mailbox = (%v, %+v), want (true, nil)", clean, v)
	}
}

func TestMailSpray_StrongCompromiseAfterCorroboratedMissingName(t *testing.T) {
	m, clock := newTestSpray(testSprayConfig())
	const ip = "192.0.2.1"
	ageTrust(t, m, clock, ip, "a@example.com")
	corroborate(t, m, "nobody@example.com")
	wantNoVerdict(t, m.Failure(ip, "nobody@example.com", mailboxMissing))
	clean, v := m.Success(ip, "c@example.com")
	if clean {
		t.Fatal("login after a corroborated missing name reported clean")
	}
	wantRule(t, v, sprayRuleCompromise, true)
	if v.Mailbox != "c@example.com" {
		t.Fatalf("verdict mailbox = %q, want c@example.com", v.Mailbox)
	}
}

// Unknown carries no information across separate failures: a later missing
// answer on the same name sticks, while one exists answer outweighs all.
func TestMailSpray_MissingOverUnknownInMemory(t *testing.T) {
	m, clock := newTestSpray(testSprayConfig())
	const ip = "192.0.2.1"
	ageTrust(t, m, clock, ip, "a@example.com")
	corroborate(t, m, "x@example.com")
	wantNoVerdict(t, m.Failure(ip, "x@example.com", mailboxExistenceUnknown))
	wantNoVerdict(t, m.Failure(ip, "x@example.com", mailboxMissing))
	_, v := m.Success(ip, "c@example.com")
	wantRule(t, v, sprayRuleCompromise, true)

	m.Failure("192.0.2.2", "y@example.com", mailboxExists)
	m.Failure("192.0.2.2", "y@example.com", mailboxMissing)
	m.mu.Lock()
	got := m.ips["192.0.2.2"].failed["y@example.com"].exist
	m.mu.Unlock()
	if got != mailboxExists {
		t.Fatalf("exists then missing folded to %v, want exists", got)
	}
}

func TestMailSpray_EstablishedMultiMailboxDowngradesCompromise(t *testing.T) {
	m, clock := newTestSpray(testSprayConfig())
	const ip = "192.0.2.1"
	ageTrust(t, m, clock, ip, "a@example.com", "b@example.com")
	corroborate(t, m, "nobody@example.com")
	wantNoVerdict(t, m.Failure(ip, "nobody@example.com", mailboxMissing))
	_, v := m.Success(ip, "c@example.com")
	wantRule(t, v, sprayRuleCompromise, false)
}

// 4d: a user fixing a stale password gets an advisory, and earns trust.
func TestMailSpray_SingleMailboxFailuresThenSuccess(t *testing.T) {
	m, clock := newTestSpray(testSprayConfig())
	const ip = "192.0.2.1"
	wantNoVerdict(t, m.Failure(ip, "a@example.com", mailboxExists))
	clock.advance(2 * 24 * time.Hour)
	wantNoVerdict(t, m.Failure(ip, "a@example.com", mailboxExists))
	clean, v := m.Success(ip, "a@example.com")
	if !clean {
		t.Fatal("success after single-mailbox failures not clean")
	}
	wantRule(t, v, sprayRuleSingleMailboxSuccess, false)
	if v.Mailbox != "a@example.com" {
		t.Fatalf("verdict mailbox = %q, want a@example.com", v.Mailbox)
	}
	// The next login while that trust ages is the same user: no repeat.
	clock.advance(time.Minute)
	if clean, v := m.Success(ip, "a@example.com"); !clean || v != nil {
		t.Fatalf("repeat login = (%v, %+v), want (true, nil)", clean, v)
	}
	clock.advance(11 * time.Minute)
	if !m.TrustedAll(ip, []string{"a@example.com"}) {
		t.Fatal("4d success recorded no trust")
	}
}

// 4d needs failures spread over days. A user who mistypes twice in a row
// and then logs in gets no advisory, and still earns trust.
func TestMailSpray_SingleMailboxQuickRetryNoAdvisory(t *testing.T) {
	for _, gap := range []time.Duration{time.Minute, sprayStaleSpread - time.Minute} {
		t.Run(gap.String(), func(t *testing.T) {
			m, clock := newTestSpray(testSprayConfig())
			const ip = "192.0.2.1"
			wantNoVerdict(t, m.Failure(ip, "a@example.com", mailboxExists))
			clock.advance(gap)
			wantNoVerdict(t, m.Failure(ip, "a@example.com", mailboxExists))
			if clean, v := m.Success(ip, "a@example.com"); !clean || v != nil {
				t.Fatalf("login after a quick retry = (%v, %+v), want (true, nil)", clean, v)
			}
			clock.advance(11 * time.Minute)
			if !m.TrustedAll(ip, []string{"a@example.com"}) {
				t.Fatal("clean login recorded no trust")
			}
		})
	}
}

func TestMailSpray_ModeOffRecordsTrustNoVerdicts(t *testing.T) {
	cfg := testSprayConfig()
	cfg.Mode = sprayOff
	m, clock := newTestSpray(cfg)
	if m.Mode() != sprayOff {
		t.Fatalf("Mode() = %v, want off", m.Mode())
	}
	wantNoVerdict(t, m.Failure("192.0.2.1", "a@example.com", mailboxExists))
	wantNoVerdict(t, m.Failure("192.0.2.1", "b@example.com", mailboxExists))
	if clean, v := m.Success("192.0.2.2", "a@example.com"); !clean || v != nil {
		t.Fatalf("clean login = (%v, %+v), want (true, nil)", clean, v)
	}
	clock.advance(11 * time.Minute)
	if !m.TrustedAll("192.0.2.2", []string{"a@example.com"}) {
		t.Fatal("mode off recorded no trust")
	}
}

// Suppression mutes repeats; evidence stays, so the IP is blocked again once
// suppression ends (the re-block on return).
func TestMailSpray_SuppressionThenReblock(t *testing.T) {
	m, clock := newTestSpray(testSprayConfig())
	const ip = "192.0.2.1"
	wantNoVerdict(t, m.Failure(ip, "a@example.com", mailboxExists))
	wantRule(t, m.Failure(ip, "b@example.com", mailboxExists), sprayRuleBreadth, true)
	clock.advance(30 * time.Minute)
	wantNoVerdict(t, m.Failure(ip, "c@example.com", mailboxExists))
	clock.advance(31 * time.Minute)
	wantRule(t, m.Failure(ip, "a@example.com", mailboxExists), sprayRuleBreadth, true)
}

func TestMailSpray_UniqueIPFloodBounded(t *testing.T) {
	cfg := testSprayConfig()
	cfg.MaxIPs = 100
	m, clock := newTestSpray(cfg)
	const trusted, fired = "192.0.2.1", "192.0.2.2"
	ageTrust(t, m, clock, trusted, "a@example.com")
	wantNoVerdict(t, m.Failure(fired, "a@example.com", mailboxExists))
	wantRule(t, m.Failure(fired, "b@example.com", mailboxExists), sprayRuleBreadth, true)

	// Every flood IP is newer than the fired one, so only rank can keep it.
	for i := range 10000 {
		clock.advance(time.Millisecond)
		m.Failure(fmt.Sprintf("2001:db8::%x", i+1), "a@example.com", mailboxExists)
		if m.Size() > 100 {
			t.Fatalf("Size() = %d after %d IPs, want <= 100", m.Size(), i+1)
		}
	}
	if !m.TrustedAll(trusted, []string{"a@example.com"}) {
		t.Fatal("flood evicted an IP holding trust")
	}
	clock.advance(61 * time.Minute)
	wantRule(t, m.Failure(fired, "c@example.com", mailboxExists), sprayRuleBreadth, true)
}

// One owned mailbox lets anyone log in cleanly from fresh IPs. That must not
// flush verdict evidence or other users' trust.
func TestMailSpray_OwnedMailboxLoginFloodKeepsEvidenceAndTrust(t *testing.T) {
	cfg := testSprayConfig()
	cfg.MaxIPs = 100
	m, clock := newTestSpray(cfg)
	const real, fired, oneShot = "192.0.2.1", "192.0.2.2", "192.0.2.3"
	ageTrust(t, m, clock, real, "a@example.com")
	wantNoVerdict(t, m.Failure(fired, "a@example.com", mailboxExists))
	wantRule(t, m.Failure(fired, "b@example.com", mailboxExists), sprayRuleBreadth, true)
	wantNoVerdict(t, m.Failure(oneShot, "a@example.com", mailboxExists))

	var flood []string
	for i := range 200 {
		clock.advance(time.Second)
		ip := fmt.Sprintf("2001:db8::%x", i+1)
		flood = append(flood, ip)
		if clean, v := m.Success(ip, "owned@example.com"); !clean || v != nil {
			t.Fatalf("flood login %d = (%v, %+v), want clean", i, clean, v)
		}
	}
	clock.advance(11 * time.Minute)
	owned := 0
	for _, ip := range flood {
		if m.TrustedAll(ip, []string{"owned@example.com"}) {
			owned++
		}
	}
	if owned > maxSprayTrustIPsPerMailbox {
		t.Fatalf("owned mailbox trusted from %d IPs, want <= %d", owned, maxSprayTrustIPsPerMailbox)
	}
	if !m.TrustedAll(real, []string{"a@example.com"}) {
		t.Fatal("login flood evicted a real user's trust")
	}
	// Logins add nothing to the evidence pool, so even one-shot evidence stays.
	wantRule(t, m.Failure(oneShot, "b@example.com", mailboxExists), sprayRuleBreadth, true)
	clock.advance(50 * time.Minute)
	wantRule(t, m.Failure(fired, "c@example.com", mailboxExists), sprayRuleBreadth, true)
}

// A failure flood evicts evidence only. An IP whose own evidence is evicted
// keeps its trust.
func TestMailSpray_FailureFloodKeepsTrust(t *testing.T) {
	cfg := testSprayConfig()
	cfg.MaxIPs = 100
	m, clock := newTestSpray(cfg)
	const real = "192.0.2.1"
	ageTrust(t, m, clock, real, "a@example.com")
	wantNoVerdict(t, m.Failure(real, "a@example.com", mailboxExists))
	for i := range 10000 {
		clock.advance(time.Millisecond)
		m.Failure(fmt.Sprintf("2001:db8::%x", i+1), "a@example.com", mailboxExists)
	}
	if !m.TrustedAll(real, []string{"a@example.com"}) {
		t.Fatal("failure flood evicted trust")
	}
}

func TestMailSpray_TrustPoolBounded(t *testing.T) {
	cfg := testSprayConfig()
	cfg.MaxIPs = 100
	m, clock := newTestSpray(cfg)
	for i := range 10000 {
		clock.advance(time.Millisecond)
		m.Success(fmt.Sprintf("2001:db8::%x", i+1), fmt.Sprintf("u%d@example.com", i))
		if m.TrustSize() > cfg.MaxIPs {
			t.Fatalf("TrustSize() = %d after %d logins, want <= %d", m.TrustSize(), i+1, cfg.MaxIPs)
		}
	}

	// One IP keeps trust on at most maxSprayTrustPerIP mailboxes.
	cfg.MaxIPs = 1000
	m, _ = newTestSpray(cfg)
	for i := range maxSprayTrustPerIP + 50 {
		m.Success("192.0.2.1", fmt.Sprintf("u%d@example.com", i))
	}
	if m.TrustSize() != maxSprayTrustPerIP {
		t.Fatalf("one IP holds %d trust records, want %d", m.TrustSize(), maxSprayTrustPerIP)
	}
}

func TestMailSpray_UniqueNameFloodBounded(t *testing.T) {
	m, clock := newTestSpray(testSprayConfig())
	corroborate(t, m, "nobody@example.com")
	wantRule(t, m.Failure("192.0.2.1", "nobody@example.com", mailboxMissing), sprayRuleMissingMailbox, true)

	// Every flood name is newer than the corroborated one, so only rank, not
	// age, can keep it.
	for i := range 100000 {
		clock.advance(time.Second)
		m.Failure("192.0.2.2", fmt.Sprintf("x%d@example.com", i), mailboxMissing)
	}
	m.mu.Lock()
	names, perIP := len(m.names), len(m.ips["192.0.2.2"].failed)
	m.mu.Unlock()
	if names > maxSprayCorroborationNames {
		t.Fatalf("corroboration holds %d names, want <= %d", names, maxSprayCorroborationNames)
	}
	if perIP > maxSprayNamesPerIP {
		t.Fatalf("one IP holds %d names, want <= %d", perIP, maxSprayNamesPerIP)
	}
	// The corroborated name survives the flood.
	wantRule(t, m.Failure("2001:db8::1", "nobody@example.com", mailboxMissing), sprayRuleMissingMailbox, true)
}

// Trusted stale-password failures must not fill the name map and hide new
// untrusted targets from either breadth detection or trust admission.
func TestMailSpray_TrustedNamesCannotHideSpray(t *testing.T) {
	m, clock := newTestSpray(testSprayConfig())
	const ip = "192.0.2.1"
	var mailboxes []string
	for i := range maxSprayNamesPerIP {
		mailboxes = append(mailboxes, fmt.Sprintf("trusted%d@example.com", i))
	}
	ageTrust(t, m, clock, ip, mailboxes...)
	for _, mb := range mailboxes {
		wantNoVerdict(t, m.Failure(ip, mb, mailboxExists))
	}
	wantNoVerdict(t, m.Failure(ip, "victim@example.com", mailboxExists))
	if clean, v := m.Success(ip, "guessed@example.com"); clean {
		t.Fatal("full trusted-name map hid the failure on another mailbox")
	} else {
		wantRule(t, v, sprayRuleWeakCompromise, false)
	}
	wantRule(t, m.Failure(ip, "second@example.com", mailboxExists), sprayRuleBreadth, true)
	if !m.TrustedAll(ip, mailboxes) {
		t.Fatal("making room for untrusted failures removed existing trust")
	}
}

// Refusing a name at capacity must not make its later successful login clean
// when the older, retained failures expire. Purging must keep that evidence.
func TestMailSpray_OverflowCannotEarnTrust(t *testing.T) {
	for _, purge := range []bool{false, true} {
		t.Run(fmt.Sprintf("purge=%v", purge), func(t *testing.T) {
			cfg := testSprayConfig()
			m, clock := newTestSpray(cfg)
			const ip = "192.0.2.1"
			for i := range maxSprayNamesPerIP {
				m.Failure(ip, fmt.Sprintf("old%d@example.com", i), mailboxExists)
			}
			clock.advance(cfg.Window - time.Minute)
			m.Failure(ip, "recent@example.com", mailboxExists)
			clock.advance(2 * time.Minute)
			if purge {
				m.Purge()
			}
			if clean, v := m.Success(ip, "guessed@example.com"); clean {
				t.Fatal("discarded recent failure allowed a login to earn trust")
			} else {
				wantRule(t, v, sprayRuleWeakCompromise, false)
			}
			clock.advance(cfg.TrustAge)
			if m.TrustedAll(ip, []string{"guessed@example.com"}) {
				t.Fatal("overflow login earned aged trust")
			}
			clock.advance(cfg.Window)
			m.Purge()
			if m.Size() != 0 {
				t.Fatal("expired overflow kept evidence alive")
			}
			if clean, v := m.Success(ip, "guessed@example.com"); !clean || v != nil {
				t.Fatalf("login after all evidence expired = (%v, %+v)", clean, v)
			}
		})
	}
}

// The pool may be almost entirely strong evidence. A batch eviction must
// stop at the rank boundary once capacity is met, even if it misses 95%.
func TestMailSpray_FullEvidencePoolKeepsStrongerEntries(t *testing.T) {
	for _, strongCount := range []int{99, 100} {
		t.Run(fmt.Sprintf("strong=%d", strongCount), func(t *testing.T) {
			cfg := testSprayConfig()
			cfg.MaxIPs = 100
			m, clock := newTestSpray(cfg)
			for i := range strongCount {
				ip := fmt.Sprintf("2001:db8::%x", i+1)
				wantNoVerdict(t, m.Failure(ip, "a@example.com", mailboxExists))
				wantRule(t, m.Failure(ip, "b@example.com", mailboxExists), sprayRuleBreadth, true)
			}
			for i := range 20 {
				clock.advance(time.Second)
				m.Failure(fmt.Sprintf("192.0.2.%d", i+1), "noise@example.com", mailboxExists)
			}
			if m.Size() > cfg.MaxIPs {
				t.Fatalf("evidence pool holds %d IPs", m.Size())
			}
			clock.advance(cfg.Suppression)
			for i := range strongCount {
				wantRule(t, m.Failure(fmt.Sprintf("2001:db8::%x", i+1), "a@example.com", mailboxExists), sprayRuleBreadth, true)
			}
		})
	}
}

func TestMailSpray_FullCorroborationPoolKeepsStrongerEntries(t *testing.T) {
	m, clock := newTestSpray(testSprayConfig())
	for i := range maxSprayCorroborationNames {
		name := fmt.Sprintf("missing%d@example.com", i)
		for _, ip := range []string{"192.0.2.1", "198.51.100.1", "203.0.113.1"} {
			m.Failure(ip, name, mailboxMissing)
		}
	}
	clock.advance(time.Second)
	m.Failure("192.0.2.2", "noise@example.com", mailboxMissing)
	if len(m.names) > maxSprayCorroborationNames {
		t.Fatalf("corroboration pool holds %d names", len(m.names))
	}
	for i := range maxSprayCorroborationNames {
		name := fmt.Sprintf("missing%d@example.com", i)
		if got := m.networkCount(m.names[name], clock.Now()); got != 3 {
			t.Fatalf("%s has %d networks after one-shot pressure, want 3", name, got)
		}
	}
}

func TestMailSpray_CapacityRanksCurrentVerdict(t *testing.T) {
	cfg := testSprayConfig()
	cfg.MaxIPs = 2
	cfg.MissingNetworks = 1
	m, clock := newTestSpray(cfg)
	for _, ip := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		clock.advance(time.Second)
		wantRule(t, m.Failure(ip, "missing@example.com", mailboxMissing), sprayRuleMissingMailbox, true)
	}
	if clean, v := m.Success("192.0.2.3", "guessed@example.com"); clean {
		t.Fatal("eviction lost the current verdict's evidence")
	} else {
		wantRule(t, v, sprayRuleCompromise, true)
	}
}

// Refused failures on an already trusted mailbox must not taint a later
// clean login after the untrusted evidence expires.
func TestMailSpray_TrustedOverflowDoesNotTaint(t *testing.T) {
	cfg := testSprayConfig()
	m, clock := newTestSpray(cfg)
	const ip = "192.0.2.1"
	ageTrust(t, m, clock, ip, "trusted@example.com")
	for i := range maxSprayNamesPerIP {
		m.Failure(ip, fmt.Sprintf("old%d@example.com", i), mailboxExists)
	}
	clock.advance(cfg.Window - 2*cfg.TrustAge)
	if clean, v := m.Success(ip, "trusted@example.com"); !clean || v != nil {
		t.Fatalf("refresh trusted login = (%v, %+v)", clean, v)
	}
	m.Failure(ip, "trusted@example.com", mailboxExists)
	clock.advance(2*cfg.TrustAge + time.Second)
	if clean, v := m.Success(ip, "new@example.com"); !clean || v != nil {
		t.Fatalf("trusted overflow tainted clean login = (%v, %+v)", clean, v)
	}
}

func TestMailSpray_ReloadAndPurgeKeepTrustIndexesBounded(t *testing.T) {
	cfg := testSprayConfig()
	cfg.MaxIPs = 300
	m, clock := newTestSpray(cfg)
	for i := range 400 {
		m.Success("192.0.2.1", fmt.Sprintf("u%d@example.com", i))
		m.Success(fmt.Sprintf("2001:db8::%x", i+1), "shared@example.com")
	}
	checkIndexes := func() {
		t.Helper()
		if len(m.trust) > cfg.MaxIPs || len(m.trustByIP) > len(m.trust) || len(m.trustByMailbox) > len(m.trust) {
			t.Fatal("trust or indexes exceeded the pool cap")
		}
		for ip, mailboxes := range m.trustByIP {
			if len(mailboxes) == 0 || len(mailboxes) > maxSprayTrustPerIP {
				t.Fatalf("IP index has %d mailboxes", len(mailboxes))
			}
			for mb := range mailboxes {
				if _, ok := m.trust[sprayTrustKey{ip, mb}]; !ok {
					t.Fatal("IP index points to an evicted trust record")
				}
			}
		}
		for mb, ips := range m.trustByMailbox {
			if len(ips) == 0 || len(ips) > maxSprayTrustIPsPerMailbox {
				t.Fatalf("mailbox index has %d IPs", len(ips))
			}
			for ip := range ips {
				if _, ok := m.trust[sprayTrustKey{ip, mb}]; !ok {
					t.Fatal("mailbox index points to an evicted trust record")
				}
			}
		}
		for k := range m.trust {
			if _, ok := m.trustByIP[k.ip][k.mailbox]; !ok {
				t.Fatal("trust record absent from IP index")
			}
			if _, ok := m.trustByMailbox[k.mailbox][k.ip]; !ok {
				t.Fatal("trust record absent from mailbox index")
			}
		}
	}
	checkIndexes()
	cfg.MaxIPs = 10
	m.SetConfig(cfg)
	checkIndexes()
	if m.TrustSize() == 0 {
		t.Fatal("shrinking the pool discarded all trust")
	}
	clock.advance(cfg.Window + time.Second)
	m.Purge()
	checkIndexes()
	if m.TrustSize() != 0 {
		t.Fatal("expired trust survived purge")
	}
	m.Success("192.0.2.1", "a@example.com")
	m.Failure("192.0.2.2", "missing@example.com", mailboxMissing)
	cfg.Window = 0
	m.SetConfig(cfg)
	checkIndexes()
	if m.TrustSize() != 0 || m.Size() != 0 || len(m.names) != 0 || m.Mode() != sprayOff {
		t.Fatal("disabling memory kept state or an active mode")
	}
}

func TestMailSpray_ConcurrentRecordingAndReload(t *testing.T) {
	cfg := testSprayConfig()
	cfg.TrustAge = 0
	m, _ := newTestSpray(cfg)
	m.Success("192.0.2.2", "trusted@example.com")
	var wg sync.WaitGroup
	for _, operation := range []func(){
		func() {
			if v := m.Failure("192.0.2.1", "a@example.com", mailboxExists); v != nil {
				t.Errorf("one concurrent failing mailbox produced %+v", v)
			}
		},
		func() {
			if clean, v := m.Success("192.0.2.2", "trusted@example.com"); !clean || v != nil {
				t.Errorf("concurrent clean login = (%v, %+v)", clean, v)
			}
		},
		func() {
			if !m.TrustedAll("192.0.2.2", []string{"trusted@example.com"}) {
				t.Error("concurrent maintenance lost trust")
			}
		},
		func() { m.Purge() },
		func() { m.SetConfig(cfg) },
	} {
		wg.Go(func() {
			for range 100 {
				operation()
			}
		})
	}
	wg.Wait()
	if m.Size() != 1 || m.TrustSize() != 1 {
		t.Fatalf("concurrent state holds %d IPs and %d trust records, want 1 each", m.Size(), m.TrustSize())
	}
	wantRule(t, m.Failure("192.0.2.1", "b@example.com", mailboxExists), sprayRuleBreadth, true)
}

func TestMailSpray_AccountlessCountsAsOneName(t *testing.T) {
	m, _ := newTestSpray(testSprayConfig())
	wantNoVerdict(t, m.Failure("192.0.2.1", "", mailboxExistenceUnknown))
	wantNoVerdict(t, m.Failure("192.0.2.1", "", mailboxExistenceUnknown))
	wantRule(t, m.Failure("192.0.2.1", "a@example.com", mailboxExists), sprayRuleBreadth, true)
}

// An accountless failure names no mailbox, so it can never be a missing one.
func TestMailSpray_AccountlessNeverMissing(t *testing.T) {
	m, _ := newTestSpray(testSprayConfig())
	for _, ip := range []string{"198.51.100.1", "203.0.113.1", "192.0.2.1"} {
		wantNoVerdict(t, m.Failure(ip, "", mailboxMissing))
	}
	m.mu.Lock()
	_, corroborated := m.names[""]
	m.mu.Unlock()
	if corroborated {
		t.Fatal("accountless failure fed corroboration")
	}
	wantRule(t, m.Failure("192.0.2.1", "b@example.com", mailboxExistenceUnknown), sprayRuleBreadth, true)
}

func TestMailSpray_PurgeDropsExpired(t *testing.T) {
	m, clock := newTestSpray(testSprayConfig())
	m.Failure("198.51.100.1", "nobody@example.com", mailboxMissing)
	m.Success("192.0.2.1", "a@example.com")
	clock.advance(6 * 24 * time.Hour)
	m.Failure("203.0.113.1", "b@example.com", mailboxExists)
	clock.advance(2 * 24 * time.Hour)
	m.Purge()
	m.mu.Lock()
	names := len(m.names)
	m.mu.Unlock()
	if m.Size() != 1 || names != 0 || m.TrustSize() != 0 {
		t.Fatalf("after purge %d IPs, %d names, %d trust, want 1, 0, 0", m.Size(), names, m.TrustSize())
	}
	if m.TrustedAll("192.0.2.1", []string{"a@example.com"}) {
		t.Fatal("trust outlived the window")
	}
}

func TestMailSpray_ZeroWindowNoOp(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	m := newMailSpray(sprayConfig{}, clock.Now)
	for _, ip := range []string{"198.51.100.1", "203.0.113.1", "192.0.2.1"} {
		wantNoVerdict(t, m.Failure(ip, "nobody@example.com", mailboxMissing))
		wantNoVerdict(t, m.Failure(ip, "b@example.com", mailboxExists))
	}
	if clean, v := m.Success("192.0.2.2", "a@example.com"); clean || v != nil {
		t.Fatalf("Success = (%v, %+v), want (false, nil)", clean, v)
	}
	clock.advance(time.Hour)
	if m.TrustedAll("192.0.2.2", []string{"a@example.com"}) {
		t.Fatal("zero config recorded trust")
	}
	m.Purge()
	if m.Size() != 0 || m.TrustSize() != 0 || m.Mode() != sprayOff {
		t.Fatalf("Size() = %d TrustSize() = %d Mode() = %v, want 0 0 off", m.Size(), m.TrustSize(), m.Mode())
	}
}

func TestSprayNetworkKey(t *testing.T) {
	if a, b := sprayNetworkKey("198.51.100.7"), sprayNetworkKey("::ffff:198.51.100.7"); a == "" || a != b {
		t.Errorf("IPv4 %q vs mapped %q, want one key", a, b)
	}
	if a, b := sprayNetworkKey("198.51.100.7"), sprayNetworkKey("198.51.100.8"); a != b || !strings.HasSuffix(a, "/16") {
		t.Errorf("same network gave %q and %q, want one /16 key", a, b)
	}
	if a, b := sprayNetworkKey("2001:db8:1::1"), sprayNetworkKey("2001:db8:2::1"); a == "" || a != b {
		t.Errorf("same /32 gave %q and %q", a, b)
	}
	if a, b := sprayNetworkKey("198.51.100.7"), sprayNetworkKey("203.0.113.7"); a == b {
		t.Errorf("different /16 shared key %q", a)
	}
	for _, s := range []string{"", "garbage", "198.51.100", "2001:db8::1/64"} {
		if got := sprayNetworkKey(s); got != "" {
			t.Errorf("sprayNetworkKey(%q) = %q, want empty", s, got)
		}
	}
}

func TestParseSprayMode(t *testing.T) {
	for in, want := range map[string]sprayMode{"observe": sprayObserve, "enforce": sprayEnforce, "off": sprayOff, "": sprayOff, "Enforce": sprayOff} {
		if got := parseSprayMode(in); got != want {
			t.Errorf("parseSprayMode(%q) = %v, want %v", in, got, want)
		}
	}
}

// Purge keeps the once-per-window record of a weak advisory even after the
// failures behind it expire, so a fresh failure cannot re-raise it early.
func TestMailSpray_WeakAlertOutlivesItsFailures(t *testing.T) {
	cfg := testSprayConfig()
	m, clock := newTestSpray(cfg)
	const ip = "192.0.2.1"
	m.Failure(ip, "x@example.com", mailboxExists)
	clock.advance(time.Hour)
	_, v := m.Success(ip, "y@example.com")
	wantRule(t, v, sprayRuleWeakCompromise, false)
	clock.advance(cfg.Window - 30*time.Minute) // the failure expires, the advisory does not
	m.Purge()
	m.Failure(ip, "x@example.com", mailboxExists)
	if _, v := m.Success(ip, "y@example.com"); v != nil {
		t.Fatalf("weak advisory re-raised within the window: %+v", v)
	}
	clock.advance(cfg.Window + time.Minute)
	m.Purge()
	if m.Size() != 0 {
		t.Fatalf("expired advisory kept %d IPs alive", m.Size())
	}
}

// The once-per-window records are capped per IP, pruned by Purge while the
// IP stays for its evidence, and never count as trust.
func TestMailSpray_WeakAlertRecordsBounded(t *testing.T) {
	cfg := testSprayConfig()
	m, clock := newTestSpray(cfg)
	const ip = "192.0.2.1"
	m.Failure(ip, "x@example.com", mailboxExists)
	var mailboxes []string
	for i := range maxSprayNamesPerIP + 8 {
		clock.advance(cfg.Suppression)
		mb := fmt.Sprintf("u%d@example.com", i)
		mailboxes = append(mailboxes, mb)
		_, v := m.Success(ip, mb)
		wantRule(t, v, sprayRuleWeakCompromise, false)
	}
	records := func() int {
		m.mu.Lock()
		defer m.mu.Unlock()
		return len(m.ips[ip].weakAlerted)
	}
	if n := records(); n != maxSprayNamesPerIP {
		t.Fatalf("weak alert records = %d, want cap %d", n, maxSprayNamesPerIP)
	}
	clock.advance(cfg.TrustAge)
	if m.TrustSize() != 0 || m.TrustedAll(ip, mailboxes[len(mailboxes)-1:]) {
		t.Fatal("a weak alert record granted trust")
	}
	clock.advance(cfg.Window)
	m.Failure(ip, "x@example.com", mailboxExists)
	m.Purge()
	if n := records(); m.Size() != 1 || n != 0 {
		t.Fatalf("after purge %d IPs, %d weak alert records, want 1, 0", m.Size(), n)
	}
}
