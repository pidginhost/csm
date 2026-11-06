package daemon

import (
	"fmt"
	"maps"
	"slices"
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
	wantRule(t, m.Failure(ip, "d@example.com", mailboxExists), sprayRuleBreadth, true)
	clean, v := m.Success(ip, "a@example.com")
	if clean {
		t.Fatal("success after failures on other mailboxes reported clean")
	}
	wantRule(t, v, sprayRuleWeakCompromise, false)
	if v.Mailbox != "a@example.com" {
		t.Fatalf("verdict mailbox = %q, want a@example.com", v.Mailbox)
	}
	clock.advance(61 * time.Minute) // past TrustAge and the breadth suppression
	if m.TrustedAll(ip, []string{"a@example.com"}) {
		t.Fatal("success after spray earned trust")
	}
	wantRule(t, m.Failure(ip, "c@example.com", mailboxExists), sprayRuleBreadth, true)
}

// An office device with a stale saved password fails on one mailbox for days
// while colleagues log in to theirs. Failures on that one mailbox, existing
// or of unknown existence as on cPanel, taint no other login: each is clean
// and earns trust.
func TestMailSprayOneStaleMailboxKeepsTrust(t *testing.T) {
	mailboxes := []string{"a@example.com", "b@example.com", "c@example.com", "d@example.com", "e@example.com"}
	for name, exist := range map[string]mailboxExistence{"exists": mailboxExists, "unknown": mailboxExistenceUnknown} {
		t.Run(name, func(t *testing.T) {
			m, clock := newTestSpray(testSprayConfig())
			const ip = "192.0.2.10"
			for hour := range 3 * 24 {
				clock.advance(time.Hour)
				wantNoVerdict(t, m.Failure(ip, "f@example.com", exist))
				wantNoVerdict(t, m.Failure(ip, "f@example.com", exist))
				for _, mb := range mailboxes {
					if clean, v := m.Success(ip, mb); !clean || v != nil {
						t.Fatalf("hour %d login to %s = (%v, %+v), want (true, nil)", hour, mb, clean, v)
					}
				}
			}
			if !m.TrustedAll(ip, mailboxes) {
				t.Fatal("logins beside one stale mailbox earned no trust")
			}
		})
	}
}

// Failures on two mailboxes the address holds no trust for still make a
// login to a third the weak advisory, and it earns no trust.
func TestMailSprayTwoFailingMailboxesStillAdvise(t *testing.T) {
	for name, exist := range map[string]mailboxExistence{"exists": mailboxExists, "unknown": mailboxExistenceUnknown} {
		t.Run(name, func(t *testing.T) {
			m, clock := newTestSpray(testSprayConfig())
			const ip = "192.0.2.11"
			wantNoVerdict(t, m.Failure(ip, "f1@example.com", exist))
			wantRule(t, m.Failure(ip, "f2@example.com", exist), sprayRuleBreadth, true)
			clean, v := m.Success(ip, "a@example.com")
			if clean {
				t.Fatal("login after failures on two other mailboxes reported clean")
			}
			wantRule(t, v, sprayRuleWeakCompromise, false)
			if want := []string{"f1@example.com", "f2@example.com"}; v.Mailbox != "a@example.com" || !slices.Equal(v.Targets, want) {
				t.Fatalf("verdict mailbox %q targets %v, want a@example.com %v", v.Mailbox, v.Targets, want)
			}
			clock.advance(11 * time.Minute)
			if m.TrustedAll(ip, []string{"a@example.com"}) {
				t.Fatal("login after failures on two other mailboxes earned trust")
			}
		})
	}
}

// One other mailbox that does not exist still makes a login the weak
// advisory, and the strong compromise once enough networks tried the name.
func TestMailSprayOneMissingMailboxStillAdvises(t *testing.T) {
	const ip = "192.0.2.12"
	m, clock := newTestSpray(testSprayConfig())
	wantNoVerdict(t, m.Failure(ip, "nobody@example.com", mailboxMissing))
	clean, v := m.Success(ip, "a@example.com")
	if clean {
		t.Fatal("login after a failure on a missing mailbox reported clean")
	}
	wantRule(t, v, sprayRuleWeakCompromise, false)
	clock.advance(11 * time.Minute)
	if m.TrustedAll(ip, []string{"a@example.com"}) {
		t.Fatal("login after a failure on a missing mailbox earned trust")
	}

	m, _ = newTestSpray(testSprayConfig())
	corroborate(t, m, "nobody@example.com")
	wantRule(t, m.Failure(ip, "nobody@example.com", mailboxMissing), sprayRuleMissingMailbox, true)
	clean, v = m.Success(ip, "a@example.com")
	if clean {
		t.Fatal("login after a corroborated missing mailbox reported clean")
	}
	wantRule(t, v, sprayRuleCompromise, true)
}

// A failure that names no mailbox could be on any of them, so it is not one
// stale device: a login after it is still the weak advisory.
func TestMailSprayOneAccountlessFailureStillAdvises(t *testing.T) {
	m, _ := newTestSpray(testSprayConfig())
	const ip = "192.0.2.13"
	wantNoVerdict(t, m.Failure(ip, "", mailboxExistenceUnknown))
	clean, v := m.Success(ip, "a@example.com")
	if clean {
		t.Fatal("login after an accountless failure reported clean")
	}
	wantRule(t, v, sprayRuleWeakCompromise, false)
}

// The one-mailbox exception covers logins to mailboxes that did not fail. A
// source that failed on v@ and w@ and then logs in to v@ is a guessed
// password beside a spray, not an office: the weak advisory, and no trust.
// With v@'s failures in the stale-password shape it is still the weak
// advisory, not the 4d one.
func TestMailSprayLoginToFailingMailboxBesideOneOtherStillAdvises(t *testing.T) {
	for name, spread := range map[string]time.Duration{"retry": 0, "stale": 2 * time.Hour} {
		t.Run(name, func(t *testing.T) {
			m, clock := newTestSpray(testSprayConfig())
			const ip = "192.0.2.14"
			wantNoVerdict(t, m.Failure(ip, "v@example.com", mailboxExists))
			clock.advance(spread)
			wantNoVerdict(t, m.Failure(ip, "v@example.com", mailboxExists))
			wantRule(t, m.Failure(ip, "w@example.com", mailboxExists), sprayRuleBreadth, true)
			clean, v := m.Success(ip, "v@example.com")
			if clean {
				t.Fatal("login to a failing mailbox beside another reported clean")
			}
			wantRule(t, v, sprayRuleWeakCompromise, false)
			clock.advance(11 * time.Minute)
			if m.TrustedAll(ip, []string{"v@example.com"}) {
				t.Fatal("login to a failing mailbox beside another earned trust")
			}
		})
	}
}

// A crack on a mailbox stays revoked beside one stale mailbox: the login
// earns no trust and raises nothing new.
func TestMailSprayStaleMailboxKeepsRevocation(t *testing.T) {
	m, clock := newTestSpray(testSprayConfig())
	const ip = "192.0.2.15"
	m.RevokeTrust(ip, "a@example.com")
	wantNoVerdict(t, m.Failure(ip, "f@example.com", mailboxExists))
	if clean, v := m.Success(ip, "a@example.com"); clean || v != nil {
		t.Fatalf("revoked login beside one stale mailbox = (%v, %+v), want (false, nil)", clean, v)
	}
	clock.advance(11 * time.Minute)
	if m.TrustedAll(ip, []string{"a@example.com"}) || m.TrustSize() != 0 {
		t.Fatal("revoked mailbox earned trust beside one stale mailbox")
	}
	// Another mailbox beside the same stale one is still clean.
	if clean, v := m.Success(ip, "b@example.com"); !clean || v != nil {
		t.Fatalf("login beside one stale mailbox = (%v, %+v), want (true, nil)", clean, v)
	}
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

// A clean login that came before failures on other mailboxes stays clean
// on its next poll, even before its trust ages.
func TestMailSpray_TrustBeforeLaterFailuresStaysClean(t *testing.T) {
	m, clock := newTestSpray(testSprayConfig())
	const ip = "192.0.2.1"
	if clean, v := m.Success(ip, "a@example.com"); !clean || v != nil {
		t.Fatalf("first login = (%v, %+v), want clean", clean, v)
	}
	clock.advance(time.Minute)
	wantNoVerdict(t, m.Failure(ip, "b@example.com", mailboxExists))
	clock.advance(3 * time.Minute)
	if clean, v := m.Success(ip, "a@example.com"); !clean || v != nil {
		t.Fatalf("poll after a later failure = (%v, %+v), want (true, nil)", clean, v)
	}
}

// The control: the failures on b@ and c@ came before the first clean login
// on a@ (both were trusted then and their trust is revoked later), so they
// still taint the next poll.
func TestMailSpray_FailureBeforeTrustStillTaints(t *testing.T) {
	m, clock := newTestSpray(testSprayConfig())
	const ip = "192.0.2.1"
	ageTrust(t, m, clock, ip, "b@example.com", "c@example.com")
	wantNoVerdict(t, m.Failure(ip, "b@example.com", mailboxExists))
	wantNoVerdict(t, m.Failure(ip, "c@example.com", mailboxExists))
	clock.advance(time.Minute)
	if clean, v := m.Success(ip, "a@example.com"); !clean || v != nil {
		t.Fatalf("first login = (%v, %+v), want clean", clean, v)
	}
	m.RevokeTrust(ip, "b@example.com")
	m.RevokeTrust(ip, "c@example.com")
	clock.advance(3 * time.Minute)
	clean, v := m.Success(ip, "a@example.com")
	if clean {
		t.Fatal("poll after an earlier failure reported clean")
	}
	wantRule(t, v, sprayRuleWeakCompromise, false)
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
	clock.advance(2 * time.Hour)
	wantNoVerdict(t, m.Failure(ip, "a@example.com", mailboxExists))
	clean, v := m.Success(ip, "a@example.com")
	if !clean {
		t.Fatal("success after single-mailbox failures not clean")
	}
	wantRule(t, v, sprayRuleSingleMailboxSuccess, false)
	if v.Mailbox != "a@example.com" || !slices.Equal(v.Targets, []string{"a@example.com"}) {
		t.Fatalf("verdict mailbox = %q targets %v, want a@example.com alone", v.Mailbox, v.Targets)
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

// Only a block verdict in enforce mode carries the spray block length.
func TestMailSprayVerdictBlockTTL(t *testing.T) {
	const ip = "192.0.2.1"
	scenarios := []struct {
		name  string
		rule  sprayRule
		block bool
		run   func(*testing.T, *mailSpray, *staticClock) *sprayVerdict
	}{
		{"breadth", sprayRuleBreadth, true, func(_ *testing.T, m *mailSpray, _ *staticClock) *sprayVerdict {
			m.Failure(ip, "a@example.com", mailboxExists)
			return m.Failure(ip, "b@example.com", mailboxExists)
		}},
		{"missing mailbox", sprayRuleMissingMailbox, true, func(t *testing.T, m *mailSpray, _ *staticClock) *sprayVerdict {
			corroborate(t, m, "nobody@example.com")
			return m.Failure(ip, "nobody@example.com", mailboxMissing)
		}},
		{"compromise", sprayRuleCompromise, true, func(t *testing.T, m *mailSpray, clock *staticClock) *sprayVerdict {
			ageTrust(t, m, clock, ip, "a@example.com")
			corroborate(t, m, "nobody@example.com")
			m.Failure(ip, "nobody@example.com", mailboxMissing)
			_, v := m.Success(ip, "c@example.com")
			return v
		}},
		{"downgraded compromise", sprayRuleCompromise, false, func(t *testing.T, m *mailSpray, clock *staticClock) *sprayVerdict {
			ageTrust(t, m, clock, ip, "a@example.com", "b@example.com")
			corroborate(t, m, "nobody@example.com")
			m.Failure(ip, "nobody@example.com", mailboxMissing)
			_, v := m.Success(ip, "c@example.com")
			return v
		}},
		{"weak compromise", sprayRuleWeakCompromise, false, func(_ *testing.T, m *mailSpray, _ *staticClock) *sprayVerdict {
			m.Failure(ip, "b@example.com", mailboxExists)
			m.Failure(ip, "c@example.com", mailboxExists)
			_, v := m.Success(ip, "a@example.com")
			return v
		}},
		{"single mailbox", sprayRuleSingleMailboxSuccess, false, func(_ *testing.T, m *mailSpray, clock *staticClock) *sprayVerdict {
			m.Failure(ip, "a@example.com", mailboxExists)
			clock.advance(2 * time.Hour)
			m.Failure(ip, "a@example.com", mailboxExists)
			_, v := m.Success(ip, "a@example.com")
			return v
		}},
	}
	for _, mode := range []string{"enforce", "observe"} {
		for _, sc := range scenarios {
			t.Run(mode+"/"+sc.name, func(t *testing.T) {
				cfg := testSprayConfig()
				cfg.Mode = parseSprayMode(mode)
				cfg.BlockTTL = 48 * time.Hour
				m, clock := newTestSpray(cfg)
				v := sc.run(t, m, clock)
				wantRule(t, v, sc.rule, sc.block)
				var want time.Duration
				if sc.block && mode == "enforce" {
					want = cfg.BlockTTL
				}
				if v.BlockTTL != want {
					t.Fatalf("BlockTTL = %v, want %v", v.BlockTTL, want)
				}
			})
		}
	}
}

// 4d needs the first failure at least an hour before the login. A user who
// mistypes twice in a row and then logs in gets no advisory, and still earns
// trust.
func TestMailSpray_SingleMailboxQuickRetryNoAdvisory(t *testing.T) {
	for _, gap := range []time.Duration{time.Minute, 59 * time.Minute} {
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

// sprayCadence fails ip every 2h on names in turn, n times, and counts the
// verdicts.
func sprayCadence(m *mailSpray, clock *staticClock, ip string, n int, names ...string) int {
	verdicts := 0
	for i := range n {
		clock.advance(2 * time.Hour)
		if m.Failure(ip, names[i%len(names)], mailboxExists) != nil {
			verdicts++
		}
	}
	return verdicts
}

// Observe mode blocks nothing, so an IP over the bar keeps failing. Its
// verdict repeats once per window, or when it fails on more mailboxes;
// enforce mode still re-blocks after each suppression period.
func TestMailSpray_ObserveVerdictOncePerWindow(t *testing.T) {
	cfg := testSprayConfig()
	const ip = "192.0.2.1"
	window := int(cfg.Window / (2 * time.Hour))

	cfg.Mode = sprayEnforce
	m, clock := newTestSpray(cfg)
	if got := sprayCadence(m, clock, ip, window, "a@example.com", "b@example.com"); got != window-1 {
		t.Fatalf("enforce: %d verdicts in a window, want %d", got, window-1)
	}

	cfg.Mode = sprayObserve
	m, clock = newTestSpray(cfg)
	if got := sprayCadence(m, clock, ip, window, "a@example.com", "b@example.com"); got != 1 {
		t.Fatalf("observe: %d verdicts in a window, want 1", got)
	}
	clock.advance(2 * time.Hour)
	wantRule(t, m.Failure(ip, "c@example.com", mailboxExists), sprayRuleBreadth, true)
	// The next verdict comes a window after the last one.
	if got := sprayCadence(m, clock, ip, window, "a@example.com", "b@example.com", "c@example.com"); got != 0 {
		t.Fatalf("observe: %d verdicts within the window after a new mailbox, want 0", got)
	}
	if got := sprayCadence(m, clock, ip, 1, "a@example.com"); got != 1 {
		t.Fatal("observe: no verdict a window after the last one")
	}
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
		m.Failure(fmt.Sprintf("2001:db8:%x::1", i+1), "a@example.com", mailboxExists)
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
		m.Failure(fmt.Sprintf("2001:db8:%x::1", i+1), "a@example.com", mailboxExists)
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
	wantRule(t, m.Failure(ip, "second@example.com", mailboxExists), sprayRuleBreadth, true)
	if clean, v := m.Success(ip, "guessed@example.com"); clean {
		t.Fatal("full trusted-name map hid the failures on other mailboxes")
	} else {
		wantRule(t, v, sprayRuleWeakCompromise, false)
	}
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
				ip := fmt.Sprintf("2001:db8:%x::1", i+1)
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
				wantRule(t, m.Failure(fmt.Sprintf("2001:db8:%x::1", i+1), "a@example.com", mailboxExists), sprayRuleBreadth, true)
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

// A pool full of multi-failure evidence must still make room: otherwise
// each new IP evicts only itself, and one that returns on a second name
// gets no verdict.
func TestMailSpray_FullRepeatPoolKeepsLearning(t *testing.T) {
	cfg := testSprayConfig()
	cfg.MaxIPs = 100
	m, clock := newTestSpray(cfg)
	for i := range cfg.MaxIPs {
		ip := fmt.Sprintf("2001:db8:%x::1", i+1)
		wantNoVerdict(t, m.Failure(ip, "a@example.com", mailboxExists))
		wantNoVerdict(t, m.Failure(ip, "a@example.com", mailboxExists))
	}
	held := func(ip string) bool {
		m.mu.Lock()
		defer m.mu.Unlock()
		return m.ips[ip] != nil
	}
	const returning = "192.0.2.201"
	for _, ip := range []string{"192.0.2.200", returning, "192.0.2.202", "192.0.2.203"} {
		clock.advance(time.Second)
		wantNoVerdict(t, m.Failure(ip, "a@example.com", mailboxExists))
		if ip != "192.0.2.200" && !held(ip) {
			t.Fatalf("new IP %s was evicted on arrival", ip)
		}
		if m.Size() > cfg.MaxIPs {
			t.Fatalf("evidence pool holds %d IPs", m.Size())
		}
	}
	clock.advance(time.Hour)
	wantRule(t, m.Failure(returning, "b@example.com", mailboxExists), sprayRuleBreadth, true)
}

// Once a batch stops before entries over a bar, weaker newcomers are
// dropped without ranking the pool again: one sort, not one per newcomer.
func TestSprayEvict_FloorSkipsSortForWeakerNewcomers(t *testing.T) {
	const limit, newcomers = 100, 50
	pool := make(map[int]int) // key to rank
	for k := range limit {
		pool[k] = sprayRankVerdict
	}
	ranked, floor := 0, 0
	insert := func(k, rank int) {
		pool[k] = rank
		sprayEvict(pool, limit, k, &floor,
			func(r int) int { ranked++; return r },
			func(int) time.Time { return time.Time{} },
			func(k int) { delete(pool, k) })
	}
	for i := range newcomers {
		insert(limit+i, i%2) // one-shot and multi-failure alike
	}
	if floor != sprayRankVerdict {
		t.Fatalf("floor = %d, want %d", floor, sprayRankVerdict)
	}
	// One sort ranks the pool and the first newcomer; every newcomer is
	// also ranked once against the floor.
	if want := limit + 1 + newcomers; ranked > want {
		t.Fatalf("ranked %d entries for %d newcomers, want at most %d (one sort)", ranked, newcomers, want)
	}
	for k := range limit {
		if pool[k] != sprayRankVerdict {
			t.Fatalf("entry %d over the bar was evicted", k)
		}
	}
	if len(pool) != limit {
		t.Fatalf("pool holds %d entries, want %d", len(pool), limit)
	}
}

// A batch that stops before entries over a bar with spare room left sets
// the floor, but a weaker newcomer admitted into that room ends it, so the
// next overflow sorts again and drops every weak entry, as before.
func TestSprayEvict_SpareRoomClearsFloor(t *testing.T) {
	const limit = 100
	pool := make(map[int]int) // key to rank
	floor := 0
	insert := func(k, rank int) {
		pool[k] = rank
		sprayEvict(pool, limit, k, &floor,
			func(r int) int { return r },
			func(int) time.Time { return time.Time{} },
			func(k int) { delete(pool, k) })
	}
	for k := range limit - 2 {
		insert(k, sprayRankVerdict)
	}
	insert(limit-2, sprayRankRepeat)
	insert(limit-1, sprayRankRepeat)
	insert(limit, sprayRankOneShot) // drops itself and both repeats
	if floor != sprayRankVerdict || len(pool) != limit-2 {
		t.Fatalf("floor = %d with %d entries, want %d with %d", floor, len(pool), sprayRankVerdict, limit-2)
	}
	insert(limit+1, sprayRankOneShot)
	if _, ok := pool[limit+1]; floor != 0 || !ok {
		t.Fatalf("floor = %d after admitting a newcomer into spare room, want 0", floor)
	}
	insert(limit+2, sprayRankOneShot)
	insert(limit+3, sprayRankOneShot)
	if _, ok := pool[limit+1]; ok || len(pool) != limit-2 || floor != sprayRankVerdict {
		t.Fatalf("overflow kept a weak entry: %d entries, floor %d", len(pool), floor)
	}
}

// Both pools record the floor when full of entries over a bar, and the
// minute purge clears it.
func TestMailSpray_FullPoolsSetEvictionFloor(t *testing.T) {
	cfg := testSprayConfig()
	cfg.MaxIPs = 100
	ips, clock := newTestSpray(cfg)
	for i := range cfg.MaxIPs {
		ip := fmt.Sprintf("2001:db8:%x::1", i+1)
		wantNoVerdict(t, ips.Failure(ip, "a@example.com", mailboxExists))
		wantRule(t, ips.Failure(ip, "b@example.com", mailboxExists), sprayRuleBreadth, true)
	}
	clock.advance(time.Second)
	ips.Failure("192.0.2.2", "a@example.com", mailboxExists)

	names, clock := newTestSpray(testSprayConfig())
	for i := range maxSprayCorroborationNames {
		name := fmt.Sprintf("missing%d@example.com", i)
		for _, ip := range []string{"192.0.2.1", "198.51.100.1", "203.0.113.1"} {
			names.Failure(ip, name, mailboxMissing)
		}
	}
	clock.advance(time.Second)
	names.Failure("192.0.2.2", "noise@example.com", mailboxMissing)

	floors := func() (int, int) {
		ips.mu.Lock()
		defer ips.mu.Unlock()
		names.mu.Lock()
		defer names.mu.Unlock()
		return ips.ipFloor, names.nameFloor
	}
	if ipFloor, nameFloor := floors(); ipFloor != sprayRankVerdict || nameFloor != sprayRankVerdict {
		t.Fatalf("floors = %d, %d, want %d for both", ipFloor, nameFloor, sprayRankVerdict)
	}
	ips.Purge()
	names.Purge()
	if ipFloor, nameFloor := floors(); ipFloor != 0 || nameFloor != 0 {
		t.Fatalf("floors after purge = %d, %d, want 0", ipFloor, nameFloor)
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
		keyed := 0
		for key, ips := range m.trustByKey {
			for ip := range ips {
				if len(m.trustByIP[ip]) == 0 || sprayEvidenceKey(ip) != key {
					t.Fatalf("evidence key index holds %s under %s without its trust", ip, key)
				}
				keyed++
			}
		}
		if keyed != len(m.trustByIP) {
			t.Fatalf("evidence key index holds %d IPs, IP index %d", keyed, len(m.trustByIP))
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
	m.Failure(ip, "w@example.com", mailboxExists)
	clock.advance(time.Hour)
	_, v := m.Success(ip, "y@example.com")
	wantRule(t, v, sprayRuleWeakCompromise, false)
	clock.advance(cfg.Window - 30*time.Minute) // the failures expire, the advisory does not
	m.Purge()
	m.Failure(ip, "x@example.com", mailboxExists)
	m.Failure(ip, "w@example.com", mailboxExists)
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
	m.Failure(ip, "w@example.com", mailboxExists)
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

// Forgetting outage failures keeps what came before: a name that also
// failed earlier keeps its first failure only. Trust and verdicts stay.
func TestMailSpray_ForgetRecentFailures(t *testing.T) {
	m, clock := newTestSpray(testSprayConfig())
	const ip = "192.0.2.1"
	ageTrust(t, m, clock, ip, "t@example.com")
	start := clock.Now()
	wantNoVerdict(t, m.Failure(ip, "both@example.com", mailboxExists))
	clock.advance(time.Hour)
	wantNoVerdict(t, m.Failure(ip, "both@example.com", mailboxExists))
	wantRule(t, m.Failure(ip, "new@example.com", mailboxExists), sprayRuleBreadth, true)
	m.mu.Lock()
	verdictAt := m.ips[ip].verdictAt
	m.mu.Unlock()

	m.ForgetRecentFailures(ip, clock.Now().Add(-10*time.Minute))
	m.mu.Lock()
	failed, kept := maps.Clone(m.ips[ip].failed), m.ips[ip].verdictAt
	m.mu.Unlock()
	got, ok := failed["both@example.com"]
	if len(failed) != 1 || !ok || !got.first.Equal(start) || !got.last.Equal(start) || got.count != 1 {
		t.Fatalf("failures after forgetting = %+v, want both@ with its first failure only", failed)
	}
	if !kept.Equal(verdictAt) {
		t.Fatal("forgetting failures dropped the verdict")
	}
	if !m.TrustedAll(ip, []string{"t@example.com"}) {
		t.Fatal("forgetting failures dropped trust")
	}
	m.ForgetRecentFailures("192.0.2.99", clock.Now()) // no evidence held
}

// Revoking one (IP, mailbox) record leaves other trust and indexes intact.
func TestMailSpray_RevokeTrustDropsOneRecord(t *testing.T) {
	m, clock := newTestSpray(testSprayConfig())
	ageTrust(t, m, clock, "192.0.2.1", "a@example.com", "b@example.com")
	ageTrust(t, m, clock, "192.0.2.2", "a@example.com")
	m.RevokeTrust("192.0.2.1", "a@example.com")
	m.RevokeTrust("192.0.2.9", "nobody@example.com") // no trust or indexes to drop
	if m.TrustedAll("192.0.2.1", []string{"a@example.com"}) || !m.TrustedAll("192.0.2.1", []string{"b@example.com"}) ||
		!m.TrustedAll("192.0.2.2", []string{"a@example.com"}) || m.TrustSize() != 2 {
		t.Fatalf("revoke dropped the wrong records: %d left", m.TrustSize())
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.trustByIP) != 2 || len(m.trustByIP["192.0.2.1"]) != 1 || len(m.trustByMailbox["a@example.com"]) != 1 {
		t.Fatalf("indexes out of step: by IP %v, by mailbox %v", m.trustByIP, m.trustByMailbox)
	}
}

func TestMailSpray_RevocationLastsForWindow(t *testing.T) {
	cfg := testSprayConfig()
	m, clock := newTestSpray(cfg)
	const ip, mailbox = "192.0.2.1", "a@example.com"
	ageTrust(t, m, clock, ip, mailbox, "b@example.com")
	m.RevokeTrust(ip, mailbox)
	for _, gap := range []time.Duration{0, cfg.Window} {
		clock.advance(gap)
		m.Purge()
		if clean, v := m.Success(ip, mailbox); clean || v != nil {
			t.Fatalf("revoked login = %v, %+v", clean, v)
		}
		if m.TrustedAll(ip, []string{mailbox}) {
			t.Fatal("revoked mailbox regained trust")
		}
	}
	clock.advance(time.Nanosecond)
	m.Purge()
	if m.Size() != 0 {
		t.Fatal("expired revocation kept evidence alive")
	}
	if clean, v := m.Success(ip, mailbox); !clean || v != nil {
		t.Fatalf("expired revocation blocked clean login: %v, %+v", clean, v)
	}
}

// The shared evidence limits also bound revocations. Saturation must not
// forget a known crack and let that mailbox earn trust again.
func TestMailSpray_RevocationAtCapacity(t *testing.T) {
	cfg := testSprayConfig()
	cfg.MaxIPs = 4
	m, clock := newTestSpray(cfg)
	const ip = "192.0.2.1"
	for i := range maxSprayNamesPerIP + 1 {
		m.RevokeTrust(ip, walkedMailbox(i))
	}
	if n := len(m.ips[ip].revoked); n != maxSprayNamesPerIP {
		t.Fatalf("revocation records = %d, want %d", n, maxSprayNamesPerIP)
	}
	for i := range 2 * cfg.MaxIPs {
		clock.advance(time.Second)
		m.Failure(fmt.Sprintf("2001:db8:%x::1", i+1), "noise@example.com", mailboxExists)
		if m.Size() > cfg.MaxIPs {
			t.Fatal("revocations exceeded the evidence pool limit")
		}
	}
	for i := range maxSprayNamesPerIP + 1 {
		if clean, _ := m.Success(ip, walkedMailbox(i)); clean {
			t.Fatalf("revoked mailbox %d regained trust at capacity", i)
		}
	}
	if m.TrustSize() != 0 {
		t.Fatal("revocations created trust")
	}
	for i := range 2 * cfg.MaxIPs {
		m.RevokeTrust(fmt.Sprintf("2001:db8:%x::1", i+1), "cracked@example.com")
		if m.Size() > cfg.MaxIPs {
			t.Fatal("new revocations exceeded the evidence pool limit")
		}
	}
}

func TestMailSpray_RevokedLoginStillReportsCompromise(t *testing.T) {
	m, _ := newTestSpray(testSprayConfig())
	const ip, mailbox = "192.0.2.1", "a@example.com"
	m.RevokeTrust(ip, mailbox)
	corroborate(t, m, "missing@example.com")
	m.Failure(ip, "missing@example.com", mailboxMissing)
	clean, v := m.Success(ip, mailbox)
	if clean {
		t.Fatal("revoked login earned trust")
	}
	wantRule(t, v, sprayRuleCompromise, true)
}

// The per-IP name cap must hold the highest breadth bar config accepts, or
// the rule would fire below the configured bar.
func TestMailSpray_NameCapHoldsHighestBreadthBar(t *testing.T) {
	const highestBar = 10 // config validation maximum
	cfg := testSprayConfig()
	cfg.BreadthMailboxes = highestBar
	m, _ := newTestSpray(cfg)
	const ip = "192.0.2.70"
	for i := range highestBar - 1 {
		wantNoVerdict(t, m.Failure(ip, fmt.Sprintf("n%d@example.com", i), mailboxExists))
	}
	wantRule(t, m.Failure(ip, "last@example.com", mailboxExists), sprayRuleBreadth, true)
}

// An IPv6 host rotates through its /64, so its failures share one evidence
// entry; another /64 and every IPv4 address keep their own.
func TestMailSprayIPv6EvidencePer64(t *testing.T) {
	cfg := testSprayConfig()
	cfg.BreadthMailboxes = 3
	m, _ := newTestSpray(cfg)
	wantNoVerdict(t, m.Failure("2001:db8:1:2::a", "a@example.com", mailboxExists))
	wantNoVerdict(t, m.Failure("2001:db8:1:2::b", "b@example.com", mailboxExists))
	v := m.Failure("2001:db8:1:2:ffff::c", "c@example.com", mailboxExists)
	wantRule(t, v, sprayRuleBreadth, true)
	if want := []string{"a@example.com", "b@example.com", "c@example.com"}; !slices.Equal(v.Targets, want) {
		t.Fatalf("targets = %v, want %v", v.Targets, want)
	}
	wantNoVerdict(t, m.Failure("2001:db8:1:3::a", "d@example.com", mailboxExists))
	wantNoVerdict(t, m.Failure("192.0.2.1", "a@example.com", mailboxExists))
	wantNoVerdict(t, m.Failure("192.0.2.2", "b@example.com", mailboxExists))
	if m.Size() != 4 {
		t.Fatalf("evidence entries = %d, want one /64, another /64 and two IPv4 addresses", m.Size())
	}
}

// Blocks target addresses: once a /64 is over the bar, each new address that
// fails draws its own verdict, and suppression holds per address.
func TestMailSprayIPv6EachAddressDrawsItsOwnVerdict(t *testing.T) {
	m, _ := newTestSpray(testSprayConfig())
	const a, b = "2001:db8:1:2::a", "2001:db8:1:2::b"
	wantNoVerdict(t, m.Failure(a, "a@example.com", mailboxExists))
	wantRule(t, m.Failure(a, "b@example.com", mailboxExists), sprayRuleBreadth, true)
	wantNoVerdict(t, m.Failure(a, "c@example.com", mailboxExists))
	wantRule(t, m.Failure(b, "a@example.com", mailboxExists), sprayRuleBreadth, true)
	wantNoVerdict(t, m.Failure(b, "d@example.com", mailboxExists))
}

// Observe mode blocks nothing: one /64 is reported once per window, and
// again only when it fails on more mailboxes, whichever address fails.
func TestMailSprayIPv6ObserveReportsOncePer64(t *testing.T) {
	cfg := testSprayConfig()
	cfg.Mode = sprayObserve
	m, _ := newTestSpray(cfg)
	wantNoVerdict(t, m.Failure("2001:db8:1:2::a", "a@example.com", mailboxExists))
	wantRule(t, m.Failure("2001:db8:1:2::a", "b@example.com", mailboxExists), sprayRuleBreadth, true)
	wantNoVerdict(t, m.Failure("2001:db8:1:2::b", "a@example.com", mailboxExists))
	wantNoVerdict(t, m.Failure("2001:db8:1:2::c", "b@example.com", mailboxExists))
	wantRule(t, m.Failure("2001:db8:1:2::d", "c@example.com", mailboxExists), sprayRuleBreadth, true)
}

// A household /64: one device's saved passwords went stale on two mailboxes
// that device holds aged trust for. Aged trust held by any address of the
// /64 excuses failures on those mailboxes, so another device's clean login
// earns trust and its one typo blocks nothing. Trust itself is still earned
// and held per address, and it excuses nothing for another /64.
func TestMailSprayIPv6TrustExcusesPer64(t *testing.T) {
	for _, trusted := range []bool{true, false} {
		t.Run(fmt.Sprintf("trusted=%v", trusted), func(t *testing.T) {
			m, clock := newTestSpray(testSprayConfig())
			const a, b = "2001:db8:1:2::a", "2001:db8:1:2::b"
			if trusted {
				ageTrust(t, m, clock, a, "x@example.com", "x2@example.com")
			}
			wantNoVerdict(t, m.Failure(a, "x@example.com", mailboxExists))
			clock.advance(time.Hour)
			wantNoVerdict(t, m.Failure(a, "x@example.com", mailboxExists))
			if v := m.Failure(a, "x2@example.com", mailboxExists); trusted {
				wantNoVerdict(t, v)
			} else {
				wantRule(t, v, sprayRuleBreadth, true)
			}

			clean, v := m.Success(b, "z@example.com")
			if trusted && (!clean || v != nil) {
				t.Fatalf("clean login beside excused failures = (%v, %+v), want (true, nil)", clean, v)
			}
			if !trusted {
				if clean {
					t.Fatal("login after untrusted failures earned trust")
				}
				wantRule(t, v, sprayRuleWeakCompromise, false)
			}
			v = m.Failure(b, "y@example.com", mailboxExists)
			if trusted {
				wantNoVerdict(t, v)
			} else {
				wantRule(t, v, sprayRuleBreadth, true)
			}
			if m.TrustedAll(b, []string{"x@example.com"}) {
				t.Fatal("trust moved between addresses of one /64")
			}
			if trusted {
				const c = "2001:db8:1:3::c"
				wantNoVerdict(t, m.Failure(c, "x@example.com", mailboxExists))
				wantRule(t, m.Failure(c, "y@example.com", mailboxExists), sprayRuleBreadth, true)
			}
		})
	}
}

// 4e and the established-source downgrade count aged trust held by any
// address of the /64.
func TestMailSprayIPv6TrustRulesCountThe64(t *testing.T) {
	m, clock := newTestSpray(testSprayConfig())
	const a, b = "2001:db8:1:2::a", "2001:db8:1:2::b"
	ageTrust(t, m, clock, a, "a@example.com", "b@example.com")
	corroborate(t, m, "nobody@example.com")
	wantNoVerdict(t, m.Failure(b, "nobody@example.com", mailboxMissing))
	_, v := m.Success(b, "c@example.com")
	wantRule(t, v, sprayRuleCompromise, false)
}

// An IPv4 address is its own evidence key: another address's trust, even
// next door, excuses nothing.
func TestMailSprayIPv4TrustExcusesOnlyItsAddress(t *testing.T) {
	m, clock := newTestSpray(testSprayConfig())
	ageTrust(t, m, clock, "192.0.2.1", "x@example.com")
	wantNoVerdict(t, m.Failure("192.0.2.2", "x@example.com", mailboxExists))
	wantRule(t, m.Failure("192.0.2.2", "y@example.com", mailboxExists), sprayRuleBreadth, true)
	wantNoVerdict(t, m.Failure("192.0.2.1", "x@example.com", mailboxExists))
	wantNoVerdict(t, m.Failure("192.0.2.1", "y@example.com", mailboxExists))
}

// Addresses of one /64 that draw verdicts are capped like the other
// per-entry records; the record that lapses first goes.
func TestMailSprayIPv6SourcesBounded(t *testing.T) {
	m, clock := newTestSpray(testSprayConfig())
	addr := func(i int) string { return fmt.Sprintf("2001:db8:1:2::%x", i+1) }
	wantNoVerdict(t, m.Failure(addr(0), "a@example.com", mailboxExists))
	for i := range maxSprayNamesPerIP + 1 {
		clock.advance(time.Second)
		wantRule(t, m.Failure(addr(i), "b@example.com", mailboxExists), sprayRuleBreadth, true)
	}
	e := m.ips["2001:db8:1:2::/64"]
	if _, ok := e.sources[addr(0)]; ok || len(e.sources) != maxSprayNamesPerIP {
		t.Fatalf("sources = %d, first kept = %v; want %d without the first", len(e.sources), ok, maxSprayNamesPerIP)
	}
	wantNoVerdict(t, m.Failure(addr(maxSprayNamesPerIP), "c@example.com", mailboxExists))
}

// A household member's device rotates its IPv6 address. A correct login to
// a mailbox some address of the /64 already trusts is clean: no compromise
// from a sibling's failure, and the new address starts its own trust.
func TestMailSprayIPv6RotatedAddressLoginIsClean(t *testing.T) {
	m, clock := newTestSpray(testSprayConfig())
	const yesterday, sibling, today = "2001:db8:1:2::a", "2001:db8:1:2::5", "2001:db8:1:2::b"
	ageTrust(t, m, clock, yesterday, "l@example.com")
	clock.advance(24 * time.Hour)
	corroborate(t, m, "nobody@example.com")
	wantNoVerdict(t, m.Failure(sibling, "nobody@example.com", mailboxMissing))
	if clean, v := m.Success(today, "l@example.com"); !clean || v != nil {
		t.Fatalf("rotated address login = (%v, %+v), want (true, nil)", clean, v)
	}
	m.mu.Lock()
	tr, ok := m.trust[sprayTrustKey{today, "l@example.com"}]
	m.mu.Unlock()
	if !ok || !tr.first.Equal(clock.Now()) {
		t.Fatalf("trust for the new address = %+v, %v; want started now", tr, ok)
	}
	if m.TrustedAll(today, []string{"l@example.com"}) {
		t.Fatal("new address inherited aged trust")
	}
}

// One device keeps failing on a stale password while another member logs in
// daily from a new address. Trust passes from address to address, so the
// logins raise nothing and, past the memory window, the member's typo still
// does not reach the breadth bar.
func TestMailSprayIPv6RotatingMemberKeepsTrustAcrossWindow(t *testing.T) {
	cfg := testSprayConfig()
	m, clock := newTestSpray(cfg)
	const stale = "2001:db8:1:2::d"
	ageTrust(t, m, clock, "2001:db8:1:2::100", "l@example.com")
	days := int(cfg.Window/(24*time.Hour)) + 3
	for day := 1; day <= days; day++ {
		clock.advance(24 * time.Hour)
		wantNoVerdict(t, m.Failure(stale, "x@example.com", mailboxExists))
		addr := fmt.Sprintf("2001:db8:1:2::%x", 0x100+day)
		if day == days {
			wantNoVerdict(t, m.Failure(addr, "l@example.com", mailboxExists))
		}
		if clean, v := m.Success(addr, "l@example.com"); !clean || v != nil {
			t.Fatalf("day %d login = (%v, %+v), want (true, nil)", day, clean, v)
		}
	}
}

// A login to a mailbox no address of the /64 trusts follows the usual rules,
// and an IPv4 address gets nothing from another address's trust.
func TestMailSprayRotatedLoginNeedsTrustOnThatMailbox(t *testing.T) {
	m, clock := newTestSpray(testSprayConfig())
	ageTrust(t, m, clock, "2001:db8:1:2::a", "l@example.com")
	corroborate(t, m, "nobody@example.com")
	wantNoVerdict(t, m.Failure("2001:db8:1:2::5", "nobody@example.com", mailboxMissing))
	clean, v := m.Success("2001:db8:1:2::b", "m@example.com")
	if clean {
		t.Fatal("login to an untrusted mailbox after a corroborated missing name was clean")
	}
	wantRule(t, v, sprayRuleCompromise, true)

	ageTrust(t, m, clock, "192.0.2.1", "l@example.com")
	wantNoVerdict(t, m.Failure("192.0.2.2", "x@example.com", mailboxExists))
	wantRule(t, m.Failure("192.0.2.2", "x2@example.com", mailboxExists), sprayRuleBreadth, true)
	clean, v = m.Success("192.0.2.2", "l@example.com")
	if clean {
		t.Fatal("IPv4 login borrowed another address's trust")
	}
	wantRule(t, v, sprayRuleWeakCompromise, false)
}

// A crack revoked anywhere in the /64 keeps the mailbox from earning trust
// through a sibling's aged trust.
func TestMailSprayIPv6RevokedMailboxNotCleanViaSibling(t *testing.T) {
	m, clock := newTestSpray(testSprayConfig())
	ageTrust(t, m, clock, "2001:db8:1:2::a", "l@example.com")
	m.RevokeTrust("2001:db8:1:2::b", "l@example.com")
	if clean, v := m.Success("2001:db8:1:2::c", "l@example.com"); clean || v != nil {
		t.Fatalf("login to a revoked mailbox = (%v, %+v), want (false, nil)", clean, v)
	}
}

// A crack drops the cracked mailbox's trust for every address of the /64, so
// a sibling's trust cannot excuse failures on it. Other mailboxes and other
// networks keep their trust.
func TestMailSprayIPv6RevocationDropsTrustAcross64(t *testing.T) {
	m, clock := newTestSpray(testSprayConfig())
	const a, b, other = "2001:db8:1:2::a", "2001:db8:1:2::b", "2001:db8:1:3::a"
	ageTrust(t, m, clock, a, "l@example.com", "o@example.com")
	ageTrust(t, m, clock, other, "l@example.com")
	m.RevokeTrust(b, "l@example.com")
	if m.TrustedAll(a, []string{"l@example.com"}) {
		t.Fatal("a sibling kept trust on the cracked mailbox")
	}
	if !m.TrustedAll(a, []string{"o@example.com"}) || !m.TrustedAll(other, []string{"l@example.com"}) {
		t.Fatal("the crack dropped unrelated trust")
	}
	wantNoVerdict(t, m.Failure(b, "l@example.com", mailboxExists))
	wantRule(t, m.Failure(b, "x@example.com", mailboxExists), sprayRuleBreadth, true)
}
