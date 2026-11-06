package daemon

import (
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/platform"
)

// recordingMailboxResolver notes every name it is asked about.
type recordingMailboxResolver struct {
	mailboxResolver
	asked []string
}

func (r *recordingMailboxResolver) Resolve(name string) sprayMailbox {
	r.asked = append(r.asked, name)
	return r.mailboxResolver.Resolve(name)
}

type fixedMailboxResolver sprayMailbox

func (f fixedMailboxResolver) Resolve(string) sprayMailbox { return sprayMailbox(f) }

// newLookupDaemon is a daemon on a cPanel host holding info@ and sales@
// example.com, with the name asked about recorded.
func newLookupDaemon(t *testing.T, mode string) (*Daemon, *staticClock, *recordingMailboxResolver) {
	t.Helper()
	d, clock := newPairingDaemon(t, sprayTestConfig(mode))
	r := &recordingMailboxResolver{mailboxResolver: newCPanelMailboxResolver(newFakeMailboxSource(), clock.Now)}
	d.mailboxes = r
	return d, clock, r
}

// sprayFailureFeeds drive one failed login through each log handler. check is
// the finding an enforce mode block raises there.
var sprayFailureFeeds = map[string]struct {
	check string
	fail  func(d *Daemon, clock *staticClock, ip, mailbox string) []alert.Finding
}{
	"exim": {"smtp_bruteforce", func(d *Daemon, clock *staticClock, ip, mailbox string) []alert.Finding {
		return feedExim(d, clock, makeEximDovecotFailLine(ip, mailbox))
	}},
	"imap": {"mail_bruteforce", func(d *Daemon, clock *staticClock, ip, mailbox string) []alert.Finding {
		return feed(d, clock, makeDovecotFailLine("imap", ip, mailbox))
	}},
}

// sprayLookupIPs are three networks, then a further address on the third.
var sprayLookupIPs = []string{"192.0.2.71", "198.51.100.71", "203.0.113.71", "203.0.113.72"}

func TestResolveSprayMailboxVerdictWins(t *testing.T) {
	const name, key = "InOf@Example.COM", "inof@example.com"
	typo := sprayMailbox{name: "info@example.com", exist: mailboxExists}
	missing := sprayMailbox{name: key, exist: mailboxMissing}
	for _, row := range []struct {
		desc    string
		verdict mailboxExistence
		answer  sprayMailbox
		want    sprayMailbox
		asked   int
	}{
		{"a stale resolver cannot overturn a verdict of exists", mailboxExists, missing, sprayMailbox{name: key, exist: mailboxExists}, 0},
		{"a typo overturns a verdict of missing", mailboxMissing, typo, typo, 1},
		{"the name itself existing does not", mailboxMissing, sprayMailbox{name: key, exist: mailboxExists}, missing, 1},
		{"unknown does not either", mailboxMissing, sprayMailbox{name: key}, missing, 1},
		{"no verdict takes a missing answer", mailboxExistenceUnknown, missing, missing, 1},
		{"no verdict takes a typo", mailboxExistenceUnknown, typo, typo, 1},
		{"no verdict takes unknown", mailboxExistenceUnknown, sprayMailbox{name: key}, sprayMailbox{name: key}, 1},
	} {
		t.Run(row.desc, func(t *testing.T) {
			r := &recordingMailboxResolver{mailboxResolver: fixedMailboxResolver(row.answer)}
			if got := resolveSprayMailbox(r, name, row.verdict); got != row.want {
				t.Fatalf("got %+v, want %+v", got, row.want)
			}
			if len(r.asked) != row.asked {
				t.Fatalf("resolver asked %d times, want %d", len(r.asked), row.asked)
			}
			// Normalising first would hide a cut name from the resolver.
			if row.asked == 1 && r.asked[0] != name {
				t.Fatalf("resolver asked about %q, want the name as typed", r.asked[0])
			}
		})
	}
	for _, verdict := range []mailboxExistence{mailboxExistenceUnknown, mailboxExists, mailboxMissing} {
		want := sprayMailbox{name: key, exist: verdict}
		if got := resolveSprayMailbox(nil, name, verdict); got != want {
			t.Errorf("nil resolver: got %+v, want %+v", got, want)
		}
	}
}

// checkSprayFirstStrike feeds one name from sprayLookupIPs. On a Missing answer
// the third network reaches the bar and the address after it is past it, so
// both are blocked. The same feed on an Exists answer blocks neither, so the
// first strike comes from the answer.
func checkSprayFirstStrike(t *testing.T, proto string) {
	t.Helper()
	src := sprayFailureFeeds[proto]
	t.Run("missing", func(t *testing.T) {
		const mailbox = "nosuch@example.com"
		d, clock, _ := newLookupDaemon(t, "enforce")
		for i, ip := range sprayLookupIPs {
			got := src.fail(d, clock, ip, mailbox)
			if exist := sprayEvidence(d, ip)[mailbox].exist; exist != mailboxMissing {
				t.Fatalf("attempt %d stored existence %d, want missing", i+1, exist)
			}
			f, ok := findingByCheck(got, src.check)
			if i < 2 {
				if ok {
					t.Fatalf("attempt %d blocked before enough networks tried the name: %+v", i+1, f)
				}
				continue
			}
			if !ok {
				t.Fatalf("attempt %d on a missing mailbox was not blocked: %+v", i+1, got)
			}
			if f.Severity != alert.Critical || f.SourceIP != ip || f.BlockTTL <= 0 ||
				!strings.Contains(f.Message, "failed login to missing mailbox "+mailbox+", tried by 3 networks") {
				t.Fatalf("attempt %d finding = %+v", i+1, f)
			}
		}
	})
	t.Run("exists", func(t *testing.T) {
		const mailbox = "info@example.com"
		d, clock, _ := newLookupDaemon(t, "enforce")
		for i, ip := range sprayLookupIPs {
			got := src.fail(d, clock, ip, mailbox)
			if n := countChecks(got, src.check, "mail_bruteforce_suspected"); n != 0 {
				t.Fatalf("attempt %d on a real mailbox was a first strike: %+v", i+1, got)
			}
			if exist := sprayEvidence(d, ip)[mailbox].exist; exist != mailboxExists {
				t.Fatalf("attempt %d stored existence %d, want exists", i+1, exist)
			}
		}
		if names := d.mailSpray.Export().Networks; len(names) != 0 {
			t.Fatalf("a real mailbox was corroborated as missing: %+v", names)
		}
	})
}

func TestEximSprayMissingMailboxOnCPanel(t *testing.T) { checkSprayFirstStrike(t, "exim") }

func TestIMAPSprayMissingMailboxOnCPanel(t *testing.T) { checkSprayFirstStrike(t, "imap") }

func TestSprayTypoOfTrustedMailboxExcused(t *testing.T) {
	const ip = "203.0.113.74"
	for proto, src := range sprayFailureFeeds {
		t.Run(proto, func(t *testing.T) {
			d, clock, _ := newLookupDaemon(t, "enforce")
			feedExim(d, clock, eximLoginLine(ip, "info@example.com"))
			if !sprayHasTrust(d, ip, "info@example.com") {
				t.Fatal("the login earned no trust")
			}
			clock.advance(11 * time.Minute) // trust ages past the failure window
			got := src.fail(d, clock, ip, "inof@example.com")
			got = append(got, src.fail(d, clock, ip, "info@example.com")...)
			if n := countChecks(got, src.check, "mail_bruteforce_suspected"); n != 0 {
				t.Fatalf("a customer's typo drew a verdict: %+v", got)
			}
			evidence := sprayEvidence(d, ip)
			if f, ok := evidence["info@example.com"]; !ok || len(evidence) != 1 || f.count != 2 || f.exist != mailboxExists {
				t.Fatalf("evidence = %+v, want both failures on info@example.com", evidence)
			}
		})
	}
}

func TestSprayTypoNeverFirstStrikes(t *testing.T) {
	for proto, src := range sprayFailureFeeds {
		t.Run(proto, func(t *testing.T) {
			d, clock, _ := newLookupDaemon(t, "enforce")
			for i, ip := range sprayLookupIPs {
				got := src.fail(d, clock, ip, "inof@example.com")
				if n := countChecks(got, src.check, "mail_bruteforce_suspected"); n != 0 {
					t.Fatalf("attempt %d on a typo was a first strike: %+v", i+1, got)
				}
				if f, ok := sprayEvidence(d, ip)["info@example.com"]; !ok || f.exist != mailboxExists {
					t.Fatalf("attempt %d evidence = %+v, want the real mailbox", i+1, sprayEvidence(d, ip))
				}
			}
			if names := d.mailSpray.Export().Networks; len(names) != 0 {
				t.Fatalf("a typo was corroborated as missing: %+v", names)
			}
		})
	}
}

// Only spray memory follows a typo to the real mailbox: the rate trackers and
// their alerts name what the client sent.
func TestSprayTypoKeepsTypedNameInTrackers(t *testing.T) {
	const ip, typed = "203.0.113.75", "inof@example.com"
	d, clock, _ := newLookupDaemon(t, "enforce")
	feedExim(d, clock, makeEximDovecotFailLine(ip, typed))
	feed(d, clock, makeDovecotFailLine("imap", ip, typed))
	if _, ok := d.smtpAuthTracker.accounts[typed]; !ok {
		t.Errorf("SMTP tracker accounts = %v, want the typed name", d.smtpAuthTracker.accounts)
	}
	if _, ok := d.mailAuthTracker.accounts[typed]; !ok {
		t.Errorf("mail tracker accounts = %v, want the typed name", d.mailAuthTracker.accounts)
	}
	if _, ok := d.mailAuthTracker.ips[ip].failedAccounts[typed]; !ok {
		t.Errorf("mail tracker failures = %v, want the typed name", d.mailAuthTracker.ips[ip].failedAccounts)
	}
}

func TestSprayLookupOffWhenModeOff(t *testing.T) {
	const ip, typed = "203.0.113.76", "Nosuch@Example.COM"
	d, clock, r := newLookupDaemon(t, "off")
	for _, src := range sprayFailureFeeds {
		src.fail(d, clock, ip, typed)
	}
	want := sprayMailbox{name: "nosuch@example.com", exist: mailboxMissing}
	if got := d.sprayMailboxFor(typed, mailboxMissing); got != want {
		t.Errorf("mode off: got %+v, want %+v", got, want)
	}
	d.mailSpray = nil
	if got := d.sprayMailboxFor(typed, mailboxMissing); got != want {
		t.Errorf("no spray memory: got %+v, want %+v", got, want)
	}
	if len(r.asked) != 0 {
		t.Fatalf("resolver called with the spray rules off: %q", r.asked)
	}
}

// A line costs one lookup however many attempts it reports, and asks about the
// name as typed. A temporary reply says nothing about the mailbox and costs none.
func TestSprayLookupOncePerLine(t *testing.T) {
	const ip = "203.0.113.77"
	d, clock, r := newLookupDaemon(t, "observe")
	feedExim(d, clock, makeEximDovecotFailLine(ip, "Info@Example.COM"))
	feedExim(d, clock, strings.Replace(makeEximDovecotFailLine(ip, "sales@example.com"),
		"535 Incorrect authentication data", "435 Unable to authenticate at present", 1))
	feed(d, clock, strings.Replace(makeDovecotFailLine("imap", ip, "Sales@Example.COM"), "1 attempts", "3 attempts", 1))
	if want := []string{"Info@Example.COM", "Sales@Example.COM"}; !slices.Equal(r.asked, want) {
		t.Fatalf("resolver asked about %q, want %q", r.asked, want)
	}
	if calls, _ := d.mailAuthTracker.Stats(); calls != 3 {
		t.Fatalf("mail tracker recorded %d attempts, want 3", calls)
	}
}

// lockProbeResolver records each lock held during a lookup. The handlers run on
// one goroutine, so a lock TryLock cannot take is one that goroutine holds.
type lockProbeResolver struct {
	locks map[string]*sync.Mutex
	calls int
	held  []string
}

func (p *lockProbeResolver) Resolve(name string) sprayMailbox {
	p.calls++
	for which, mu := range p.locks {
		if !mu.TryLock() {
			p.held = append(p.held, which)
			continue
		}
		mu.Unlock()
	}
	return sprayMailbox{name: normalizeSprayMailbox(name)}
}

func TestSprayLookupHoldsNoTrackerLock(t *testing.T) {
	d, clock := newPairingDaemon(t, sprayTestConfig("enforce"))
	probe := &lockProbeResolver{locks: map[string]*sync.Mutex{
		"smtp":  &d.smtpAuthTracker.mu,
		"mail":  &d.mailAuthTracker.mu,
		"spray": &d.mailSpray.mu,
	}}
	d.mailboxes = probe
	for _, src := range sprayFailureFeeds {
		src.fail(d, clock, "203.0.113.78", "nosuch@example.com")
	}
	if probe.calls != len(sprayFailureFeeds) || len(probe.held) != 0 {
		t.Fatalf("calls = %d, locks held during a lookup: %v", probe.calls, probe.held)
	}
}

func TestSprayLookupOwnedOnCPanelOnly(t *testing.T) {
	for panel, want := range map[platform.Panel]bool{platform.PanelCPanel: true, platform.PanelNone: false} {
		t.Run("panel="+string(panel), func(t *testing.T) {
			usePanel(t, panel)
			if got := New(sprayTestConfig("observe"), nil, nil, "").mailboxes != nil; got != want {
				t.Fatalf("resolver present = %v, want %v", got, want)
			}
		})
	}
}
