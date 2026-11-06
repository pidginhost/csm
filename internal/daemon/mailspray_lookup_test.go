package daemon

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
	"github.com/pidginhost/csm/internal/store"
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

// An address with no trust that mistypes a mailbox and then gets it right tried
// one mailbox, so it stays under a breadth bar of two.
func TestSprayTypoThenRealNameIsOneMailbox(t *testing.T) {
	const ip = "203.0.113.73"
	for proto, src := range sprayFailureFeeds {
		t.Run(proto, func(t *testing.T) {
			d, clock, _ := newLookupDaemon(t, "enforce")
			got := src.fail(d, clock, ip, "inof@example.com")
			got = append(got, src.fail(d, clock, ip, "info@example.com")...)
			if n := countChecks(got, src.check, "mail_bruteforce_suspected"); n != 0 {
				t.Fatalf("one mailbox drew a verdict: %+v", got)
			}
			evidence := sprayEvidence(d, ip)
			if f, ok := evidence["info@example.com"]; !ok || len(evidence) != 1 || f.count != 2 || f.exist != mailboxExists {
				t.Fatalf("evidence = %+v, want both failures on info@example.com", evidence)
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

// useAccountKey installs a mail_brute_account_key for one test.
func useAccountKey(t *testing.T, spec string) {
	t.Helper()
	ex, err := NewAccountExtractor(spec)
	if err != nil {
		t.Fatal(err)
	}
	SetAccountExtractor(ex)
	t.Cleanup(func() { SetAccountExtractor(nil) })
}

// Only the default key reads the whole login. A regex can capture part of it,
// and bare info is a missing account though info@example.com is real, so the
// failure must count as unknown and never reach the first strike.
func TestSprayLookupNeedsWholeLoginName(t *testing.T) {
	for _, tc := range []struct{ key, stored string }{
		{"regex:user=<([^@>]+)", "info"},
		{"regex:user=<([^>]+)>", "info@example.com"},
		{"builtin:postfix-sasl", ""}, // a Dovecot login line has no such field
	} {
		t.Run(tc.key, func(t *testing.T) {
			useAccountKey(t, tc.key)
			d, clock, r := newLookupDaemon(t, "enforce")
			for i, ip := range sprayLookupIPs {
				got := feed(d, clock, makeDovecotFailLine("imap", ip, "info@example.com"))
				if n := countChecks(got, "mail_bruteforce", "mail_bruteforce_suspected"); n != 0 {
					t.Fatalf("attempt %d was a first strike: %+v", i+1, got)
				}
			}
			for _, ip := range sprayLookupIPs {
				if f, ok := sprayEvidence(d, ip)[tc.stored]; tc.stored != "" && (!ok || f.count != 1 || f.exist != mailboxExistenceUnknown) {
					t.Fatalf("evidence of %s = %+v, want one unknown failure on %q", ip, sprayEvidence(d, ip), tc.stored)
				}
			}
			if calls, _ := d.mailAuthTracker.Stats(); calls != int64(len(sprayLookupIPs)) {
				t.Fatalf("mail tracker recorded %d attempts, want %d", calls, len(sprayLookupIPs))
			}
			if len(r.asked) != 0 {
				t.Fatalf("resolver asked about %q", r.asked)
			}
		})
	}
}

func TestSprayLookupStrikesOnDefaultAccountKey(t *testing.T) {
	for _, key := range []string{"", "builtin:dovecot-user"} {
		t.Run("key="+key, func(t *testing.T) {
			useAccountKey(t, key)
			checkSprayFirstStrike(t, "imap")
		})
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
			if got := newMailboxResolver(platform.Info{Panel: panel}) != nil; got != want {
				t.Fatalf("resolver present = %v, want %v", got, want)
			}
		})
	}
}

// The log readers are what ask, so they start with the resolver set.
func TestSprayLookupWiredWithLogReaders(t *testing.T) {
	for panel, want := range map[platform.Panel]bool{platform.PanelCPanel: true, platform.PanelNone: false} {
		t.Run("panel="+string(panel), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "mail.log")
			if err := os.WriteFile(path, nil, 0600); err != nil {
				t.Fatal(err)
			}
			server := platform.WSNone
			platform.ResetForTest()
			platform.SetOverrides(platform.Overrides{Panel: &panel, WebServer: &server})
			t.Cleanup(platform.ResetForTest)
			cfg := sprayTestConfig("observe")
			cfg.MailLogs = config.MailLogsConfig{Source: "file", File: path}
			previous := config.Active()
			config.SetActive(cfg)
			t.Cleanup(func() { config.SetActive(previous) })
			d := New(cfg, nil, nil, "")
			d.staleSession401 = newStaleSession401s()
			d.startLogWatchers()
			t.Cleanup(func() {
				close(d.stopCh)
				d.wg.Wait()
			})
			if got := d.mailboxes != nil; got != want {
				t.Fatalf("resolver present = %v, want %v", got, want)
			}
		})
	}
}

func TestSprayLookupPreservesPlatformStartupOrder(t *testing.T) {
	platform.ResetForTest()
	t.Cleanup(platform.ResetForTest)
	cfg := sprayTestConfig("observe")
	cfg.WebServer.Type = "nginx"
	cfg.WebServer.AccessLogs = []string{"/var/log/example/access.log"}
	New(cfg, nil, nil, "")
	if !platform.SetOverrides(PlatformOverridesFrom(cfg)) {
		t.Fatal("constructing the daemon cached detection before startup could install overrides")
	}
	if got := platform.Detect(); got.WebServer != platform.WSNginx || !slices.Equal(got.AccessLogPaths, cfg.WebServer.AccessLogs) {
		t.Fatalf("startup lost configured web server or log paths: %+v", got)
	}
}

func TestSprayLookupKeepsTrustForTrailingDomainDot(t *testing.T) {
	const ip = "203.0.113.79"
	for proto, src := range sprayFailureFeeds {
		t.Run(proto, func(t *testing.T) {
			d, clock, _ := newLookupDaemon(t, "enforce")
			for _, mailbox := range []string{"info@example.com.", "sales@example.com."} {
				feedExim(d, clock, eximLoginLine(ip, mailbox))
			}
			clock.advance(11 * time.Minute)
			var got []alert.Finding
			for _, mailbox := range []string{"info@example.com.", "sales@example.com."} {
				got = append(got, src.fail(d, clock, ip, mailbox)...)
			}
			if n := countChecks(got, src.check, "mail_bruteforce_suspected"); n != 0 {
				t.Fatalf("failures on the same trusted names drew a spray verdict: %+v", got)
			}
		})
	}
}

func TestSprayLookupRestoresTrailingDomainDotTrust(t *testing.T) {
	const ip = "203.0.113.79"
	d, clock, _ := newLookupDaemon(t, "enforce")
	first, last := clock.Now().Add(-time.Hour), clock.Now()
	loadSpraySnapshot(t, d.mailSpray, store.MailSprayState{
		Trust: map[string]map[string]store.GoodSourcePair{ip: {
			"info@example.com.": {First: first, Last: last},
		}},
		IPs: map[string]store.MailSprayIP{ip: {
			Failed: map[string]store.MailSprayFailure{
				"info@example.com.": {First: last, Last: last, Count: 1, Exist: uint8(mailboxExists)},
			},
			LastSeen: last,
		}},
	})
	if !d.mailSpray.TrustedAll(ip, []string{"info@example.com"}) {
		t.Fatal("saved login trust did not follow the canonical mailbox")
	}
	got := feedExim(d, clock, makeEximDovecotFailLine(ip, "info@example.com."))
	if n := countChecks(got, "smtp_bruteforce", "mail_bruteforce_suspected"); n != 0 {
		t.Fatalf("a repeated failure on the restored mailbox drew a spray verdict: %+v", got)
	}
	evidence := sprayEvidence(d, ip)
	if f, ok := evidence["info@example.com"]; !ok || len(evidence) != 1 || f.count != 2 || f.exist != mailboxExists {
		t.Fatalf("evidence = %+v, want one mailbox with both failures", evidence)
	}
}
