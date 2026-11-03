package daemon

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// countChecks counts findings whose check is one of checks.
func countChecks(findings []alert.Finding, checks ...string) int {
	n := 0
	for _, f := range findings {
		for _, c := range checks {
			if f.Check == c {
				n++
			}
		}
	}
	return n
}

// A sprayer that guesses one IMAP or POP password must not whitelist itself.
// A login that follows failures on other mailboxes earns no trust, so the
// walk still reaches the Critical slow block, not the advisory. The spray
// rules are off, so only the slow path can fire.
func TestMailSlowBruteNotExemptedBySuccessAfterSpray(t *testing.T) {
	const ip = "203.0.113.150"
	for _, proto := range []string{"imap", "pop3"} {
		t.Run(proto, func(t *testing.T) {
			d, clock := newPairingDaemon(t, sprayTestConfig("off"))
			var got []alert.Finding
			for i := 0; i < slowBruteWalkAccounts-1; i++ {
				clock.advance(8 * time.Minute)
				got = append(got, feed(d, clock, makeDovecotFailLine(proto, ip, walkedMailbox(i)))...)
			}
			if n := countChecks(got, "mail_bruteforce", "mail_bruteforce_suspected"); n != 0 {
				t.Fatalf("fired below the walk bar: %+v", got)
			}
			clock.advance(8 * time.Minute)
			feed(d, clock, makeDovecotSuccessLine(proto, ip, walkedMailbox(0)))
			clock.advance(8 * time.Minute)
			got = feed(d, clock, makeDovecotFailLine(proto, ip, walkedMailbox(slowBruteWalkAccounts-1)))
			if f, ok := findingByCheck(got, "mail_bruteforce_suspected"); ok {
				t.Fatalf("a login after the walk turned the slow block into an advisory: %+v", f)
			}
			f, ok := findingByCheck(got, "mail_bruteforce")
			if !ok || f.Severity != alert.Critical || !strings.Contains(f.Message, "across") {
				t.Fatalf("a login after the walk exempted it from the slow block: %+v", got)
			}
		})
	}
}

// Login trust vouches only for the mailboxes it names: a failure that names
// no mailbox keeps the slow block armed.
func TestMailSlowBruteTrustDoesNotHideUnnamedFailures(t *testing.T) {
	const ip = "203.0.113.162"
	clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTrackerWithSpray(t, clock)
	accounts := []string{"a@example.com", "b@example.com", "c@example.com"}
	for _, account := range accounts {
		tr.RecordSuccess(ip, account)
	}
	clock.advance(mailGoodSourceTTL + time.Hour) // only the login trust vouches

	var fired alert.Finding
	for i := 0; i < 40; i++ {
		account := accounts[i%len(accounts)]
		if i == 0 {
			account = ""
		}
		if got, ok := findingByCheck(tr.Record(ip, account), "mail_bruteforce"); ok {
			fired = got
		}
		clock.advance(8 * time.Minute)
	}
	if fired.Check == "" || !strings.Contains(fired.Message, "across") {
		t.Fatalf("a failure naming no mailbox was hidden by login trust: %+v", fired)
	}
}

// A login after a failure on another mailbox earns no 24h good standing
// either, in every spray mode; a clean login still does.
func TestMailSuccessAfterSprayEarnsNoGoodSource(t *testing.T) {
	const ip, clean = "203.0.113.151", "203.0.113.152"
	for _, mode := range []string{"off", "observe", "enforce"} {
		t.Run(mode, func(t *testing.T) {
			d, clock := newPairingDaemon(t, sprayTestConfig(mode))
			feed(d, clock, makeDovecotFailLine("imap", ip, "b@example.com"))
			got := feed(d, clock, makeDovecotSuccessLine("imap", ip, "a@example.com"))
			feed(d, clock, makeDovecotSuccessLine("imap", clean, "a@example.com"))

			snap := d.mailAuthTracker.ExportGoodSource()
			if _, ok := snap[ip]; ok {
				t.Fatalf("a login after spraying earned good standing: %+v", snap[ip])
			}
			if _, ok := snap[clean]["a@example.com"]; !ok {
				t.Fatalf("a clean login earned no good standing: %+v", snap)
			}
			if sprayHasTrust(d, ip, "a@example.com") || !sprayHasTrust(d, clean, "a@example.com") {
				t.Fatal("login trust does not match the login's history")
			}
			f, ok := findingByCheck(got, "mail_account_compromised")
			if ok != (mode != "off") {
				t.Fatalf("compromise finding = %v in mode %s: %+v", ok, mode, got)
			}
			if ok && (f.Severity != alert.High || f.SourceIP != ip || f.Mailbox != "a@example.com" || !strings.Contains(f.Message, "IMAP/POP")) {
				t.Fatalf("finding = %+v", f)
			}
		})
	}
}

// With the spray memory switched off, a login keeps its old good standing.
func TestMailSprayDisabledKeepsGoodSource(t *testing.T) {
	const ip = "203.0.113.156"
	d, clock := newPairingDaemon(t, &config.Config{})
	feed(d, clock, makeDovecotFailLine("imap", ip, "b@example.com"))
	if got := feed(d, clock, makeDovecotSuccessLine("imap", ip, "a@example.com")); len(got) != 0 {
		t.Fatalf("login raised findings: %+v", got)
	}
	if _, ok := d.mailAuthTracker.ExportGoodSource()[ip]["a@example.com"]; !ok {
		t.Fatal("disabled spray memory withheld good standing")
	}
}

func TestMailSprayBreadthIMAP(t *testing.T) {
	const ip = "203.0.113.153"
	for _, tc := range []struct {
		mode, check, prefix string
		sev                 alert.Severity
	}{
		{"enforce", "mail_bruteforce", "Mail auth brute force from " + ip + ": ", alert.Critical},
		{"observe", "mail_bruteforce_suspected", "Suspected IMAP/POP password spray from " + ip, alert.High},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			d, clock := newPairingDaemon(t, sprayTestConfig(tc.mode))
			if got := feed(d, clock, makeDovecotFailLine("imap", ip, "a@example.com")); len(got) != 0 {
				t.Fatalf("one mailbox raised findings: %+v", got)
			}
			got := feed(d, clock, makeDovecotFailLine("imap", ip, "b@example.com"))
			f, ok := findingByCheck(got, tc.check)
			if !ok {
				t.Fatalf("two untrusted mailboxes raised no %s: %+v", tc.check, got)
			}
			if f.Severity != tc.sev || f.SourceIP != ip || !strings.HasPrefix(f.Message, tc.prefix) ||
				!strings.Contains(f.Details, "Targets: a@example.com, b@example.com.") {
				t.Fatalf("finding = %+v", f)
			}
			if tc.mode == "observe" {
				if f, ok := findingByCheck(got, "mail_bruteforce"); ok {
					t.Fatalf("observe mode blocked: %+v", f)
				}
			}
		})
	}
}

// SMTP and IMAP/POP failures land in one memory: one failure on each side
// reaches the breadth bar once, on whichever side comes second.
func TestMailSpraySharedAcrossProtocols(t *testing.T) {
	const ip = "203.0.113.154"
	for name, src := range smtpLoginSources {
		for _, imapFirst := range []bool{false, true} {
			t.Run(name+"/imapFirst="+strconv.FormatBool(imapFirst), func(t *testing.T) {
				d, clock := newPairingDaemon(t, sprayTestConfig("enforce"))
				smtp := func() []alert.Finding { return src.feed(d, clock, src.failure(ip, "b@example.com")...) }
				imap := func() []alert.Finding { return feed(d, clock, makeDovecotFailLine("imap", ip, "c@example.com")) }
				first, second, want := smtp, imap, "mail_bruteforce"
				if imapFirst {
					first, second, want = imap, smtp, "smtp_bruteforce"
				}
				got := first()
				got = append(got, second()...)
				if n := countChecks(got, "smtp_bruteforce", "mail_bruteforce"); n != 1 {
					t.Fatalf("block findings = %d, want 1: %+v", n, got)
				}
				if f, ok := findingByCheck(got, want); !ok || !strings.Contains(f.Details, "Targets: b@example.com, c@example.com.") {
					t.Fatalf("breadth across protocols did not fire as %s: %+v", want, got)
				}
			})
		}
	}
}

// Every login fails during an auth outage, so outage traffic is no evidence.
func TestMailSprayOutageNotEvidence(t *testing.T) {
	const ip = "203.0.113.157"
	backendErr := `Jun 19 02:00:00 host dovecot[123]: auth-worker(alice@example.com,192.0.2.4)<1><a>: conn unix:...: ` +
		`socket error: Failed to connect to /usr/local/cpanel/var/cpdoveauthd.sock: connection refused`
	for _, tc := range []struct {
		name     string
		setup    func(*Daemon, *staticClock)
		evidence bool
	}{
		{"control", func(*Daemon, *staticClock) {}, true},
		{"backend probe down", func(d *Daemon, _ *staticClock) {
			d.mailAuthTracker.SetBackendDownCheck(func() bool { return true })
		}, false},
		{"backend errors in the log", func(d *Daemon, clock *staticClock) {
			var got []alert.Finding
			for i := 0; i < mailBackendDegradedThreshold; i++ {
				got = append(got, feed(d, clock, backendErr)...)
			}
			if _, ok := findingByCheck(got, "mail_auth_backend_degraded"); !ok {
				t.Fatalf("backend errors did not degrade the tracker: %+v", got)
			}
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, clock := newPairingDaemon(t, sprayTestConfig("enforce"))
			tc.setup(d, clock)
			got := feed(d, clock, makeDovecotFailLine("imap", ip, "a@example.com"), makeDovecotFailLine("imap", ip, "b@example.com"))
			_, blocked := findingByCheck(got, "mail_bruteforce")
			if n := d.mailSpray.Size(); blocked != tc.evidence || (n != 0) != tc.evidence {
				t.Fatalf("blocked = %v, spray IPs = %d, want evidence = %v", blocked, n, tc.evidence)
			}
		})
	}
}

// One Dovecot line can carry several attempts, each recorded on its own.
// However the per-IP, slow and spray paths line up, one source gets one
// mail_bruteforce per suppression window. The spray memory still records
// every failure.
func TestMailSprayOneBlockPerSource(t *testing.T) {
	const ip = "203.0.113.158"
	attempts := func(n, mailbox string) string {
		return strings.Replace(makeDovecotFailLine("imap", ip, mailbox), "1 attempts", n+" attempts", 1)
	}
	for _, tc := range []struct {
		name  string
		lines []string
	}{
		// The fifth failure crosses the per-IP bar and the second
		// mailbox the breadth bar in one call.
		{"same failure", []string{attempts("4", "a@example.com"), attempts("1", "b@example.com")}},
		// Spray fires on the first attempt of the line, the per-IP bar
		// on its fourth.
		{"spray first in one line", []string{attempts("1", "a@example.com"), attempts("5", "b@example.com")}},
		{"per-IP first, spray on a later line", []string{attempts("5", "a@example.com"), attempts("1", "b@example.com")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, clock := newPairingDaemon(t, sprayTestConfig("enforce"))
			got := feed(d, clock, tc.lines...)
			if n := countChecks(got, "mail_bruteforce"); n != 1 {
				t.Fatalf("mail_bruteforce findings = %d, want 1: %+v", n, got)
			}
			if ev := sprayEvidence(d, ip); len(ev) != 2 || ev["a@example.com"].count+ev["b@example.com"].count < 5 {
				t.Fatalf("spray evidence = %+v, want every attempt on both mailboxes", ev)
			}
		})
	}
}

// A login that trips both the short-window compromise rule and the spray
// rule raises one mail_account_compromised, the stronger of the two.
func TestMailSprayOneCompromisePerLogin(t *testing.T) {
	const ip = "203.0.113.159"
	d, clock := newPairingDaemon(t, sprayTestConfig("enforce"))
	feed(d, clock,
		makeDovecotFailLine("imap", ip, "a@example.com"),
		makeDovecotFailLine("imap", ip, "a@example.com"),
		makeDovecotFailLine("imap", ip, "b@example.com"))
	got := feed(d, clock, makeDovecotSuccessLine("imap", ip, "a@example.com"))
	if n := countChecks(got, "mail_account_compromised"); n != 1 {
		t.Fatalf("compromise findings = %d, want 1: %+v", n, got)
	}
	if f, _ := findingByCheck(got, "mail_account_compromised"); f.Severity != alert.Critical || f.Mailbox != "a@example.com" {
		t.Fatalf("finding = %+v", f)
	}
}

// IPv4-mapped IPv6 and plain IPv4 are one source for IMAP/POP too.
func TestMailSprayIPv4MappedKeysAsIPv4(t *testing.T) {
	d, clock := newPairingDaemon(t, sprayTestConfig("enforce"))
	feed(d, clock,
		makeDovecotFailLine("imap", "::ffff:203.0.113.160", "a@example.com"),
		makeDovecotSuccessLine("imap", "::ffff:203.0.113.161", "a@example.com"))
	if ev := sprayEvidence(d, "203.0.113.160"); len(ev) != 1 || d.mailSpray.Size() != 1 {
		t.Fatal("failure evidence not keyed by the IPv4 address")
	}
	if !sprayHasTrust(d, "203.0.113.161", "a@example.com") || d.mailSpray.TrustSize() != 1 {
		t.Fatal("login trust not keyed by the IPv4 address")
	}
}

// A mail client polls every few minutes. While a colleague's stale device
// keeps one failure on another mailbox in memory, a login raises the weak
// compromise advisory once per mailbox per memory window, not once per
// suppression period.
func TestMailSprayWeakCompromiseOncePerMailbox(t *testing.T) {
	const ip = "203.0.113.163"
	cfg := sprayTestConfig("enforce")
	d, clock := newPairingDaemon(t, cfg)
	logins := func(mailbox string, n int) int {
		got := 0
		for range n {
			clock.advance(time.Hour)
			for _, f := range feed(d, clock, makeDovecotSuccessLine("imap", ip, mailbox)) {
				if f.Check == "mail_account_compromised" {
					if !strings.HasPrefix(f.Message, "Possible mail account compromise: ") || f.Mailbox != mailbox {
						t.Fatalf("finding = %+v", f)
					}
					got++
				}
			}
		}
		return got
	}
	feed(d, clock, makeDovecotFailLine("imap", ip, "x@example.com"))
	if n := logins("y@example.com", 10); n != 1 {
		t.Fatalf("weak advisories for y@example.com = %d over 10 hourly logins, want 1", n)
	}
	if n := logins("z@example.com", 2); n != 1 {
		t.Fatalf("weak advisories for z@example.com = %d, want its own 1", n)
	}
	if d.mailSpray.TrustSize() != 0 {
		t.Fatal("deduplicated logins earned trust")
	}
	clock.advance(time.Duration(cfg.Thresholds.MailSprayWindowMin) * time.Minute)
	feed(d, clock, makeDovecotFailLine("imap", ip, "x@example.com"))
	if n := logins("y@example.com", 1); n != 1 {
		t.Fatalf("weak advisories after the window with a fresh failure = %d, want 1", n)
	}
}

// A brute-forcer that cracks the one mailbox it hammered must not earn login
// trust on it, whether the compromise finding fires or is suppressed. A login
// with no failures before it still does.
func TestMailCrackedMailboxEarnsNoTrust(t *testing.T) {
	const ip, clean = "203.0.113.164", "203.0.113.165"
	cfg := sprayTestConfig("enforce")
	d, clock := newPairingDaemon(t, cfg)
	crack := func() []alert.Finding {
		feed(d, clock, makeDovecotFailLine("imap", ip, "a@example.com"), makeDovecotFailLine("imap", ip, "a@example.com"))
		return feed(d, clock, makeDovecotSuccessLine("imap", ip, "a@example.com"))
	}
	if f, ok := findingByCheck(crack(), "mail_account_compromised"); !ok || f.Severity != alert.Critical {
		t.Fatalf("crack raised no Critical compromise: %+v", f)
	}
	if f, ok := findingByCheck(crack(), "mail_account_compromised"); ok {
		t.Fatalf("second crack inside suppression raised a finding: %+v", f)
	}
	feed(d, clock, makeDovecotSuccessLine("imap", clean, "a@example.com"))
	clock.advance(time.Duration(cfg.Thresholds.SMTPBruteForceWindowMin+1) * time.Minute) // past TrustAge
	if d.mailSpray.TrustedAll(ip, []string{"a@example.com"}) {
		t.Fatal("cracked mailbox earned login trust")
	}
	if !d.mailSpray.TrustedAll(clean, []string{"a@example.com"}) {
		t.Fatal("a login with no failures earned no trust")
	}
}
