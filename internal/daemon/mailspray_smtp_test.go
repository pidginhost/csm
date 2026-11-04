package daemon

import (
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// sprayTestConfig turns the spray rules on in mode, with trust aging past
// the test tracker's fast window.
func sprayTestConfig(mode string) *config.Config {
	cfg := &config.Config{}
	th := &cfg.Thresholds
	th.SMTPBruteForceWindowMin = 10
	th.SMTPBruteForceSuppressMin = 60
	th.MailSprayMode = mode
	th.MailSprayWindowMin = 7 * 24 * 60
	th.MailSprayBreadthMailboxes = 2
	th.MailSprayMissingNetworks = 3
	return cfg
}

// feedExim hands each line to the Exim handler one second apart.
func feedExim(d *Daemon, clock *staticClock, lines ...string) []alert.Finding {
	var got []alert.Finding
	for _, line := range lines {
		clock.advance(time.Second)
		got = append(got, d.handleEximLine(line, alert.Observation{}, d.currentCfg())...)
	}
	return got
}

// eximLoginLine is an authenticated Exim arrival for user from ip.
func eximLoginLine(ip, user string) string {
	return fmt.Sprintf(`2026-04-14 12:00:00 1abc-DEF-01 <= sender@example.com H=(client.example) [%s]:54321 P=esmtpsa A=dovecot_login:%s S=1200`, ip, user)
}

func postfixLoginLine(ip, user string) string {
	return "postfix/smtpd[99]: 4ABC123: client=unknown[" + ip + "], sasl_method=PLAIN, sasl_username=" + user
}

// smtpLoginSource drives one SMTP log family: a failed and a successful
// login for a mailbox from an address.
type smtpLoginSource struct {
	feed    func(*Daemon, *staticClock, ...string) []alert.Finding
	failure func(ip, mailbox string) []string
	login   func(ip, mailbox string) []string
}

var smtpLoginSources = map[string]smtpLoginSource{
	"postfix": {
		feed: feed,
		failure: func(ip, mailbox string) []string {
			return []string{"dovecot: auth: sql(" + mailbox + "," + ip + "): Password mismatch", fmt.Sprintf(postfixFailFmt, ip, mailbox)}
		},
		login: func(ip, mailbox string) []string { return []string{postfixLoginLine(ip, mailbox)} },
	},
	"exim": {
		feed:    feedExim,
		failure: func(ip, mailbox string) []string { return []string{makeEximDovecotFailLine(ip, mailbox)} },
		login:   func(ip, mailbox string) []string { return []string{eximLoginLine(ip, mailbox)} },
	},
}

func walkedMailbox(i int) string { return fmt.Sprintf("user%02d@example.com", i) }

// A sprayer that guesses one password must not whitelist itself. A login
// that follows failures on other mailboxes earns no trust, so the walk still
// reaches the slow block. The spray rules are off, so only the slow path can
// fire.
func TestSMTPSlowBruteNotExemptedBySuccessAfterSpray(t *testing.T) {
	const ip = "203.0.113.60"
	for name, src := range smtpLoginSources {
		t.Run(name, func(t *testing.T) {
			d, clock := newPairingDaemon(t, sprayTestConfig("off"))
			var got []alert.Finding
			for i := 0; i < slowBruteWalkAccounts-1; i++ {
				clock.advance(8 * time.Minute)
				got = append(got, src.feed(d, clock, src.failure(ip, walkedMailbox(i))...)...)
			}
			if f, ok := findingByCheck(got, "smtp_bruteforce"); ok {
				t.Fatalf("fired below the walk bar: %+v", f)
			}
			clock.advance(8 * time.Minute)
			src.feed(d, clock, src.login(ip, walkedMailbox(0))...)
			clock.advance(8 * time.Minute)
			got = src.feed(d, clock, src.failure(ip, walkedMailbox(slowBruteWalkAccounts-1))...)
			f, ok := findingByCheck(got, "smtp_bruteforce")
			if !ok || !strings.Contains(f.Message, "across") {
				t.Fatalf("a login after the walk exempted it from the slow block: %+v", got)
			}
		})
	}
}

// sprayHasTrust reports whether the spray memory holds login trust for the
// pair, aged or not.
func sprayHasTrust(d *Daemon, ip, mailbox string) bool {
	d.mailSpray.mu.Lock()
	defer d.mailSpray.mu.Unlock()
	_, ok := d.mailSpray.trust[sprayTrustKey{ip, mailbox}]
	return ok
}

// sprayEvidence copies the failure names the spray memory holds for ip.
func sprayEvidence(d *Daemon, ip string) map[string]sprayFailure {
	d.mailSpray.mu.Lock()
	defer d.mailSpray.mu.Unlock()
	out := map[string]sprayFailure{}
	if e := d.mailSpray.ips[ip]; e != nil {
		for name, f := range e.failed {
			out[name] = f
		}
	}
	return out
}

// An office whose devices log in to every mailbox it later fails on keeps
// its stale saved passwords out of the slow block. Trust matches across the
// spelling of the success and failure logs. One failure on a mailbox it never
// logged in to ends the exemption.
func TestSMTPSlowBruteExemptedForTrustedMailboxes(t *testing.T) {
	const ip = "203.0.113.61"
	for name, src := range smtpLoginSources {
		t.Run(name, func(t *testing.T) {
			d, clock := newPairingDaemon(t, sprayTestConfig("enforce"))
			for i := 0; i < slowBruteWalkAccounts; i++ {
				if got := src.feed(d, clock, src.login(ip, walkedMailbox(i))...); len(got) != 0 {
					t.Fatalf("clean login raised findings: %+v", got)
				}
			}
			clock.advance(11 * time.Minute) // trust ages past the failure window
			var got []alert.Finding
			for i := 0; i < slowBruteWalkAccounts; i++ {
				clock.advance(8 * time.Minute)
				got = append(got, src.feed(d, clock, src.failure(ip, strings.ToUpper(walkedMailbox(i)))...)...)
			}
			if f, ok := findingByCheck(got, "smtp_bruteforce"); ok {
				t.Fatalf("failures on trusted mailboxes reached a block: %+v", f)
			}
			clock.advance(8 * time.Minute)
			got = src.feed(d, clock, src.failure(ip, walkedMailbox(slowBruteWalkAccounts))...)
			f, ok := findingByCheck(got, "smtp_bruteforce")
			if !ok || !strings.Contains(f.Message, "across") {
				t.Fatalf("an untrusted mailbox in the walk did not end the exemption: %+v", got)
			}
		})
	}
}

// postfixMissingMailboxFindings has three networks try one mailbox that
// Dovecot does not know, and returns each attempt's findings.
func postfixMissingMailboxFindings(t *testing.T, mode string) [][]alert.Finding {
	t.Helper()
	d, clock := newPairingDaemon(t, sprayTestConfig(mode))
	const ghost = "ghost@example.com"
	var out [][]alert.Finding
	for _, ip := range []string{"192.0.2.70", "198.51.100.70", "203.0.113.70"} {
		out = append(out, feed(d, clock,
			"dovecot: auth: sql("+ghost+","+ip+"): unknown user",
			fmt.Sprintf(postfixFailFmt, ip, ghost)))
	}
	return out
}

func TestSMTPSprayPostfixMissingMailbox(t *testing.T) {
	attempts := postfixMissingMailboxFindings(t, "enforce")
	for i, got := range attempts[:2] {
		if f, ok := findingByCheck(got, "smtp_bruteforce"); ok {
			t.Fatalf("attempt %d blocked before enough networks tried the name: %+v", i+1, f)
		}
	}
	f, ok := findingByCheck(attempts[2], "smtp_bruteforce")
	if !ok {
		t.Fatalf("third network on a missing mailbox was not blocked: %+v", attempts[2])
	}
	if f.Severity != alert.Critical || f.SourceIP != "203.0.113.70" ||
		!strings.HasPrefix(f.Message, "SMTP brute force from 203.0.113.70: ") ||
		!strings.Contains(f.Message, "ghost@example.com") {
		t.Fatalf("finding = %+v", f)
	}
}

func TestSMTPSprayObserveModeEmitsSuspected(t *testing.T) {
	attempts := postfixMissingMailboxFindings(t, "observe")
	for i, got := range attempts {
		if f, ok := findingByCheck(got, "smtp_bruteforce"); ok {
			t.Fatalf("observe mode blocked attempt %d: %+v", i+1, f)
		}
	}
	f, ok := findingByCheck(attempts[2], "mail_bruteforce_suspected")
	if !ok {
		t.Fatalf("observe mode reported nothing: %+v", attempts[2])
	}
	if f.Severity != alert.High || f.SourceIP != "203.0.113.70" || f.Mailbox != "" ||
		!strings.Contains(f.Message, "SMTP") || !strings.Contains(f.Message, "observe mode") {
		t.Fatalf("finding = %+v", f)
	}
}

func TestSMTPSprayEximBreadth(t *testing.T) {
	const ip = "203.0.113.62"
	d, clock := newPairingDaemon(t, sprayTestConfig("enforce"))
	if f, ok := findingByCheck(feedExim(d, clock, makeEximDovecotFailLine(ip, "a@example.com")), "smtp_bruteforce"); ok {
		t.Fatalf("one mailbox reached the breadth block: %+v", f)
	}
	got := feedExim(d, clock, makeEximDovecotFailLine(ip, "b@example.com"))
	f, ok := findingByCheck(got, "smtp_bruteforce")
	if !ok {
		t.Fatalf("two untrusted mailboxes were not blocked: %+v", got)
	}
	if f.Severity != alert.Critical || f.SourceIP != ip || !strings.HasPrefix(f.Message, "SMTP brute force from "+ip+": ") ||
		!strings.Contains(f.Details, "Targets: a@example.com, b@example.com.") {
		t.Fatalf("finding = %+v", f)
	}
}

func TestSMTPSprayEximSuccessAfterSprayAdvisory(t *testing.T) {
	const ip = "203.0.113.63"
	d, clock := newPairingDaemon(t, sprayTestConfig("enforce"))
	feedExim(d, clock, makeEximDovecotFailLine(ip, "b@example.com"))
	got := feedExim(d, clock, eximLoginLine(ip, "a@example.com"))
	f, ok := findingByCheck(got, "mail_account_compromised")
	if !ok {
		t.Fatalf("login after a failure on another mailbox raised nothing: %+v", got)
	}
	if f.Severity != alert.High || f.SourceIP != ip || f.Mailbox != "a@example.com" || f.Domain != "example.com" {
		t.Fatalf("finding = %+v", f)
	}
	if !slices.Contains(f.Claims, admission.Claim{Kind: admission.ClaimMailbox, Value: "a@example.com"}) {
		t.Fatalf("finding was not stamped with its mailbox claim: %+v", f.Claims)
	}
	if sprayHasTrust(d, ip, "a@example.com") {
		t.Fatal("a login after spraying earned trust")
	}
}

// The failure log and the success log spell one mailbox differently; both
// must land on one key, or a user's own login would look like a spray.
func TestSMTPSprayCrossSourceMailboxKey(t *testing.T) {
	cases := map[string]struct {
		ip, key  string
		failures []string
		login    string
	}{
		"exim": {
			ip: "203.0.113.64", key: "alice@example.com",
			failures: []string{makeEximDovecotFailLine("203.0.113.64", "Alice@Example.COM"), makeEximDovecotFailLine("203.0.113.64", "alice@example.com")},
			login:    eximLoginLine("203.0.113.64", "alice@example.com"),
		},
		"postfix": {
			ip: "203.0.113.65", key: "alice@example.net",
			failures: []string{
				"dovecot: auth: sql(Alice@Example.NET,203.0.113.65): Password mismatch", fmt.Sprintf(postfixFailFmt, "203.0.113.65", "Alice@Example.NET"),
				"dovecot: auth: sql(alice@example.net,203.0.113.65): Password mismatch", fmt.Sprintf(postfixFailFmt, "203.0.113.65", "alice@example.net"),
			},
			login: postfixLoginLine("203.0.113.65", "ALICE@example.net"),
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			d, clock := newPairingDaemon(t, sprayTestConfig("enforce"))
			src := smtpLoginSources[name]
			if f, ok := findingByCheck(src.feed(d, clock, tc.failures...), "smtp_bruteforce"); ok {
				t.Fatalf("two spellings of one mailbox counted as two: %+v", f)
			}
			if ev := sprayEvidence(d, tc.ip); len(ev) != 1 || ev[tc.key].count != 2 {
				t.Fatalf("evidence = %+v, want two failures on %s", ev, tc.key)
			}
			got := src.feed(d, clock, tc.login)
			if f, ok := findingByCheck(got, "mail_account_compromised"); ok && f.Severity == alert.Critical {
				t.Fatalf("own mailbox login treated as a compromise: %+v", f)
			}
			if !sprayHasTrust(d, tc.ip, tc.key) {
				t.Fatal("login on the failing mailbox earned no trust")
			}
		})
	}
}

// cPanel users can log in with their account name. It is a mailbox key on
// both sides, and nothing says whether it exists, so it never first-strikes.
func TestSMTPSprayEximBareAccountLogin(t *testing.T) {
	d, clock := newPairingDaemon(t, sprayTestConfig("enforce"))
	ips := []string{"192.0.2.71", "198.51.100.71", "203.0.113.71"}
	for _, ip := range ips {
		if f, ok := findingByCheck(feedExim(d, clock, makeEximDovecotFailLine(ip, "cpuser")), "smtp_bruteforce"); ok {
			t.Fatalf("account name of unknown existence was blocked: %+v", f)
		}
		if ev := sprayEvidence(d, ip); len(ev) != 1 || ev["cpuser"].exist != mailboxExistenceUnknown {
			t.Fatalf("evidence for %s = %+v, want cpuser of unknown existence", ip, ev)
		}
	}
	if got := feedExim(d, clock, eximLoginLine(ips[0], "cpuser")); len(got) != 0 {
		t.Fatalf("own account login raised findings: %+v", got)
	}
	if !sprayHasTrust(d, ips[0], "cpuser") {
		t.Fatal("account login did not match its failures")
	}
}

// Every login fails during an auth outage, so outage traffic is no evidence.
func TestSMTPSprayOutageNotEvidence(t *testing.T) {
	const ip = "203.0.113.66"
	down := func(d *Daemon) { d.smtpAuthTracker.SetBackendDownCheck(func() bool { return true }) }
	cases := map[string]struct {
		setup    func(*Daemon)
		feed     func(*Daemon, *staticClock, ...string) []alert.Finding
		before   []string
		lines    []string
		evidence bool
	}{
		"control, exim": {feed: feedExim, evidence: true,
			lines: []string{makeEximDovecotFailLine(ip, "a@example.com"), makeEximDovecotFailLine(ip, "b@example.com")}},
		"control, postfix": {feed: feed, evidence: true,
			lines: append(smtpLoginSources["postfix"].failure(ip, "a@example.com"), smtpLoginSources["postfix"].failure(ip, "b@example.com")...)},
		"exim backend down": {setup: down, feed: feedExim,
			lines: []string{makeEximDovecotFailLine(ip, "a@example.com"), makeEximDovecotFailLine(ip, "b@example.com")}},
		"postfix backend down": {setup: down, feed: feed,
			lines: append(smtpLoginSources["postfix"].failure(ip, "a@example.com"), smtpLoginSources["postfix"].failure(ip, "b@example.com")...)},
		"dovecot error for the client": {feed: feed,
			before: []string{"dovecot: auth: Error: sql(a@example.com," + ip + "): Temporary authentication failure"},
			lines:  append(smtpLoginSources["postfix"].failure(ip, "a@example.com"), smtpLoginSources["postfix"].failure(ip, "b@example.com")...)},
		"postfix SASL warning for the process": {feed: feed,
			before: []string{"Oct 31 20:44:14 mail postfix/submission/smtpd[2245421]: warning: SASL: Connect to private/auth failed: Connection refused"},
			lines:  append(smtpLoginSources["postfix"].failure(ip, "a@example.com"), smtpLoginSources["postfix"].failure(ip, "b@example.com")...)},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			d, clock := newPairingDaemon(t, sprayTestConfig("enforce"))
			if tc.setup != nil {
				tc.setup(d)
			}
			tc.feed(d, clock, tc.before...)
			_, blocked := findingByCheck(tc.feed(d, clock, tc.lines...), "smtp_bruteforce")
			if n := d.mailSpray.Size(); blocked != tc.evidence || (n != 0) != tc.evidence {
				t.Fatalf("blocked = %v, spray IPs = %d, want evidence = %v", blocked, n, tc.evidence)
			}
		})
	}
}

// An outage starts before it is detected. A failure seen while degraded
// drops the IP's spray failures from the last fast window, on either
// tracker; older failures stay.
func TestSprayOutageForgetsRecentFailures(t *testing.T) {
	const ip = "203.0.113.170"
	for _, proto := range []string{"smtp", "imap"} {
		t.Run(proto, func(t *testing.T) {
			clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
			var tr interface {
				Record(ip, account string) []alert.Finding
				SetBackendDownCheck(func() bool)
			}
			var spray *mailSpray
			if proto == "smtp" {
				smtp := newTestTrackerWithSpray(t, clock)
				tr, spray = smtp, smtp.spray
			} else {
				mail := newTestMailTrackerWithSpray(t, clock)
				tr, spray = mail, mail.spray
			}
			tr.Record(ip, "old@example.com")
			clock.advance(time.Hour)
			tr.Record(ip, "recent@example.com")
			clock.advance(5 * time.Minute)
			tr.SetBackendDownCheck(func() bool { return true })
			tr.Record(ip, "outage@example.com")
			spray.mu.Lock()
			names := slices.Sorted(maps.Keys(spray.ips[ip].failed))
			spray.mu.Unlock()
			if !slices.Equal(names, []string{"old@example.com"}) {
				t.Fatalf("spray failures after a degraded failure = %v, want only the old one", names)
			}
		})
	}
}

// As on IMAP/POP, an SMTP login during an auth outage leaves spray memory
// alone: it would earn trust while that outage's failures were dropped.
func TestSMTPSprayOutageSuccessEarnsNoTrust(t *testing.T) {
	for _, down := range []bool{false, true} {
		clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
		tr := newTestTrackerWithSpray(t, clock)
		tr.SetBackendDownCheck(func() bool { return down })
		tr.RecordSuccess("203.0.113.171", "a@example.com")
		if got, want := tr.spray.TrustSize(), map[bool]int{false: 1, true: 0}[down]; got != want {
			t.Fatalf("backend down = %v: %d trust records, want %d", down, got, want)
		}
	}
}

// IPv4-mapped IPv6 and plain IPv4 are one source on every SMTP path.
func TestSMTPSprayIPv4MappedKeysAsIPv4(t *testing.T) {
	cases := map[string]struct {
		feed  func(*Daemon, *staticClock, ...string) []alert.Finding
		lines []string
		ip    string
		trust bool
	}{
		"exim failure":    {feed: feedExim, lines: []string{makeEximDovecotFailLine("::ffff:203.0.113.80", "a@example.com")}, ip: "203.0.113.80"},
		"exim success":    {feed: feedExim, lines: []string{eximLoginLine("::ffff:203.0.113.81", "a@example.com")}, ip: "203.0.113.81", trust: true},
		"postfix failure": {feed: feed, lines: smtpLoginSources["postfix"].failure("::ffff:203.0.113.82", "a@example.com"), ip: "203.0.113.82"},
		"postfix success": {feed: feed, lines: []string{postfixLoginLine("::ffff:203.0.113.83", "a@example.com")}, ip: "203.0.113.83", trust: true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			d, clock := newPairingDaemon(t, sprayTestConfig("enforce"))
			tc.feed(d, clock, tc.lines...)
			if tc.trust {
				if !sprayHasTrust(d, tc.ip, "a@example.com") || d.mailSpray.TrustSize() != 1 {
					t.Fatalf("login trust not keyed by %s", tc.ip)
				}
			} else if ev := sprayEvidence(d, tc.ip); len(ev) != 1 || d.mailSpray.Size() != 1 {
				t.Fatalf("failure evidence not keyed by %s", tc.ip)
			}
		})
	}
}

func TestMailSprayFindingMapping(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	const ip = "203.0.113.90"
	breadth := &sprayVerdict{Rule: sprayRuleBreadth, Block: true, Targets: []string{"", "a@example.com"}, Extra: 2}
	missing := &sprayVerdict{Rule: sprayRuleMissingMailbox, Block: true, Mailbox: "ghost@example.com", Targets: []string{"ghost@example.com"}, Networks: 3}
	compromise := &sprayVerdict{Rule: sprayRuleCompromise, Block: true, Mailbox: "a@example.com", Targets: []string{"ghost@example.com"}}
	cases := []struct {
		name          string
		proto         mailProto
		v             *sprayVerdict
		mode          sprayMode
		check, prefix string
		sev           alert.Severity
		mailbox       bool
	}{
		{"smtp breadth enforce", protoSMTP, breadth, sprayEnforce, "smtp_bruteforce", "SMTP brute force from " + ip + ": ", alert.Critical, false},
		{"mail breadth enforce", protoMail, breadth, sprayEnforce, "mail_bruteforce", "Mail auth brute force from " + ip + ": ", alert.Critical, false},
		{"smtp missing enforce", protoSMTP, missing, sprayEnforce, "smtp_bruteforce", "SMTP brute force from " + ip + ": ", alert.Critical, false},
		{"smtp missing observe", protoSMTP, missing, sprayObserve, "mail_bruteforce_suspected", "Suspected SMTP password spray from " + ip, alert.High, false},
		{"mail breadth observe", protoMail, breadth, sprayObserve, "mail_bruteforce_suspected", "Suspected IMAP/POP password spray from " + ip, alert.High, false},
		{"compromise enforce", protoSMTP, compromise, sprayEnforce, "mail_account_compromised", "Mail account compromise: ", alert.Critical, true},
		{"compromise observe", protoSMTP, compromise, sprayObserve, "mail_account_compromised", "Mail account compromise: ", alert.High, true},
		{"compromise downgraded", protoMail, &sprayVerdict{Rule: sprayRuleCompromise, Mailbox: "a@example.com"}, sprayEnforce, "mail_account_compromised", "Mail account compromise: ", alert.High, true},
		{"weak compromise", protoSMTP, &sprayVerdict{Rule: sprayRuleWeakCompromise, Mailbox: "a@example.com", Targets: []string{"b@example.com"}}, sprayEnforce, "mail_account_compromised", "Possible mail account compromise: ", alert.High, true},
		{"single mailbox success", protoSMTP, &sprayVerdict{Rule: sprayRuleSingleMailboxSuccess, Mailbox: "a@example.com", Targets: []string{"a@example.com"}}, sprayEnforce, "mail_account_compromised", "Mail login after repeated failures: ", alert.High, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := sprayFinding(tc.proto, ip, tc.v, tc.mode, now)
			if f.Check != tc.check || f.Severity != tc.sev || !strings.HasPrefix(f.Message, tc.prefix) {
				t.Fatalf("finding = %s %v %q", f.Check, f.Severity, f.Message)
			}
			if strings.Contains(f.Message, "observe mode") != (tc.mode == sprayObserve) {
				t.Fatalf("observe mode wording mismatch: %q", f.Message)
			}
			if strings.Count(f.Message, " from ") != 1 {
				t.Fatalf("message must name one source: %q", f.Message)
			}
			want := alert.Finding{Timestamp: now, SourceIP: ip}
			if tc.mailbox {
				want.Mailbox, want.Domain = "a@example.com", "example.com"
			}
			got := f
			got.Severity, got.Check, got.Message, got.Details = 0, "", "", ""
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("finding sets fields beyond the mapping: %+v", got)
			}
		})
	}
	f := sprayFinding(protoSMTP, ip, breadth, sprayEnforce, now)
	if !strings.Contains(f.Details, "Targets: (no mailbox), a@example.com (+2 more).") {
		t.Fatalf("details = %q", f.Details)
	}
	f = sprayFinding(protoSMTP, ip, &sprayVerdict{Rule: sprayRuleBreadth, Block: true, Targets: []string{"x y\n@example.com"}}, sprayEnforce, now)
	if !strings.Contains(f.Details, `account="x\x20y\x0a@example.com"`) {
		t.Fatalf("unsafe target not escaped: %q", f.Details)
	}
}

// One failure raises one smtp_bruteforce, even when it crosses the per-IP
// bar and a spray rule at once. The spray memory still records it.
func TestSMTPSprayOneBlockPerFailure(t *testing.T) {
	const ip = "203.0.113.67"
	d, clock := newPairingDaemon(t, sprayTestConfig("enforce"))
	for i := 1; i < d.smtpAuthTracker.perIPThreshold; i++ {
		if f, ok := findingByCheck(feedExim(d, clock, makeEximDovecotFailLine(ip, "a@example.com")), "smtp_bruteforce"); ok {
			t.Fatalf("blocked before either bar: %+v", f)
		}
	}
	got := feedExim(d, clock, makeEximDovecotFailLine(ip, "b@example.com"))
	n := 0
	for _, f := range got {
		if f.Check == "smtp_bruteforce" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("smtp_bruteforce findings = %d, want 1: %+v", n, got)
	}
	if ev := sprayEvidence(d, ip); len(ev) != 2 {
		t.Fatalf("spray evidence = %+v, want both mailboxes", ev)
	}
}

// Exim logs a 4xx reply when the Dovecot auth socket cannot answer. Such a
// failure says nothing about the password: it still counts toward the per-IP
// signals, but never becomes spray evidence.
func TestSMTPSprayEximTemporaryFailureNotEvidence(t *testing.T) {
	const ip = "203.0.113.68"
	for _, tc := range []struct {
		reply    string
		evidence bool
	}{
		{"435 Unable to authenticate at present", false},
		{"535 Incorrect authentication data", true},
	} {
		t.Run(tc.reply[:3], func(t *testing.T) {
			d, clock := newPairingDaemon(t, sprayTestConfig("enforce"))
			var got []alert.Finding
			for _, mailbox := range []string{"a@example.com", "b@example.com"} {
				got = append(got, feedExim(d, clock, fmt.Sprintf(
					"2026-04-14 12:00:00 dovecot_login authenticator failed for (bot.example) [%s]:54321: %s (set_id=%s)", ip, tc.reply, mailbox))...)
			}
			if calls := smtpCalls(d); calls != 2 {
				t.Fatalf("SMTP failures = %d, want 2", calls)
			}
			_, blocked := findingByCheck(got, "smtp_bruteforce")
			if n := d.mailSpray.Size(); blocked != tc.evidence || (n != 0) != tc.evidence {
				t.Fatalf("blocked = %v, spray IPs = %d, want evidence = %v", blocked, n, tc.evidence)
			}
		})
	}
}

// Login trust vouches only for the mailboxes it names. A failure naming no
// mailbox (an empty Exim set_id, or Postfix pairing that cannot tell the
// mailbox) keeps the slow block armed.
func TestSMTPSlowBruteTrustDoesNotHideUnnamedFailures(t *testing.T) {
	const ip = "203.0.113.69"
	accounts := []string{"a@example.com", "b@example.com", "c@example.com"}
	for _, unnamed := range []bool{false, true} {
		t.Run(fmt.Sprintf("unnamed=%v", unnamed), func(t *testing.T) {
			clock := &staticClock{t: time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)}
			tr := newTestTrackerWithSpray(t, clock)
			for _, account := range accounts {
				tr.RecordSuccess(ip, account)
			}
			clock.advance(11 * time.Minute) // trust ages past the failure window
			var fired bool
			for i := 0; i < tr.slowThreshold; i++ {
				account := accounts[i%len(accounts)]
				if unnamed && i%10 == 0 {
					account = ""
				}
				if _, ok := findingByCheck(tr.Record(ip, account), "smtp_bruteforce"); ok {
					fired = true
				}
				clock.advance(8 * time.Minute)
			}
			if fired != unnamed {
				t.Fatalf("smtp_bruteforce fired = %v, want %v", fired, unnamed)
			}
		})
	}
}

// Three addresses of one /64 that each fail on one mailbox reach the
// breadth bar together; the block names the address that failed last.
func TestSMTPSprayIPv6BlocksFailingAddress(t *testing.T) {
	cfg := sprayTestConfig("enforce")
	cfg.Thresholds.MailSprayBreadthMailboxes = 3
	d, clock := newPairingDaemon(t, cfg)
	for i, ip := range []string{"2001:db8:1:2::a", "2001:db8:1:2::b", "2001:db8:1:2::c"} {
		got := feedExim(d, clock, makeEximDovecotFailLine(ip, walkedMailbox(i)))
		f, blocked := findingByCheck(got, "smtp_bruteforce")
		if blocked != (i == 2) || (blocked && f.SourceIP != ip) {
			t.Fatalf("failure %d from %s: findings = %+v", i+1, ip, got)
		}
	}
}

// IPv6 evidence is kept per /64, but blocks name the failing address. The
// finding says which network the targets and history belong to.
func TestMailSprayFindingNamesIPv6Scope(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	breadth := &sprayVerdict{Rule: sprayRuleBreadth, Block: true, Targets: []string{"a@example.com", "b@example.com"}}
	compromise := &sprayVerdict{Rule: sprayRuleCompromise, Block: true, Mailbox: "a@example.com", Targets: []string{"ghost@example.com"}}
	const scope = "Targets and failure history cover 2001:db8:1:2::/64; any block applies to 2001:db8:1:2::c only."
	for _, v := range []*sprayVerdict{breadth, compromise} {
		f := sprayFinding(protoSMTP, "2001:db8:1:2::c", v, sprayEnforce, now)
		if f.SourceIP != "2001:db8:1:2::c" || !strings.HasSuffix(f.Details, scope) {
			t.Fatalf("IPv6 %s finding: source %s, details %q", v.Rule, f.SourceIP, f.Details)
		}
		if f = sprayFinding(protoSMTP, "203.0.113.90", v, sprayEnforce, now); strings.Contains(f.Details, "cover") {
			t.Fatalf("IPv4 %s finding names a network: %q", v.Rule, f.Details)
		}
	}
}
