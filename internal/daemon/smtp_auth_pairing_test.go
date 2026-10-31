package daemon

import (
	"fmt"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

const postfixFailFmt = "Oct 31 20:44:15 mail postfix/submission/smtpd[2245421]: warning: unknown[%s]: SASL LOGIN authentication failed: (reason unavailable), sasl_username=%s"

func newPairingDaemon(t *testing.T, cfg *config.Config) (*Daemon, *staticClock) {
	t.Helper()
	clock := &staticClock{t: time.Date(2026, 10, 31, 20, 0, 0, 0, time.UTC)}
	d := New(cfg, nil, nil, "")
	d.smtpAuthTracker = newTestTracker(t, clock)
	d.mailAuthTracker = newTestMailTracker(t, clock)
	return d, clock
}

// feed hands each line to the mail handler one second apart.
func feed(d *Daemon, clock *staticClock, lines ...string) []alert.Finding {
	var got []alert.Finding
	for _, line := range lines {
		clock.advance(time.Second)
		got = append(got, d.handleMailLine(line, alert.Observation{}, d.currentCfg())...)
	}
	return got
}

func smtpCalls(d *Daemon) int64 {
	calls, _ := d.smtpAuthTracker.Stats()
	return calls
}

// Postfix's failure line is the request's final result; a Dovecot rejection
// for the same client just before it shows a credential was checked.
func TestPairedPostfixFailureCounts(t *testing.T) {
	cases := []struct {
		name, verdict, ip string
	}{
		{"password mismatch", "dovecot: auth: sql(alice@example.net,%s): Password mismatch", "203.0.113.80"},
		{"unknown user", "Oct 31 20:44:13 mail dovecot: auth: sql(alice@example.net,%s): unknown user", "203.0.113.81"},
		{"pam rejection", "dovecot: auth-worker(4567): pam(alice@example.net,%s): pam_authenticate() failed: Authentication failure (Password mismatch?)", "203.0.113.82"},
		{"worker connection prefix", "dovecot: auth-worker(4567): conn unix:auth-worker (pid=4560,uid=97): auth-worker<1>: pam(alice@example.net,%s): unknown user", "203.0.113.83"},
		{"named passdb", "dovecot[812]: auth: Primary SQL(alice@example.net,%s): Password mismatch", "203.0.113.84"},
		{"master login", "dovecot: auth: sql(alice@example.net,%s,master): Password mismatch", "203.0.113.85"},
		{"ipv6", "dovecot: auth: passwd-file(alice@example.net,%s): Password mismatch", "2001:db8::86"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, clock := newPairingDaemon(t, &config.Config{})
			var got []alert.Finding
			for i := 0; i < 5; i++ {
				got = append(got, feed(d, clock,
					fmt.Sprintf(tc.verdict, tc.ip),
					fmt.Sprintf(postfixFailFmt, tc.ip, "alice@example.net"))...)
			}
			if len(got) != 1 || got[0].Check != "smtp_bruteforce" || got[0].SourceIP != tc.ip {
				t.Fatalf("findings = %+v, want one smtp_bruteforce for %s", got, tc.ip)
			}
			if calls := smtpCalls(d); calls != 5 {
				t.Fatalf("SMTP failures = %d, want 5", calls)
			}
			if d.mailAuthTracker.Size() != 0 {
				t.Fatalf("SMTP failures reached the IMAP tracker")
			}
		})
	}
}

// smtpd_client_port_logging and plain smtpd service names pair the same way.
func TestPairedPostfixFailureLineFormats(t *testing.T) {
	for _, failure := range []string{
		"postfix/smtpd[99]: warning: mx.example.net[203.0.113.90]:51234: SASL PLAIN authentication failed: ",
		"postfix/smtpd[99]: warning: unknown[203.0.113.90]: SASL LOGIN authentication failed: UGFzc3dvcmQ6",
		"postfix/smtpd[99]: warning: unknown[203.0.113.90]: SASL LOGIN authentication failed",
	} {
		d, clock := newPairingDaemon(t, &config.Config{})
		feed(d, clock, "dovecot: auth: sql(bob,203.0.113.90): unknown user", failure)
		if calls := smtpCalls(d); calls != 1 {
			t.Fatalf("%q: SMTP failures = %d, want 1", failure, calls)
		}
	}
}

// A rejection from one database followed by success in a later one leaves
// no Postfix failure, so nothing counts, even when a failure follows later.
func TestVerdictWithoutPostfixFailureNeverCounts(t *testing.T) {
	d, clock := newPairingDaemon(t, &config.Config{})
	for i := 0; i < 10; i++ {
		feed(d, clock, "dovecot: auth: sql(alice@example.net,203.0.113.91): unknown user")
	}
	clock.advance(time.Minute)
	feed(d, clock, fmt.Sprintf(postfixFailFmt, "203.0.113.91", "alice@example.net"))
	if calls := smtpCalls(d); calls != 0 {
		t.Fatalf("SMTP failures = %d, want 0", calls)
	}
}

// Another database failing internally for the same client, before or after
// the rejection, makes the Postfix failure an outage, not a wrong password.
func TestPairingExcludesClientWithAuthError(t *testing.T) {
	for _, tc := range []struct {
		name  string
		lines []string
	}{
		{"error after rejection", []string{
			"dovecot: auth: sql(alice@example.net,203.0.113.92): unknown user",
			"dovecot: auth: Error: ldap(alice@example.net,203.0.113.92): ldap_search() failed: Can't contact LDAP server",
		}},
		{"error before rejection", []string{
			"dovecot: auth-worker(12): Error: pgsql(alice@example.net,203.0.113.92): Password query failed: connection lost",
			"dovecot: auth: passwd-file(alice@example.net,203.0.113.92): unknown user",
		}},
		{"warning with worker prefix", []string{
			"dovecot: auth-worker(12): Warning: conn unix:auth-worker (pid=11,uid=97): auth-worker<1>: pam(alice@example.net,203.0.113.92): request timed out",
			"dovecot: auth: sql(alice@example.net,203.0.113.92): Password mismatch",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, clock := newPairingDaemon(t, &config.Config{})
			for i := 0; i < 5; i++ {
				feed(d, clock, append(tc.lines, fmt.Sprintf(postfixFailFmt, "203.0.113.92", "alice@example.net"))...)
			}
			if calls := smtpCalls(d); calls != 0 {
				t.Fatalf("SMTP failures = %d, want 0", calls)
			}
		})
	}
}

// An error for one client does not hide another client's rejection, and it
// expires with the pairing window.
func TestAuthErrorIsPerClientAndExpires(t *testing.T) {
	d, clock := newPairingDaemon(t, &config.Config{})
	feed(d, clock,
		"dovecot: auth: Error: ldap(a,198.51.100.7): ldap_search() failed",
		"dovecot: auth: sql(b,203.0.113.93): unknown user",
		fmt.Sprintf(postfixFailFmt, "203.0.113.93", "b"))
	if calls := smtpCalls(d); calls != 1 {
		t.Fatalf("other client's error suppressed the pair: SMTP failures = %d, want 1", calls)
	}
	feed(d, clock, "dovecot: auth: Error: ldap(a,203.0.113.94): ldap_search() failed")
	clock.advance(time.Minute)
	feed(d, clock,
		"dovecot: auth: sql(b,203.0.113.94): unknown user",
		fmt.Sprintf(postfixFailFmt, "203.0.113.94", "b"))
	if calls := smtpCalls(d); calls != 2 {
		t.Fatalf("expired error still suppressed the pair: SMTP failures = %d, want 2", calls)
	}
}

// Each database in a chain logs its own rejection; one request still ends in
// one Postfix failure and counts once.
func TestSeveralVerdictsOneFailureCountsOnce(t *testing.T) {
	d, clock := newPairingDaemon(t, &config.Config{})
	feed(d, clock,
		"dovecot: auth: sql(alice@example.net,203.0.113.95): unknown user",
		"dovecot: auth: passwd-file(alice@example.net,203.0.113.95): unknown user",
		fmt.Sprintf(postfixFailFmt, "203.0.113.95", "alice@example.net"))
	if calls := smtpCalls(d); calls != 1 {
		t.Fatalf("SMTP failures = %d, want 1", calls)
	}
}

// Postfix failures without a fresh Dovecot rejection (outages, stale replies)
// never count, whatever their reply text says.
func TestUnpairedPostfixFailureNeverCounts(t *testing.T) {
	d, clock := newPairingDaemon(t, &config.Config{})
	for i := 0; i < 10; i++ {
		feed(d, clock, fmt.Sprintf(postfixFailFmt, "203.0.113.96", "alice@example.net"))
	}
	if calls := smtpCalls(d); calls != 0 {
		t.Fatalf("SMTP failures = %d, want 0", calls)
	}
}

// A rejection pairs only with a failure from the address Dovecot appended.
func TestPairingNeedsSameClient(t *testing.T) {
	for _, verdict := range []string{
		"dovecot: auth: sql(alice@example.net,203.0.113.97): unknown user",
		// The client chooses its login name; an address inside it is not
		// the request's address.
		"dovecot: auth: sql(x,198.51.100.9,203.0.113.97): unknown user",
		"dovecot: auth: sql(x,198.51.100.9,master,203.0.113.97): unknown user",
	} {
		d, clock := newPairingDaemon(t, &config.Config{})
		feed(d, clock, verdict, fmt.Sprintf(postfixFailFmt, "198.51.100.9", "x"))
		if calls := smtpCalls(d); calls != 0 {
			t.Fatalf("%q paired with another client: SMTP failures = %d", verdict, calls)
		}
	}
}

func TestPairingIgnoresExcludedVerdicts(t *testing.T) {
	for _, verdict := range []string{
		// Login-process requests are counted from their login summaries.
		"dovecot: auth: sql(alice@example.net,203.0.113.98,<AbCdEf123456>): Password mismatch",
		// A logged password is client text after the verdict, and syslog
		// can cut it right after a forged verdict.
		"dovecot: auth: sql(a,203.0.113.98): Password mismatch (given password: x)",
		"dovecot: auth: sql(a,198.51.100.5): Password mismatch (given password: ,203.0.113.98): unknown user",
		"dovecot: auth: Error: sql(a,203.0.113.98): unknown user",
		"dovecot: auth: Debug: sql(a,203.0.113.98): unknown user",
		"dovecot: auth: sql(a,203.0.113.98): Invalid password in passdb: Not a valid MD5-CRYPT or PLAIN-MD5 password",
		"dovecot: lmtp(4321): sql(a,203.0.113.98): unknown user",
		"postfix/smtpd[99]: auth: sql(a,203.0.113.98): unknown user",
	} {
		d, clock := newPairingDaemon(t, &config.Config{})
		feed(d, clock, verdict, fmt.Sprintf(postfixFailFmt, "203.0.113.98", "a"))
		if calls := smtpCalls(d); calls != 0 {
			t.Fatalf("%q paired: SMTP failures = %d, want 0", verdict, calls)
		}
	}
}

func TestPairingSkipsInfraPrivateAndEximHosts(t *testing.T) {
	for _, tc := range []struct {
		name, ip string
		exim     bool
	}{
		{"infra", "192.0.2.10", false},
		{"private", "10.0.0.7", false},
		{"loopback", "127.0.0.1", false},
		// Exim logs its own SMTP AUTH failures.
		{"exim host", "203.0.113.99", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, clock := newPairingDaemon(t, &config.Config{InfraIPs: []string{"192.0.2.10"}})
			d.smtpAuthFromExim = tc.exim
			for i := 0; i < 10; i++ {
				feed(d, clock,
					"dovecot: auth: sql(a,"+tc.ip+"): unknown user",
					fmt.Sprintf(postfixFailFmt, tc.ip, "a"))
			}
			if calls := smtpCalls(d); calls != 0 {
				t.Fatalf("SMTP failures = %d, want 0", calls)
			}
		})
	}
}

// The mailbox comes from Dovecot's verdict, not the name Postfix appends.
func TestPairedFailuresFeedAccountSpray(t *testing.T) {
	d, clock := newPairingDaemon(t, &config.Config{})
	var got []alert.Finding
	for i := 1; i <= 12; i++ {
		ip := fmt.Sprintf("203.0.113.%d", 100+i)
		got = append(got, feed(d, clock,
			"dovecot: auth: sql(Alice@Example.net,"+ip+"): Password mismatch",
			fmt.Sprintf(postfixFailFmt, ip, "decoy@example.org"))...)
	}
	var spray []alert.Finding
	for _, f := range got {
		if f.Check == "smtp_account_spray" {
			spray = append(spray, f)
		}
	}
	if len(spray) != 1 || spray[0].Mailbox != "alice@example.net" {
		t.Fatalf("findings = %+v, want one smtp_account_spray for alice@example.net", got)
	}
}

// A verdict is claimed by the first failure for its client, even when that
// failure blames the authentication server.
func TestVerdictPairsOnce(t *testing.T) {
	d, clock := newPairingDaemon(t, &config.Config{})
	feed(d, clock,
		"dovecot: auth: sql(a,203.0.113.70): unknown user",
		fmt.Sprintf(postfixFailFmt, "203.0.113.70", "a"),
		fmt.Sprintf(postfixFailFmt, "203.0.113.70", "a"))
	if calls := smtpCalls(d); calls != 1 {
		t.Fatalf("SMTP failures = %d, want 1", calls)
	}
	feed(d, clock,
		"dovecot: auth: sql(a,203.0.113.71): unknown user",
		"postfix/smtpd[99]: warning: unknown[203.0.113.71]: SASL PLAIN authentication failed: Connection lost to authentication server",
		fmt.Sprintf(postfixFailFmt, "203.0.113.71", "a"))
	if calls := smtpCalls(d); calls != 1 {
		t.Fatalf("server-blamed failure: SMTP failures = %d, want 1", calls)
	}
}

// When error marks exceed the tracking budget, pairing is withheld rather
// than an outage mark being dropped.
func TestAuthTroubleOverflowWithholdsPairing(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 10, 31, 20, 0, 0, 0, time.UTC)}
	d := New(&config.Config{}, nil, nil, "")
	d.smtpAuthTracker = newSMTPAuthTracker(5, 8, 12, 10*time.Minute, time.Hour, 40, 6*time.Hour, 2, clock.Now)
	feed(d, clock,
		"dovecot: auth: Error: ldap(a,198.51.100.1): failed",
		"dovecot: auth: Error: ldap(a,198.51.100.2): failed",
		"dovecot: auth: Error: ldap(a,198.51.100.3): failed",
		"dovecot: auth: sql(b,203.0.113.72): unknown user",
		fmt.Sprintf(postfixFailFmt, "203.0.113.72", "b"))
	if calls := smtpCalls(d); calls != 0 {
		t.Fatalf("SMTP failures = %d, want 0 while marks overflow", calls)
	}
	clock.advance(time.Minute)
	feed(d, clock,
		"dovecot: auth: sql(b,203.0.113.72): unknown user",
		fmt.Sprintf(postfixFailFmt, "203.0.113.72", "b"))
	if calls := smtpCalls(d); calls != 1 {
		t.Fatalf("SMTP failures = %d, want 1 after the overflow expired", calls)
	}
}

// smtpd echoes client text into other warnings. With a verdict pending for
// the address that text names, none of these lines may claim it.
func TestPostfixLinesThatMustNotPair(t *testing.T) {
	for _, tc := range []struct{ name, line string }{
		{"client text in another warning", "postfix/smtpd[99]: warning: Illegal address syntax from unknown[203.0.113.65] in RCPT command: <x[198.51.100.9]: SASL LOGIN authentication failed: x>"},
		{"brackets in hostname", "postfix/smtpd[99]: warning: x[198.51.100.9].example[203.0.113.70]: SASL LOGIN authentication failed: x"},
		{"quoted auth mechanism", `postfix/smtpd[99]: warning: unknown[198.51.100.9]: SASL "LOGIN authentication failed: x" authentication aborted`},
		{"invalid failure suffix", "postfix/smtpd[99]: warning: unknown[198.51.100.9]: SASL LOGIN authentication failedness: x"},
		{"missing open bracket", "postfix/smtpd[99]: warning: 198.51.100.9]: SASL LOGIN authentication failed: x"},
		{"invalid port", "postfix/smtpd[99]: warning: unknown[198.51.100.9]:not-a-port: SASL LOGIN authentication failed: x"},
		{"port overflow", "postfix/smtpd[99]: warning: unknown[198.51.100.9]:70000: SASL LOGIN authentication failed: x"},
		{"aborted by client", "postfix/smtpd[99]: warning: unknown[198.51.100.9]: SASL LOGIN authentication aborted"},
		{"other program", "dovecot: warning: unknown[198.51.100.9]: SASL LOGIN authentication failed: x"},
		{"postfix client", "postfix/smtp[99]: warning: unknown[198.51.100.9]: SASL LOGIN authentication failed: x"},
		{"bad pid", "postfix/smtpd[9x]: warning: unknown[198.51.100.9]: SASL LOGIN authentication failed: x"},
		{"temporary reply", "postfix/smtpd[99]: warning: unknown[198.51.100.9]: SASL PLAIN authentication failed: Temporary authentication failure"},
		{"backend error reply", "postfix/smtpd[99]: warning: unknown[198.51.100.9]: SASL PLAIN authentication failed: Authentication backend error, sasl_username=a"},
		{"cyrus transient", "postfix/smtpd[99]: warning: unknown[198.51.100.9]: SASL PLAIN authentication failed: transient failure (e.g., weak key)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, clock := newPairingDaemon(t, &config.Config{})
			feed(d, clock, "dovecot: auth: sql(a,198.51.100.9): unknown user", tc.line)
			if calls := smtpCalls(d); calls != 0 {
				t.Fatalf("SMTP failures = %d, want 0", calls)
			}
		})
	}
}
