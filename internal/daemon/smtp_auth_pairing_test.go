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

// Extra passdb answers must not corroborate a later reconnect failure that
// repeats the previous SASL reply without a new credential check.
func TestSeveralVerdictsCannotFeedLaterFailure(t *testing.T) {
	d, clock := newPairingDaemon(t, &config.Config{})
	feed(d, clock,
		"dovecot: auth: sql(alice@example.net,203.0.113.95): unknown user",
		"dovecot: auth: passwd-file(alice@example.net,203.0.113.95): unknown user",
		fmt.Sprintf(postfixFailFmt, "203.0.113.95", "alice@example.net"),
		"postfix/submission/smtpd[2245421]: warning: SASL: Connect to Dovecot auth socket 'private/auth' failed: Connection refused",
		fmt.Sprintf(postfixFailFmt, "203.0.113.95", "alice@example.net"))
	if calls := smtpCalls(d); calls != 1 {
		t.Fatalf("SMTP failures = %d, want only the completed request", calls)
	}
}

// Concurrent requests can finish in a different order from their passdb
// answers. The address is known, but the mailbox cannot be picked by FIFO.
func TestPairingOmitsAmbiguousMailbox(t *testing.T) {
	d, clock := newPairingDaemon(t, &config.Config{})
	feed(d, clock,
		"dovecot: auth: sql(alice@example.net,203.0.113.95): unknown user",
		"dovecot: auth: sql(bob@example.net,203.0.113.95): unknown user",
		fmt.Sprintf(postfixFailFmt, "203.0.113.95", "bob@example.net"),
		fmt.Sprintf(postfixFailFmt, "203.0.113.95", "alice@example.net"))
	if calls := smtpCalls(d); calls != 2 {
		t.Fatalf("SMTP failures = %d, want 2", calls)
	}
	if len(d.smtpAuthTracker.accounts) != 0 {
		t.Fatalf("ambiguous mailbox created account evidence: %+v", d.smtpAuthTracker.accounts)
	}
}

// A successful fallback leaves an unused passdb rejection. If smtpd then
// loses its backend, that rejection must not authenticate its stale reply.
func TestPostfixBackendWarningWithholdsPairing(t *testing.T) {
	for _, warning := range []string{
		"SASL: Connect to Dovecot auth socket 'private/auth' failed: Connection refused",
		"SASL: Couldn't send handshake: Broken pipe",
		"SASL: Protocol version mismatch (2 vs. 1)",
	} {
		t.Run(warning, func(t *testing.T) {
			d, clock := newPairingDaemon(t, &config.Config{})
			feed(d, clock,
				"dovecot: auth: sql(alice@example.net,203.0.113.95): unknown user",
				"postfix/submission/smtpd[2245421]: warning: "+warning,
				fmt.Sprintf(postfixFailFmt, "203.0.113.95", "alice@example.net"))
			if calls := smtpCalls(d); calls != 0 {
				t.Fatalf("SMTP failures = %d during smtpd backend failure", calls)
			}
			feed(d, clock,
				"dovecot: auth: sql(bob@example.net,203.0.113.96): unknown user",
				"postfix/smtpd[99]: warning: unknown[203.0.113.96]: SASL LOGIN authentication failed: x")
			if calls := smtpCalls(d); calls != 1 {
				t.Fatalf("other smtpd process suppressed: failures = %d, want 1", calls)
			}
			clock.advance(time.Minute)
			feed(d, clock,
				"dovecot: auth: sql(alice@example.net,203.0.113.95): unknown user",
				fmt.Sprintf(postfixFailFmt, "203.0.113.95", "alice@example.net"))
			if calls := smtpCalls(d); calls != 2 {
				t.Fatalf("recovered smtpd process suppressed: failures = %d, want 2", calls)
			}
		})
	}
}

func TestPairingOverflowIncludesWindowBoundary(t *testing.T) {
	d, clock := newPairingDaemon(t, &config.Config{})
	d.smtpAuthTracker.maxTracked = 1
	feed(d, clock,
		"dovecot: auth: Error: ldap(a,198.51.100.1): failed",
		"dovecot: auth: Error: ldap(a,203.0.113.95): failed")
	clock.advance(smtpAuthPairWindow - 2*time.Second)
	feed(d, clock,
		"dovecot: auth: sql(alice@example.net,203.0.113.95): unknown user",
		fmt.Sprintf(postfixFailFmt, "203.0.113.95", "alice@example.net"))
	if calls := smtpCalls(d); calls != 0 {
		t.Fatalf("overflow mark expired before the inclusive window: failures = %d", calls)
	}
}

func TestPairingHonorsNewInfraProtection(t *testing.T) {
	d, clock := newPairingDaemon(t, &config.Config{})
	feed(d, clock, "dovecot: auth: sql(alice@example.net,203.0.113.95): unknown user")
	cfg := &config.Config{InfraIPs: []string{"203.0.113.95"}}
	d.handleMailLine(fmt.Sprintf(postfixFailFmt, "203.0.113.95", "alice@example.net"), alert.Observation{}, cfg)
	if calls := smtpCalls(d); calls != 0 {
		t.Fatalf("newly protected address recorded %d failures", calls)
	}
}

func TestPairingOmitsMailboxAfterPendingOverflow(t *testing.T) {
	d, clock := newPairingDaemon(t, &config.Config{})
	feed(d, clock, "dovecot: auth: sql(alice@example.net,203.0.113.95): unknown user")
	for i := 0; i < smtpAuthPairMaxPending; i++ {
		feed(d, clock, "dovecot: auth: sql(bob@example.net,203.0.113.95): unknown user")
	}
	feed(d, clock, fmt.Sprintf(postfixFailFmt, "203.0.113.95", "alice@example.net"))
	if calls := smtpCalls(d); calls != 1 || len(d.smtpAuthTracker.accounts) != 0 {
		t.Fatalf("overflow lost mailbox ambiguity: calls=%d accounts=%+v", calls, d.smtpAuthTracker.accounts)
	}
}

func TestPostfixProtocolFailuresDoNotClaimCredentialEvidence(t *testing.T) {
	for _, reply := range []string{
		"Invalid authentication mechanism",
		"Invalid authentication mechanism: 'INVALID'",
		"Invalid base64 data in initial response",
		"Invalid base64 data in continued response",
	} {
		t.Run(reply, func(t *testing.T) {
			d, clock := newPairingDaemon(t, &config.Config{})
			feed(d, clock,
				"dovecot: auth: sql(alice@example.net,203.0.113.95): unknown user",
				"postfix/smtpd[99]: warning: unknown[203.0.113.95]: SASL LOGIN authentication failed: "+reply)
			if calls := smtpCalls(d); calls != 0 {
				t.Fatalf("local protocol rejection recorded %d credential failures", calls)
			}
		})
	}
}

// Reading a backlog quickly must not turn an old, unused passdb rejection
// into evidence for a much later Postfix failure.
func TestPairingRespectsLoggedTime(t *testing.T) {
	for _, tc := range []struct {
		name, verdictTime, failureTime string
		want                           int64
	}{
		{"rfc3339 stale", "2026-10-31T19:50:00Z", "2026-10-31T20:00:00Z", 0},
		{"syslog stale", "Oct 31 19:50:00", "Oct 31 20:00:00", 0},
		{"out of order", "2026-10-31T20:00:03Z", "2026-10-31T20:00:02Z", 0},
		{"rfc3339 fresh", "2026-10-31T19:59:58Z", "2026-10-31T20:00:00Z", 1},
		{"syslog fresh", "Oct 31 19:59:58", "Oct 31 20:00:00", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, clock := newPairingDaemon(t, &config.Config{})
			feed(d, clock,
				tc.verdictTime+" mail dovecot: auth: sql(alice@example.net,203.0.113.95): unknown user",
				tc.failureTime+" mail postfix/smtpd[99]: warning: unknown[203.0.113.95]: SASL LOGIN authentication failed: x")
			if calls := smtpCalls(d); calls != tc.want {
				t.Fatalf("SMTP failures = %d, want %d", calls, tc.want)
			}
		})
	}
}

func TestPairingAcrossSyslogNewYear(t *testing.T) {
	d, clock := newPairingDaemon(t, &config.Config{})
	clock.t = time.Date(2027, 1, 1, 0, 0, 3, 0, time.Local)
	feed(d, clock,
		"Dec 31 23:59:59 mail dovecot: auth: sql(alice@example.net,203.0.113.95): unknown user",
		"Jan  1 00:00:01 mail postfix/smtpd[99]: warning: unknown[203.0.113.95]: SASL LOGIN authentication failed: x")
	if calls := smtpCalls(d); calls != 1 {
		t.Fatalf("year rollover lost a fresh pair: failures = %d", calls)
	}
}

// Saturation drops new verdicts, but must not evict a retained client's
// evidence or leave the map unavailable after old entries expire.
func TestPairingPendingCapacityRecovers(t *testing.T) {
	d, clock := newPairingDaemon(t, &config.Config{})
	d.smtpAuthTracker.maxTracked = 1
	feed(d, clock,
		"dovecot: auth: sql(alice@example.net,203.0.113.95): unknown user",
		"dovecot: auth: sql(bob@example.net,203.0.113.96): unknown user",
		fmt.Sprintf(postfixFailFmt, "203.0.113.96", "bob@example.net"),
		fmt.Sprintf(postfixFailFmt, "203.0.113.95", "alice@example.net"))
	if calls := smtpCalls(d); calls != 1 {
		t.Fatalf("saturated map recorded %d failures, want 1 retained verdict", calls)
	}
	feed(d, clock, "dovecot: auth: sql(alice@example.net,203.0.113.95): unknown user")
	clock.advance(time.Minute)
	feed(d, clock,
		"dovecot: auth: sql(bob@example.net,203.0.113.96): unknown user",
		fmt.Sprintf(postfixFailFmt, "203.0.113.96", "bob@example.net"))
	if calls := smtpCalls(d); calls != 2 {
		t.Fatalf("expired map did not recover: failures = %d, want 2", calls)
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

// Protocol rejections do not prove a credential check. A parallel request
// must neither count nor consume the real attempt's pending verdict.
func TestSASLProtocolRejectionDoesNotConsumeVerdict(t *testing.T) {
	for _, local := range []string{
		"postfix/smtpd[98]: warning: unknown[203.0.113.73]: SASL LOGIN authentication failed: Invalid base64 data in continued response",
		"postfix/smtpd[98]: warning: unknown[203.0.113.73]: SASL PLAIN authentication failed: Invalid base64 data in initial response",
		"postfix/smtpd[98]: warning: unknown[203.0.113.73]: SASL XYZ authentication failed: Invalid authentication mechanism",
		"postfix/smtpd[98]: warning: unknown[203.0.113.73]: SASL XYZ authentication failed: Invalid authentication mechanism: 'XYZ'",
		"postfix/smtpd[98]: warning: unknown[203.0.113.73]: SASL LOGIN authentication failed: Authentication request timed out",
		"postfix/smtpd[98]: warning: unknown[203.0.113.73]: SASL LOGIN authentication failed: Unexpected continuation",
		"postfix/smtpd[98]: warning: unknown[203.0.113.73]: SASL PLAIN authentication failed: Client didn't present valid SSL certificate",
		"postfix/smtpd[98]: warning: unknown[203.0.113.73]: SASL PLAIN authentication failed: SSL certificate didn't contain username",
	} {
		for _, suffix := range []string{"", ", sasl_username=authentication server"} {
			t.Run(local+suffix, func(t *testing.T) {
				assertSMTPVerdictPreserved(t, local+suffix)
			})
		}
	}
}

func assertSMTPVerdictPreserved(t *testing.T, line string) {
	t.Helper()
	d, clock := newPairingDaemon(t, &config.Config{})
	feed(d, clock, "dovecot: auth: sql(a,203.0.113.73): Password mismatch")
	pending := d.smtpAuthTracker.pendingVerdicts["203.0.113.73"][0]
	feed(d, clock, line)
	if calls := smtpCalls(d); calls != 0 {
		t.Fatalf("protocol rejection recorded %d credential failures", calls)
	}
	if got := d.smtpAuthTracker.pendingVerdicts["203.0.113.73"]; len(got) != 1 || got[0] != pending {
		t.Fatalf("protocol rejection changed pending verdict: %+v", got)
	}
	// Reuse the process too: the rejection must not mark it as unhealthy.
	failure := "postfix/smtpd[98]: warning: unknown[203.0.113.73]: SASL LOGIN authentication failed: (reason unavailable), sasl_username=a"
	feed(d, clock, failure, failure)
	if calls := smtpCalls(d); calls != 1 {
		t.Fatalf("SMTP failures = %d, want one real failure", calls)
	}
	if len(d.smtpAuthTracker.pendingVerdicts) != 0 {
		t.Fatal("completed failure left a pending verdict")
	}
}

// Postfix logs these before or outside a credential check. Client text in
// them must not be mistaken for a SASL failure or a backend warning.
func TestPostfixNonAuthLinesPreserveVerdict(t *testing.T) {
	for _, msg := range []string{
		"warning: unknown[203.0.113.73]: SASL LOGIN authentication aborted",
		"warning: unknown[203.0.113.73]: request longer than 12288: SASL LOGIN authentication fail...",
		"warning: AUTH command rate limit exceeded: 1 from unknown[203.0.113.73] for service submission",
		"> unknown[203.0.113.73]: 500 5.5.6 SASL response limit exceeded",
		"> unknown[203.0.113.73]: 504 5.5.4 Encryption required for requested authentication mechanism",
		"> unknown[203.0.113.73]: 503 5.5.1 Error: authentication not enabled",
		`warning: unknown[203.0.113.73]: SASL "LOGIN authentication failed: Connection lost to authentication server" authentication failed: Invalid authentication mechanism`,
		"warning: unknown[203.0.113.73]: SASL TEMPORARY authentication failed: Invalid authentication mechanism: 'TEMPORARY'",
	} {
		t.Run(msg, func(t *testing.T) {
			assertSMTPVerdictPreserved(t, "postfix/smtpd[98]: "+msg)
		})
	}
}

// A genuine backend failure must retire the verdict without counting it;
// otherwise a later warning could reuse the withheld credential evidence.
func TestPostfixServerFaultConsumesVerdict(t *testing.T) {
	for _, reply := range []string{
		"Authentication backend error",
		"Connection lost to authentication server",
		"Can't connect to authentication server",
		"Temporary authentication failure",
		"generic failure",
		"no memory available",
		"transient failure (e.g., weak key)",
		"remote authentication server unavailable",
	} {
		t.Run(reply, func(t *testing.T) {
			d, clock := newPairingDaemon(t, &config.Config{})
			feed(d, clock,
				"dovecot: auth: sql(a,203.0.113.73): Password mismatch",
				"postfix/smtpd[98]: warning: unknown[203.0.113.73]: SASL LOGIN authentication failed: "+reply+", sasl_username=Invalid authentication mechanism")
			if calls := smtpCalls(d); calls != 0 {
				t.Fatalf("backend failure recorded %d credential failures", calls)
			}
			if len(d.smtpAuthTracker.pendingVerdicts) != 0 {
				t.Fatal("backend failure left a reusable verdict")
			}
			feed(d, clock, fmt.Sprintf(postfixFailFmt, "203.0.113.73", "a"))
			if calls := smtpCalls(d); calls != 0 {
				t.Fatalf("later failure reused withheld evidence: calls=%d", calls)
			}
		})
	}
}

func TestPostfixUsernameCannotForgeFailureReason(t *testing.T) {
	for _, name := range []string{
		"Connection lost to authentication server",
		"Temporary authentication failure",
		"Authentication backend error",
		"Invalid authentication mechanism",
		"Invalid base64 data in continued response",
		"Authentication request timed out",
		"a, sasl_username=Authentication backend error",
	} {
		t.Run(name, func(t *testing.T) {
			d, clock := newPairingDaemon(t, &config.Config{})
			feed(d, clock,
				"dovecot: auth: sql(a,203.0.113.73): Password mismatch",
				fmt.Sprintf(postfixFailFmt, "203.0.113.73", name))
			if calls := smtpCalls(d); calls != 1 {
				t.Fatalf("username suppressed a credential failure: calls=%d", calls)
			}
		})
	}
}
