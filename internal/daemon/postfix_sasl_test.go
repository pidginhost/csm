package daemon

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// Older Postfix logs name only the client; newer versions can append the
// attempted account. Both must count, even when the account resembles a
// backend error. Include both rsyslog timestamp formats and per-service tags.
func TestPostfixSASLFailuresRaiseSMTPBruteForce(t *testing.T) {
	cases := []struct {
		name, format, ip string
	}{
		{"submission iso timestamp", "2026-10-31T12:34:11.494854+02:00 mail postfix/submission/smtpd[2207002]: warning: unknown[%s]: SASL LOGIN authentication failed: UGFzc3dvcmQ6", "203.0.113.50"},
		{"smtpd classic timestamp", "Oct 31 12:34:11 mail postfix/smtpd[1234]: warning: mx.example.net[%s]: SASL PLAIN authentication failed: ", "198.51.100.23"},
		{"ipv6 client", "Oct 31 12:34:11 mail postfix/submission/smtpd[99]: warning: unknown[%s]: SASL LOGIN authentication failed: authentication failure", "2001:db8::5"},
		{"no reply text", "Oct 31 12:34:11 mail postfix/smtpd[1234]: warning: unknown[%s]: SASL LOGIN authentication failed", "203.0.113.51"},
		{"client port logging", "Oct 31 12:34:11 mail postfix/smtpd[1234]: warning: unknown[%s]:51234: SASL LOGIN authentication failed: UGFzc3dvcmQ6", "203.0.113.52"},
		{"client port logging ipv6", "Oct 31 12:34:11 mail postfix/smtpd[1234]: warning: unknown[%s]:51234: SASL LOGIN authentication failed: UGFzc3dvcmQ6", "2001:db8::6"},
		{"username resembles outage", "Oct 31 12:34:11 mail postfix/smtpd[1234]: warning: unknown[%s]: SASL PLAIN authentication failed: authentication failure, sasl_username=temporary@example.net", "203.0.113.53"},
		{"username contains server phrase", "Oct 31 12:34:11 mail postfix/smtpd[1234]: warning: unknown[%s]: SASL LOGIN authentication failed: (reason unavailable), sasl_username=authentication server", "203.0.113.54"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clock := &staticClock{t: time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)}
			d := New(&config.Config{}, nil, nil, "")
			d.smtpAuthTracker = newTestTracker(t, clock)
			var got []alert.Finding
			for i := 0; i < 5; i++ {
				got = append(got, d.handleMailLine(fmt.Sprintf(tc.format, tc.ip), alert.Observation{}, d.currentCfg())...)
			}
			if len(got) != 1 || got[0].Check != "smtp_bruteforce" || got[0].SourceIP != tc.ip {
				t.Fatalf("findings = %+v, want one smtp_bruteforce for %s after 5 failures", got, tc.ip)
			}
		})
	}
}

// Lines that look like SMTP AUTH failures but are not the client's fault, or
// do not come from postfix smtpd, must not count toward a block.
func TestPostfixSASLLinesThatMustNotCount(t *testing.T) {
	cases := []struct {
		name, line string
	}{
		{"auth server lost", "Oct 31 12:34:11 mail postfix/submission/smtpd[99]: warning: unknown[203.0.113.60]: SASL PLAIN authentication failed: Connection lost to authentication server"},
		{"auth server temporary failure", "Oct 31 12:34:11 mail postfix/submission/smtpd[99]: warning: unknown[203.0.113.61]: SASL PLAIN authentication failed: Temporary authentication failure"},
		{"auth backend error", "Oct 31 12:34:11 mail postfix/submission/smtpd[99]: warning: unknown[203.0.113.61]: SASL PLAIN authentication failed: Authentication backend error"},
		{"auth backend error with username", "Oct 31 12:34:11 mail postfix/submission/smtpd[99]: warning: unknown[203.0.113.61]: SASL PLAIN authentication failed: Authentication backend error, sasl_username=alice@example.net"},
		{"auth server connect failure", "Oct 31 12:34:11 mail postfix/smtpd[99]: warning: unknown[203.0.113.61]: SASL PLAIN authentication failed: Can't connect to authentication server"},
		{"cyrus generic failure", "Oct 31 12:34:11 mail postfix/smtpd[99]: warning: unknown[203.0.113.61]: SASL PLAIN authentication failed: generic failure"},
		{"cyrus memory failure", "Oct 31 12:34:11 mail postfix/smtpd[99]: warning: unknown[203.0.113.61]: SASL PLAIN authentication failed: no memory available"},
		{"cyrus transient failure", "Oct 31 12:34:11 mail postfix/smtpd[99]: warning: unknown[203.0.113.61]: SASL PLAIN authentication failed: transient failure (e.g., weak key)"},
		{"cyrus server unavailable", "Oct 31 12:34:11 mail postfix/smtpd[99]: warning: unknown[203.0.113.61]: SASL PLAIN authentication failed: remote authentication server unavailable"},
		{"other program", "Oct 31 12:34:11 mail dovecot: warning: unknown[203.0.113.62]: SASL LOGIN authentication failed: UGFzc3dvcmQ6"},
		{"postfix non-smtpd", "Oct 31 12:34:11 mail postfix/smtp[99]: warning: unknown[203.0.113.63]: SASL LOGIN authentication failed: UGFzc3dvcmQ6"},
		{"aborted by client", "Oct 31 12:34:11 mail postfix/smtpd[99]: warning: unknown[203.0.113.64]: SASL LOGIN authentication aborted"},
		{"infra address", "Oct 31 12:34:11 mail postfix/smtpd[99]: warning: unknown[192.0.2.10]: SASL LOGIN authentication failed: UGFzc3dvcmQ6"},
		{"private address", "Oct 31 12:34:11 mail postfix/smtpd[99]: warning: unknown[10.0.0.7]: SASL LOGIN authentication failed: UGFzc3dvcmQ6"},
		{"client field without brackets", "Oct 31 12:34:11 mail postfix/smtpd[99]: warning: 203.0.113.68x: SASL LOGIN authentication failed: UGFzc3dvcmQ6"},
		{"not an address", "Oct 31 12:34:11 mail postfix/smtpd[99]: warning: unknown[localhost]: SASL LOGIN authentication failed: UGFzc3dvcmQ6"},
		// smtpd echoes client-supplied text into other warnings; it must not
		// name an address of the client's choosing.
		{"client text in another warning", "Oct 31 12:34:11 mail postfix/smtpd[99]: warning: Illegal address syntax from unknown[203.0.113.65] in RCPT command: <x[198.51.100.9]: SASL LOGIN authentication failed: x>"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clock := &staticClock{t: time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)}
			d := New(&config.Config{InfraIPs: []string{"192.0.2.10"}}, nil, nil, "")
			d.smtpAuthTracker = newTestTracker(t, clock)
			for i := 0; i < 10; i++ {
				if got := d.handleMailLine(tc.line, alert.Observation{}, d.currentCfg()); len(got) != 0 {
					t.Fatalf("findings = %+v, want none", got)
				}
			}
			if calls, _ := d.smtpAuthTracker.Stats(); calls != 0 {
				t.Fatalf("tracker recorded %d failures, want 0", calls)
			}
		})
	}
}

// The client address is the bracketed one that closes the client field, so
// a hostname carrying brackets cannot steer the block at another address.
func TestPostfixSASLFailureTracksTheClientAddress(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)}
	d := New(&config.Config{}, nil, nil, "")
	d.smtpAuthTracker = newTestTracker(t, clock)
	line := "Oct 31 12:34:11 mail postfix/smtpd[99]: warning: x[198.51.100.99].example[203.0.113.70]: SASL LOGIN authentication failed: UGFzc3dvcmQ6"
	var got []alert.Finding
	for i := 0; i < 5; i++ {
		got = append(got, d.handleMailLine(line, alert.Observation{}, d.currentCfg())...)
	}
	if len(got) != 1 || got[0].SourceIP != "203.0.113.70" {
		t.Fatalf("findings = %+v, want one finding for 203.0.113.70", got)
	}
}

// xsasl_dovecot_server_first returns XSASL_AUTH_TEMP without changing the
// reply when reconnect fails. The warning can reuse any earlier SASL reply.
func TestPostfixSASLReconnectFailureDoesNotCount(t *testing.T) {
	for _, diagnostic := range []string{
		"SASL: Connect to Dovecot auth socket 'private/auth' failed: Connection refused",
		"SASL: Couldn't send handshake: Broken pipe",
		"SASL: Protocol version error",
		"SASL: Protocol version mismatch (2 vs. 1)",
		"SASL: Connected to wrong auth socket (auth-master instead of auth-client)",
	} {
		for _, reply := range []string{"", "(reason unavailable)", "UGFzc3dvcmQ6", "authentication failure"} {
			t.Run(diagnostic+"/"+reply, func(t *testing.T) {
				clock := &staticClock{t: time.Now()}
				d := New(&config.Config{}, nil, nil, "")
				d.smtpAuthTracker = newTestTracker(t, clock)
				const prefix = "Oct 31 12:34:11 mail postfix/submission/smtpd[99]: warning: "
				for i := 0; i < 10; i++ {
					if got := d.handleMailLine(prefix+diagnostic, alert.Observation{}, d.currentCfg()); len(got) != 0 {
						t.Fatalf("backend diagnostic raised findings: %+v", got)
					}
					line := prefix + "unknown[203.0.113.61]: SASL PLAIN authentication failed: " + reply
					if got := d.handleMailLine(line, alert.Observation{}, d.currentCfg()); len(got) != 0 {
						t.Fatalf("backend failure raised findings: %+v", got)
					}
				}
				if calls, _ := d.smtpAuthTracker.Stats(); calls != 0 {
					t.Fatalf("backend failures entered tracker: %d calls", calls)
				}
				// The next result from a recovered backend must start fresh.
				for i := 0; i < 5; i++ {
					got := d.handleMailLine(prefix+"unknown[203.0.113.61]: SASL PLAIN authentication failed: "+reply, alert.Observation{}, d.currentCfg())
					want := 0
					if i == 4 {
						want = 1
					}
					if len(got) != want || (want == 1 && (got[0].Check != "smtp_bruteforce" || got[0].SourceIP != "203.0.113.61")) {
						t.Fatalf("recovery attempt %d: findings = %+v", i+1, got)
					}
				}
			})
		}
	}
}

func TestPostfixSASLBackendErrorsStayWithTheirProcess(t *testing.T) {
	clock := &staticClock{t: time.Now()}
	d := New(&config.Config{}, nil, nil, "")
	d.smtpAuthTracker = newTestTracker(t, clock)
	const diagnostic = "warning: SASL: Connect to Dovecot auth socket 'private/auth' failed: Connection refused"
	const failed = "warning: unknown[203.0.113.61]: SASL PLAIN authentication failed: (reason unavailable)"
	for i := 0; i < 5; i++ {
		// Both the PID and the service distinguish independent workers.
		for _, tag := range []string{"postfix/smtpd[98]", "postfix/submission/smtpd[99]"} {
			if got := d.handleMailLine(tag+": "+diagnostic, alert.Observation{}, d.currentCfg()); len(got) != 0 {
				t.Fatalf("backend diagnostic raised findings: %+v", got)
			}
		}
		got := d.handleMailLine("postfix/smtpd[99]: "+failed, alert.Observation{}, d.currentCfg())
		want := 0
		if i == 4 {
			want = 1
		}
		if len(got) != want || (want == 1 && got[0].Check != "smtp_bruteforce") {
			t.Fatalf("healthy worker attempt %d: findings = %+v", i+1, got)
		}
	}
}

func TestPostfixSASLWarningGrammar(t *testing.T) {
	for _, msg := range []string{
		// The AUTH mechanism is client-supplied, including quotes and spaces.
		`unknown[203.0.113.61]: SASL "LOGIN authentication failed: x" authentication aborted`,
		"unknown[203.0.113.61]: SASL LOGIN authentication failedness: x",
		"203.0.113.61]: SASL LOGIN authentication failed: x",
		"unknown[203.0.113.61]:not-a-port: SASL LOGIN authentication failed: x",
		"unknown[203.0.113.61]:70000: SASL LOGIN authentication failed: x",
		"unknown[203.0.113.61]: SASL LOGIN authentication failed: x",
	} {
		line := "postfix/smtpd[99]: warning: " + msg
		want := ""
		if msg == "unknown[203.0.113.61]: SASL LOGIN authentication failed: x" {
			want = "203.0.113.61"
		}
		if got := postfixSASLFailureIP(line); got != want {
			t.Errorf("%q: got %q, want %q", line, got, want)
		}
	}
}

func TestPostfixSASLBackendCorrelationLifecycle(t *testing.T) {
	const diagnostic = "postfix/smtpd[99]: warning: SASL: Couldn't send handshake: Broken pipe"
	const failed = "postfix/smtpd[99]: warning: unknown[203.0.113.61]: SASL PLAIN authentication failed: (reason unavailable)"
	for _, boundary := range []string{
		"connect from unknown[203.0.113.61]",
		"warning: unknown[203.0.113.61]: SASL PLAIN authentication failed: Authentication backend error",
	} {
		t.Run(boundary, func(t *testing.T) {
			tr := newTestTracker(t, &staticClock{t: time.Now()})
			if got := tr.postfixSASLFailureIP(diagnostic); got != "" {
				t.Fatalf("diagnostic names %q", got)
			}
			if got := tr.postfixSASLFailureIP("postfix/smtpd[99]: " + boundary); got != "" {
				t.Fatalf("boundary names %q", got)
			}
			if got := tr.postfixSASLFailureIP(failed); got != "203.0.113.61" {
				t.Fatalf("next connection or AUTH result names %q", got)
			}
		})
	}
	var tr *smtpAuthTracker
	if got := tr.postfixSASLFailureIP(failed); got != "" {
		t.Fatalf("disabled tracker names %q", got)
	}
}

func TestPostfixSASLBackendCorrelationBudget(t *testing.T) {
	clock := &staticClock{t: time.Now()}
	tr := newTestTracker(t, clock)
	tr.maxTracked = 2
	for i := 0; i < 3; i++ {
		line := fmt.Sprintf("postfix/smtpd[%d]: warning: SASL: Protocol version error", i+1)
		if got := tr.postfixSASLFailureIP(line); got != "" {
			t.Fatalf("diagnostic names %q", got)
		}
	}
	if got := len(tr.postfixBackendErrors); got != 2 {
		t.Fatalf("pending errors = %d, want bounded at 2", got)
	}
	const failed = "postfix/smtpd[3]: warning: unknown[203.0.113.61]: SASL PLAIN authentication failed: (reason unavailable)"
	if got := tr.postfixSASLFailureIP(failed); got != "" {
		t.Fatalf("overflow lost a backend error: names %q", got)
	}
	clock.advance(tr.window)
	tr.Purge()
	if got := len(tr.postfixBackendErrors); got != 0 {
		t.Fatalf("expired errors = %d, want 0", got)
	}
	if got := tr.postfixSASLFailureIP(failed); got != "203.0.113.61" {
		t.Fatalf("expired overflow still suppresses: names %q", got)
	}
}

func TestPostfixSASLBackendCorrelationConcurrentWorkers(t *testing.T) {
	tr := newTestTracker(t, &staticClock{t: time.Now()})
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Go(func() {
			prefix := fmt.Sprintf("postfix/smtpd[%d]: warning: ", i+1)
			if got := tr.postfixSASLFailureIP(prefix + "SASL: Protocol version error"); got != "" {
				t.Errorf("diagnostic names %q", got)
			}
			tr.Purge()
			if got := tr.postfixSASLFailureIP(prefix + "unknown[203.0.113.61]: SASL PLAIN authentication failed: (reason unavailable)"); got != "" {
				t.Errorf("reconnect failure names %q", got)
			}
		})
	}
	wg.Wait()
	if got := len(tr.postfixBackendErrors); got != 0 {
		t.Fatalf("consumed errors retained: %d", got)
	}
}

func TestPostfixSASLOutageDoesNotAccumulateSubnetEvidence(t *testing.T) {
	clock := &staticClock{t: time.Now()}
	d := New(&config.Config{}, nil, nil, "")
	d.smtpAuthTracker = newTestTracker(t, clock)
	for i := 1; i <= 10; i++ {
		prefix := fmt.Sprintf("postfix/smtpd[%d]: warning: ", i)
		for _, msg := range []string{
			"SASL: Couldn't send handshake: Broken pipe",
			fmt.Sprintf("unknown[203.0.113.%d]: SASL PLAIN authentication failed: (reason unavailable)", i),
		} {
			if got := d.handleMailLine(prefix+msg, alert.Observation{}, d.currentCfg()); len(got) != 0 {
				t.Fatalf("outage raised findings: %+v", got)
			}
		}
	}
	if calls, _ := d.smtpAuthTracker.Stats(); calls != 0 || d.smtpAuthTracker.Size() != 0 {
		t.Fatalf("outage left evidence: %d calls, %d entries", calls, d.smtpAuthTracker.Size())
	}
	for i := 1; i <= 8; i++ {
		obs := alert.Observation{Producer: "mail_log", Stream: "mail", Cursor: fmt.Sprint(i), ObservedAt: clock.Now()}
		line := fmt.Sprintf("postfix/smtpd[%d]: warning: unknown[203.0.113.%d]: SASL PLAIN authentication failed: (reason unavailable)", i, i)
		got := d.handleMailLine(line, obs, d.currentCfg())
		want := 0
		if i == 8 {
			want = 1
		}
		if len(got) != want {
			t.Fatalf("recovery attempt %d raised %+v", i, got)
		}
		if want == 1 && (got[0].Check != "smtp_subnet_spray" || len(got[0].SprayConstituents) != 8) {
			t.Fatalf("subnet evidence missing: %+v", got)
		}
	}
}

func TestPostfixSASLActiveProbeOutageDoesNotAccumulate(t *testing.T) {
	d := New(&config.Config{}, nil, nil, "")
	d.smtpAuthTracker = newTestTracker(t, &staticClock{t: time.Now()})
	down := true
	d.smtpAuthTracker.SetBackendDownCheck(func() bool { return down })
	const line = "postfix/smtpd[99]: warning: unknown[203.0.113.61]: SASL PLAIN authentication failed: (reason unavailable)"
	for i := 0; i < 10; i++ {
		if got := d.handleMailLine(line, alert.Observation{}, d.currentCfg()); len(got) != 0 {
			t.Fatalf("active probe outage raised findings: %+v", got)
		}
	}
	if calls, _ := d.smtpAuthTracker.Stats(); calls != 0 || d.smtpAuthTracker.Size() != 0 {
		t.Fatalf("active probe outage left evidence: %d calls, %d entries", calls, d.smtpAuthTracker.Size())
	}
	down = false
	if got := d.handleMailLine(line, alert.Observation{}, d.currentCfg()); len(got) != 0 {
		t.Fatalf("outage traffic caused a block after recovery: %+v", got)
	}
	if calls, _ := d.smtpAuthTracker.Stats(); calls != 1 {
		t.Fatalf("recovered backend not counted: %d calls", calls)
	}
}
