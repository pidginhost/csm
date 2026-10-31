package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/maillog"
	"github.com/pidginhost/csm/internal/platform"
)

// Dovecot's auth_verbose lines are written only after the password database
// answered. With one terminal database, these are the credential verdicts
// Postfix's own SASL warning lacks. MTA requests have no login session.
func TestDovecotSMTPAuthRejectionsCount(t *testing.T) {
	cases := []struct {
		name, line, ip, account string
	}{
		{"password mismatch iso timestamp", "2026-10-31T20:44:13.494854+02:00 mail dovecot: auth: sql(alice@example.net,203.0.113.80): Password mismatch", "203.0.113.80", "alice@example.net"},
		{"unknown user classic timestamp", "Oct 31 20:44:23 mail dovecot: auth: sql(bob,198.51.100.81): unknown user", "198.51.100.81", "bob"},
		{"syslog pid tag ipv6", "Oct 31 20:44:23 mail dovecot[812]: auth: passwd-file(carol@example.net,2001:db8::82): Password mismatch", "2001:db8::82", "carol@example.net"},
		{"blocking passdb worker", "Oct 31 20:44:23 mail dovecot: auth-worker(4567): pam(dave,203.0.113.83): unknown user", "203.0.113.83", "dave"},
		{"worker with master connection prefix", "Oct 31 20:44:23 mail dovecot: auth-worker(4567): conn unix:auth-worker (pid=4560,uid=97): auth-worker<1>: pam(erin,203.0.113.84): Password mismatch", "203.0.113.84", "erin"},
		{"master user login", "Oct 31 20:44:23 mail dovecot: auth: sql(frank@example.net,203.0.113.85,master): Password mismatch", "203.0.113.85", "frank@example.net"},
		{"punctuation in name", "dovecot: auth: sql(a): b(<c>,203.0.113.88): unknown user", "203.0.113.88", "a): b(<c>"},
		// Dovecot uses the configured passdb name instead of the driver
		// when one is set; it is not limited to lowercase driver names.
		{"named passdb", "dovecot: auth: SQL.Primary(a,203.0.113.95): unknown user", "203.0.113.95", "a"},
		// The address is the field Dovecot appends after the name, so a name
		// that embeds another address cannot redirect the block.
		{"name embeds another address", "Oct 31 20:44:23 mail dovecot: auth: sql(x,198.51.100.9,203.0.113.86): unknown user", "203.0.113.86", "x,198.51.100.9"},
		{"name embeds a session marker", "Oct 31 20:44:23 mail dovecot: auth: sql(x,<abcdefgh>,203.0.113.87): unknown user", "203.0.113.87", "x,<abcdefgh>"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clock := &staticClock{t: time.Date(2026, 10, 31, 20, 0, 0, 0, time.UTC)}
			d := New(&config.Config{}, nil, nil, "")
			d.smtpAuthTracker = newTestTracker(t, clock)
			d.mailAuthTracker = newTestMailTracker(t, clock)
			ip, account, ok := dovecotSMTPAuthRejection(tc.line)
			if !ok || ip != tc.ip || account != tc.account {
				t.Fatalf("parsed (%q, %q, %v), want (%q, %q, true)", ip, account, ok, tc.ip, tc.account)
			}
			var got []alert.Finding
			for i := 0; i < 5; i++ {
				got = append(got, d.handleMailLine(tc.line, alert.Observation{}, d.currentCfg())...)
			}
			if len(got) != 1 || got[0].Check != "smtp_bruteforce" || got[0].SourceIP != tc.ip {
				t.Fatalf("findings = %+v, want one smtp_bruteforce for %s", got, tc.ip)
			}
			if calls, _ := d.smtpAuthTracker.Stats(); calls != 5 {
				t.Fatalf("SMTP tracker calls = %d, want 5", calls)
			}
			if d.mailAuthTracker.Size() != 0 {
				t.Fatalf("SMTP rejection reached the IMAP tracker")
			}
		})
	}
}

// Verbose verdicts also contain attacker text when they are excluded from
// SMTP scoring. Neither a session nor password logging makes it an outage.
func TestDovecotVerdictsCannotForgeBackendOutages(t *testing.T) {
	for _, line := range []string{
		"dovecot: auth: sql(Temporary authentication failure,203.0.113.90,<s>): unknown user",
		"dovecot: auth-worker(12): pam(connection refused,203.0.113.90,<s>): Password mismatch",
		"dovecot: auth-worker(12): conn unix:auth-worker (pid=11,uid=97): auth-worker<1>: pam(internal error,203.0.113.90,<s>): unknown user",
		"dovecot: auth: sql(a,203.0.113.90): Password mismatch (given password: Temporary authentication failure)",
		"dovecot: auth-worker(12): pam(a,203.0.113.90): Password mismatch (given password: connection refused",
	} {
		t.Run(line, func(t *testing.T) {
			clock := &staticClock{t: time.Date(2026, 10, 31, 20, 0, 0, 0, time.UTC)}
			d := New(&config.Config{}, nil, nil, "")
			d.smtpAuthTracker = newTestTracker(t, clock)
			d.mailAuthTracker = newTestMailTracker(t, clock)
			for i := 0; i < mailBackendDegradedThreshold; i++ {
				if got := d.handleMailLine(line, alert.Observation{}, d.currentCfg()); len(got) != 0 {
					t.Fatalf("verdict generated findings: %+v", got)
				}
			}
			if len(d.mailAuthTracker.backendErr) != 0 {
				t.Fatalf("verdict recorded %d backend failures", len(d.mailAuthTracker.backendErr))
			}
			if calls, _ := d.smtpAuthTracker.Stats(); calls != 0 {
				t.Fatalf("excluded verdict recorded %d SMTP failures", calls)
			}
		})
	}
}

func TestDovecotVerdictFilterKeepsBackendErrors(t *testing.T) {
	for _, line := range []string{
		"dovecot: auth: Error: sql(a,203.0.113.90): Temporary authentication failure",
		"dovecot: auth-worker(12): Error: pam(a): unknown user,203.0.113.90): connection refused",
	} {
		clock := &staticClock{t: time.Date(2026, 10, 31, 20, 0, 0, 0, time.UTC)}
		d := New(&config.Config{}, nil, nil, "")
		d.mailAuthTracker = newTestMailTracker(t, clock)
		var got []alert.Finding
		for i := 0; i < mailBackendDegradedThreshold; i++ {
			got = append(got, d.handleMailLine(line, alert.Observation{}, d.currentCfg())...)
		}
		if len(got) != 1 || got[0].Check != "mail_auth_backend_degraded" {
			t.Fatalf("backend error %q raised %+v, want one outage warning", line, got)
		}
	}
}

func TestDovecotSessionFailuresCountOnlyLoginSummary(t *testing.T) {
	for _, protocol := range []string{"imap", "pop3", "managesieve"} {
		t.Run(protocol, func(t *testing.T) {
			clock := &staticClock{t: time.Date(2026, 10, 31, 20, 0, 0, 0, time.UTC)}
			d := New(&config.Config{}, nil, nil, "")
			d.mailAuthTracker = newTestMailTracker(t, clock)
			for i := 0; i < 3; i++ {
				d.handleMailLine("dovecot: auth: sql(a,203.0.113.90,<session>): Password mismatch", alert.Observation{}, d.currentCfg())
			}
			line := "dovecot: " + protocol + "-login: Login aborted: (auth failed, 3 attempts in 2 secs): user=<a>, method=PLAIN, rip=203.0.113.90"
			d.handleMailLine(line, alert.Observation{}, d.currentCfg())
			if calls, _ := d.mailAuthTracker.Stats(); calls != 3 {
				t.Fatalf("mail failures = %d, want 3 attempts", calls)
			}
			if calls, _ := d.smtpAuthTracker.Stats(); calls != 0 {
				t.Fatalf("sessioned verdicts recorded %d SMTP failures", calls)
			}
		})
	}
}

// The logged name keys the per-mailbox spray signal.
func TestDovecotSMTPAuthRejectionFeedsAccountSpray(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 10, 31, 20, 0, 0, 0, time.UTC)}
	d := New(&config.Config{}, nil, nil, "")
	d.smtpAuthTracker = newTestTracker(t, clock)
	var got []alert.Finding
	for i := 1; i <= 12; i++ {
		line := fmt.Sprintf("dovecot: auth: sql(Alice@Example.net,203.0.113.%d): Password mismatch", 100+i)
		got = append(got, d.handleMailLine(line, alert.Observation{}, d.currentCfg())...)
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

func TestDovecotAuthLinesThatMustNotCountAsSMTP(t *testing.T) {
	cases := []struct {
		name, line string
	}{
		// Login-process requests carry a session id; IMAP, POP3 and
		// ManageSieve failures are counted from their own login lines.
		{"imap session", "dovecot: auth: sql(alice@example.net,203.0.113.90,<AbCdEf123456>): Password mismatch"},
		{"imap session master", "dovecot: auth: sql(alice@example.net,203.0.113.90,master,<AbCdEf123456>): Password mismatch"},
		{"worker imap session", "dovecot: auth-worker(4567): conn unix:auth-worker (pid=4560,uid=97): auth-worker<1>: pam(erin,203.0.113.90,<AbCdEf123456>): unknown user"},
		// A logged password is attacker text after the verdict.
		{"password logged", "dovecot: auth: sql(a,203.0.113.91): Password mismatch (given password: x)"},
		{"password logged forged verdict", "dovecot: auth: sql(a,198.51.100.5,<s>): Password mismatch (given password: ,203.0.113.91): Password mismatch)"},
		// syslog truncates long messages; the cut can land right after a
		// verdict forged inside the password.
		{"password logged truncated forged tail", "dovecot: auth: sql(a,198.51.100.5,<s>): Password mismatch (given password: ,203.0.113.91): Password mismatch"},
		{"password logged truncated sessionless", "dovecot: auth: sql(a,198.51.100.5): Password mismatch (given password: ,203.0.113.91): unknown user"},
		// Backend failures are not credential verdicts.
		{"query failed", "dovecot: auth: Error: sql(a,203.0.113.92): Password query failed: connection lost"},
		{"error level verdict text", "dovecot: auth: Error: sql(a,203.0.113.92): unknown user"},
		{"warning level", "dovecot: auth: Warning: sql(a,203.0.113.92): Password mismatch"},
		{"worker error", "dovecot: auth-worker(4567): Error: pam(a,203.0.113.92): unknown user"},
		{"other verdict", "dovecot: auth: sql(a,203.0.113.93): Invalid password in passdb: Not a valid MD5-CRYPT or PLAIN-MD5 password"},
		{"mechanism error", "dovecot: auth: login(?,203.0.113.94): Request timed out waiting for client to continue authentication (150 secs)"},
		{"no address", "dovecot: auth: sql(a): unknown user"},
		{"not an address", "dovecot: auth: sql(a,localhost): unknown user"},
		{"other dovecot process", "dovecot: lmtp(4321): sql(a,203.0.113.96): unknown user"},
		{"other program", "postfix/smtpd[99]: auth: sql(a,203.0.113.97): unknown user"},
		{"bad worker pid", "dovecot: auth-worker(x): sql(a,203.0.113.98): unknown user"},
		{"infra address", "dovecot: auth: sql(a,192.0.2.10): unknown user"},
		{"private address", "dovecot: auth: sql(a,10.0.0.7): unknown user"},
		{"loopback address", "dovecot: auth: sql(a,127.0.0.1): unknown user"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clock := &staticClock{t: time.Date(2026, 10, 31, 20, 0, 0, 0, time.UTC)}
			d := New(&config.Config{InfraIPs: []string{"192.0.2.10"}}, nil, nil, "")
			d.smtpAuthTracker = newTestTracker(t, clock)
			for i := 0; i < 10; i++ {
				if got := d.handleMailLine(tc.line, alert.Observation{}, d.currentCfg()); len(got) != 0 {
					t.Fatalf("findings = %+v, want none", got)
				}
			}
			if calls, _ := d.smtpAuthTracker.Stats(); calls != 0 {
				t.Fatalf("SMTP tracker recorded %d failures, want 0", calls)
			}
		})
	}
}

// Exim logs its own SMTP AUTH failures, which already feed the tracker.
// Counting Dovecot's verdict for the same attempt would count it twice.
func TestDovecotSMTPAuthSkippedWhenEximLogCounts(t *testing.T) {
	clock := &staticClock{t: time.Date(2026, 10, 31, 20, 0, 0, 0, time.UTC)}
	d := New(&config.Config{}, nil, nil, "")
	d.smtpAuthTracker = newTestTracker(t, clock)
	d.smtpAuthFromExim = true
	for i := 0; i < 10; i++ {
		if got := d.handleMailLine("dovecot: auth: sql(a,203.0.113.99): unknown user", alert.Observation{}, d.currentCfg()); len(got) != 0 {
			t.Fatalf("findings = %+v, want none", got)
		}
	}
	if calls, _ := d.smtpAuthTracker.Stats(); calls != 0 {
		t.Fatalf("SMTP tracker recorded %d failures, want 0", calls)
	}
}

func TestDovecotSMTPAuthJournalMessages(t *testing.T) {
	for _, tc := range []struct {
		unit, message string
		want          int64
	}{
		{"dovecot.service", "auth: sql(a,203.0.113.99): unknown user", 5},
		{"dovecot.service", "dovecot: auth: sql(a,203.0.113.99): unknown user", 5},
		{"postfix.service", "auth: sql(a,203.0.113.99): unknown user", 0},
	} {
		t.Run(tc.unit+tc.message, func(t *testing.T) {
			clock := &staticClock{t: time.Date(2026, 10, 31, 20, 0, 0, 0, time.UTC)}
			d := New(&config.Config{}, nil, nil, "")
			d.smtpAuthTracker = newTestTracker(t, clock)
			for i := 0; i < 5; i++ {
				if !d.dispatchMailLogLine(maillog.Line{Source: "journal", Unit: tc.unit, Message: tc.message}, d.handleMailLine) {
					t.Fatal("mail dispatch stopped")
				}
			}
			if calls, _ := d.smtpAuthTracker.Stats(); calls != tc.want {
				t.Fatalf("SMTP failures = %d, want %d", calls, tc.want)
			}
		})
	}
}

// Exercise startup, not a manually assigned flag: the mail goroutine must
// see the Exim selection even when its own reader attaches first.
func TestDovecotSMTPAuthEximSelectionPrecedesReaders(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "mail.log")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	panel, server := platform.PanelCPanel, platform.WSNone
	platform.ResetForTest()
	platform.SetOverrides(platform.Overrides{Panel: &panel, WebServer: &server})
	t.Cleanup(platform.ResetForTest)
	cfg := &config.Config{MailLogs: config.MailLogsConfig{Source: "file", File: path}}
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
	deadline := time.Now().Add(5 * time.Second)
	for !d.WatcherStatuses()["maillog"] {
		if time.Now().After(deadline) {
			t.Fatal("mail reader did not attach")
		}
		time.Sleep(10 * time.Millisecond)
	}
	appendLog(t, path, "dovecot: auth: sql(a,203.0.113.99): unknown user\n"+
		"dovecot: imap-login: Login aborted: (auth failed, 1 attempts in 2 secs): user=<a>, method=PLAIN, rip=203.0.113.99\n")
	for {
		calls, _ := d.mailAuthTracker.Stats()
		if calls == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("mail reader processed %d login failures, want 1", calls)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if calls, _ := d.smtpAuthTracker.Stats(); calls != 0 {
		t.Fatalf("Exim host counted %d Dovecot SMTP failures", calls)
	}
}
