package daemon

// Fuzz tests for log parsers that process attacker-controlled input.
// These parsers are fed every line of access logs, error logs, auth logs,
// mail logs, and WAF audit logs — any of which can contain attacker-chosen
// bytes. A single crafted log line that panics the daemon is a remote DoS,
// so every parser must survive arbitrary input without crashing.
//
// Run locally with:
//   go test -fuzz=FuzzParseModSecLogLine -fuzztime=60s ./internal/daemon/
//
// CI runs these with the regular test command (which exercises the seed
// corpus). Long fuzzing is expected to happen nightly or on-demand.

import (
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// Shared minimal config for fuzz tests. The parsers read Suppressions,
// InfraIPs, and similar fields but only for filtering; we want maximum
// coverage so we leave everything empty (most permissive).
func fuzzConfig() *config.Config {
	return &config.Config{}
}

// FuzzParseModSecLogLine exercises the ModSecurity error-log parser with
// arbitrary input. Real ModSec error lines look like:
//
//	[Wed Apr 01 15:15:05 2026] [error] [client 1.2.3.4] ModSecurity: Access denied with code 403 [id "920420"] [msg "..."]
//
// but the parser must not panic on truncated lines, missing brackets,
// unicode, nulls, very long lines, or malformed IP/rule fields.
func FuzzParseModSecLogLine(f *testing.F) {
	seeds := []string{
		"",
		" ",
		"\n",
		"\x00\x00\x00",
		`[Wed Apr 01 15:15:05 2026] [error] [client 1.2.3.4] ModSecurity: Access denied with code 403 [id "920420"] [msg "Test"]`,
		`[client 1.2.3.4] ModSecurity`,
		`[client ] ModSecurity:`,
		`ModSecurity: [id "999999"]`,
		`[id "920420"]`,
		`[client 999.999.999.999]`,
		`[client ::1] ModSecurity: Access denied`,
		`[client 2001:db8::1] ModSecurity: Access denied with code 403 [id "900001"]`,
		// Unicode, control chars, embedded newlines (shouldn't happen in
		// practice but let's prove we survive)
		"ModSecurity: \u0000\u0001\u0002 Access denied",
		"ModSecurity: 日本語 [id \"1\"]",
		// Extremely long line
		string(make([]byte, 64*1024)),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		cfg := fuzzConfig()
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("parseModSecLogLine panicked on input %q: %v", line, r)
			}
		}()
		_ = parseModSecLogLine(line, cfg)
	})
}

// FuzzParseModSecLogLineDeduped exercises the dedup+escalation wrapper.
// The wrapper has additional state-tracking logic (escalation counters,
// dedup TTL), so it's worth fuzzing separately.
func FuzzParseModSecLogLineDeduped(f *testing.F) {
	seeds := []string{
		"",
		`[Wed Apr 01 15:15:05 2026] [error] [client 1.2.3.4] ModSecurity: Access denied with code 403 [id "920420"] [msg "Test"]`,
		`[Wed Apr 01 15:15:06 2026] [error] [client 1.2.3.4] ModSecurity: Access denied with code 403 [id "900001"] [msg "CSM custom rule"]`,
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		cfg := fuzzConfig()
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("parseModSecLogLineDeduped panicked on input %q: %v", line, r)
			}
		}()
		_ = parseModSecLogLineDeduped(line, cfg)
	})
}

// FuzzParseAccessLogBruteForce exercises the Apache/Nginx Combined Log
// Format parser that drives wp-login and xmlrpc real-time brute force.
// Example real line:
//
//	1.2.3.4 - - [01/Apr/2026:15:15:05 +0000] "POST /wp-login.php HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
func FuzzParseAccessLogBruteForce(f *testing.F) {
	seeds := []string{
		"",
		"POST",
		`1.2.3.4 - - [01/Apr/2026:15:15:05 +0000] "POST /wp-login.php HTTP/1.1" 200 1234 "-" "Mozilla/5.0"`,
		`1.2.3.4 - - [01/Apr/2026:15:15:05 +0000] "POST /xmlrpc.php HTTP/1.1" 200 1234 "-" "curl"`,
		`- - - [] "GET / HTTP/1.1" 200 0 "-" "-"`,
		`999.999.999.999 - - [01/Apr/2026:15:15:05 +0000] "POST /wp-login.php HTTP/1.1" 401 0 "-" "-"`,
		`::1 - - [01/Apr/2026:15:15:05 +0000] "POST /wp-login.php HTTP/1.1" 401 0 "-" "-"`,
		`127.0.0.1 - - [01/Apr/2026:15:15:05 +0000] "POST /wp-login.php HTTP/1.1" 401 0 "-" "-"`,
		// Malformed requests
		`1.2.3.4 "POST /wp-login.php" 200`,
		`"POST /wp-login.php"`,
		string(make([]byte, 64*1024)),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		cfg := fuzzConfig()
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("parseAccessLogBruteForce panicked on input %q: %v", line, r)
			}
		}()
		_ = parseAccessLogBruteForce(line, cfg)
	})
}

// FuzzParseAccessLogLineEnhanced exercises the cPanel-access-log parser.
func FuzzParseAccessLogLineEnhanced(f *testing.F) {
	seeds := []string{
		"",
		`1.2.3.4 phuser [01/Apr/2026:15:15:05 +0000] "GET /cpsess1234/frontend/paper_lantern/index.html?login=1 HTTP/1.1" 200 1234 "-" "Mozilla/5.0" 123456`,
		// Malformed lines
		`phuser [01/Apr/2026`,
		`1.2.3.4`,
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		cfg := fuzzConfig()
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("parseAccessLogLineEnhanced panicked on input %q: %v", line, r)
			}
		}()
		_ = parseAccessLogLineEnhanced(line, cfg)
	})
}

// FuzzParseSecureLogLine exercises the /var/log/secure (RHEL) /
// /var/log/auth.log (Debian) parser.
func FuzzParseSecureLogLine(f *testing.F) {
	seeds := []string{
		"",
		"Apr 10 15:15:05 host sshd[1234]: Failed password for root from 1.2.3.4 port 54321 ssh2",
		"Apr 10 15:15:05 host sshd[1234]: Accepted publickey for phuser from 1.2.3.4 port 54321 ssh2",
		"Apr 10 15:15:05 host sshd[1234]: Invalid user admin from 1.2.3.4",
		"Apr 10 15:15:05 host sshd[1234]: Disconnected from authenticating user root 1.2.3.4 port 54321",
		"Apr 10 15:15:05 host sudo: phuser : TTY=pts/0 ; PWD=/home/phuser ; USER=root ; COMMAND=/bin/ls",
		// Malformed / truncated
		"Apr 10",
		"sshd[",
		`Failed password for from`,
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		cfg := fuzzConfig()
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("parseSecureLogLine panicked on input %q: %v", line, r)
			}
		}()
		_ = parseSecureLogLine(line, cfg)
	})
}

// FuzzParseEximLogLine exercises the /var/log/exim_mainlog parser.
func FuzzParseEximLogLine(f *testing.F) {
	seeds := []string{
		"",
		"2026-04-10 15:15:05 1hAbCd-0001ab-Ef <= user@example.com H=(localhost) [127.0.0.1] P=esmtp S=1234",
		"2026-04-10 15:15:05 1hAbCd-0001ab-Ef => user@example.com R=dnslookup T=remote_smtp",
		"2026-04-10 15:15:05 H=mail.evil.com [1.2.3.4] SMTP connection lost after MAIL",
		"2026-04-10 15:15:05 H=(localhost) [127.0.0.1] F=<> rejected RCPT <spam@example.com>: relay not permitted",
		// Malformed
		"2026-04-10",
		"1hAbCd-0001ab-Ef",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		cfg := fuzzConfig()
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("parseEximLogLine panicked on input %q: %v", line, r)
			}
		}()
		_ = parseEximLogLine(line, cfg)
	})
}

// FuzzParseSessionLogLine exercises the cPanel session log parser.
func FuzzParseSessionLogLine(f *testing.F) {
	seeds := []string{
		"",
		"[2026-04-10 15:15:05 +0000] info [cpaneld] 1.2.3.4 phuser \"GET /frontend/paper_lantern/index.html HTTP/1.1\" 200",
		"[2026-04-10 15:15:05 +0000] info [webmaild] 1.2.3.4 phuser@example.com \"POST /session/login HTTP/1.1\" 200",
		"[2026-04-10 15:15:05 +0000] info [whostmgrd] 1.2.3.4 root \"GET / HTTP/1.1\" 200",
		// Malformed
		"[2026-04-10",
		"info [",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		cfg := fuzzConfig()
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("parseSessionLogLine panicked on input %q: %v", line, r)
			}
		}()
		_ = parseSessionLogLine(line, cfg)
	})
}

// FuzzParseFTPLogLine exercises the FTP log parser from /var/log/messages.
func FuzzParseFTPLogLine(f *testing.F) {
	seeds := []string{
		"",
		"Apr 10 15:15:05 host pure-ftpd: (phuser@1.2.3.4) [NOTICE] Logout.",
		"Apr 10 15:15:05 host pure-ftpd: (?@1.2.3.4) [WARNING] Authentication failed for user [admin]",
		// Malformed
		"pure-ftpd:",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		cfg := fuzzConfig()
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("parseFTPLogLine panicked on input %q: %v", line, r)
			}
		}()
		_ = parseFTPLogLine(line, cfg)
	})
}

// FuzzParseDovecotLogLine exercises the Dovecot/Courier mail log parser.
func FuzzParseDovecotLogLine(f *testing.F) {
	seeds := []string{
		"",
		"Apr 10 15:15:05 host dovecot: imap-login: Login: user=<phuser@example.com>, method=PLAIN, rip=1.2.3.4, lip=10.0.0.1",
		"Apr 10 15:15:05 host dovecot: imap-login: Aborted login (auth failed, 1 attempts in 2 secs): user=<admin@example.com>, method=PLAIN, rip=1.2.3.4",
		// Malformed
		"dovecot: imap-login:",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		cfg := fuzzConfig()
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("parseDovecotLogLine panicked on input %q: %v", line, r)
			}
		}()
		_ = parseDovecotLogLine(line, cfg)
	})
}

// FuzzParsePHPShieldLogLine exercises the PHP Shield event log parser.
func FuzzParsePHPShieldLogLine(f *testing.F) {
	seeds := []string{
		"",
		`{"time":"2026-04-10T15:15:05Z","user":"phuser","event":"dangerous_function","function":"exec","file":"/home/phuser/public_html/shell.php"}`,
		`{"time":"2026-04-10T15:15:05Z"}`,
		"not json",
		`{"malformed`,
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		cfg := fuzzConfig()
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("parsePHPShieldLogLine panicked on input %q: %v", line, r)
			}
		}()
		_ = parsePHPShieldLogLine(line, cfg)
	})
}
