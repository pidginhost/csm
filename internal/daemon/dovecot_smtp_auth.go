package daemon

import (
	"net"
	"strings"
)

// dovecotSMTPAuthRejection parses a Dovecot auth_verbose credential verdict
// for a request that has no login session, which is how an MTA such as
// Postfix asks Dovecot to check SMTP AUTH:
//
//	auth: sql(alice@example.net,203.0.113.5): Password mismatch
//	auth-worker(4567): pam(bob,203.0.113.5): unknown user
//
// Dovecot writes these only after the password database answered, so unlike
// Postfix's own SASL warning they never stand for a backend outage.
//
// The client name is attacker text and sits before the fields Dovecot
// appends, so the address, master flag and session marker are read from the
// right. A logged password follows the verdict, so such lines are refused,
// including one that syslog cut short right after a forged verdict inside
// the password. An earlier verdict makes the boundary ambiguous; other
// punctuation in the name does not.
//
// A passdb chain logs per database, not per authentication result. A later
// database can succeed or fail internally after this rejection. These lines
// cannot distinguish that case or correlate multiple verdicts for one attempt.
func dovecotSMTPAuthRejection(line string) (ip, account string, ok bool) {
	inner := dovecotPassdbFields(line)
	if inner == "" {
		return "", "", false
	}
	switch {
	case strings.HasSuffix(inner, "): Password mismatch"):
		inner = strings.TrimSuffix(inner, "): Password mismatch")
	case strings.HasSuffix(inner, "): unknown user"):
		inner = strings.TrimSuffix(inner, "): unknown user")
	default:
		return "", "", false
	}
	if containsDovecotAuthVerdict(inner) {
		return "", "", false
	}
	inner = strings.TrimSuffix(inner, ",master")
	comma := strings.LastIndexByte(inner, ',')
	if comma < 0 {
		return "", "", false
	}
	// A login process (IMAP, POP3, ManageSieve, submission) appends its
	// session id last, which never parses as an address; those failures are
	// counted from the login process's own line.
	addr := net.ParseIP(inner[comma+1:])
	if addr == nil {
		return "", "", false
	}
	return addr.String(), inner[:comma], true
}

func dovecotPassdbFields(line string) string {
	seg := dovecotPassdbSegment(dovecotServiceMessage(line))
	open := strings.IndexByte(seg, '(')
	if open <= 0 || !isDovecotPassdbName(seg[:open]) {
		return ""
	}
	return seg[open+1:]
}

// Even an excluded or truncated verdict carries client text. It must not
// reach the outage detector, which also searches for phrases in the line.
func containsDovecotAuthVerdict(fields string) bool {
	return strings.Contains(fields, "): Password mismatch") || strings.Contains(fields, "): unknown user")
}

// dovecotPassdbSegment strips the auth process prefix from a Dovecot message.
// Severity prefixes remain so the caller can reject non-verdict lines.
func dovecotPassdbSegment(msg string) string {
	if rest, ok := strings.CutPrefix(msg, "auth: "); ok {
		return rest
	}
	rest, ok := strings.CutPrefix(msg, "auth-worker(")
	if !ok {
		return ""
	}
	pid, rest, ok := strings.Cut(rest, "): ")
	if !ok || !isASCIIDigits(pid) {
		return ""
	}
	// Dovecot 2.3 prefixes worker lines with the auth master connection:
	// "conn unix:auth-worker (pid=N,uid=N): auth-worker<N>: driver(...)".
	if conn, ok := strings.CutPrefix(rest, "conn unix:auth-worker (pid="); ok {
		_, tail, found := strings.Cut(conn, "): auth-worker<")
		if !found {
			return ""
		}
		_, tail, found = strings.Cut(tail, ">: ")
		if !found {
			return ""
		}
		rest = tail
	}
	return rest
}

func isDovecotPassdbName(s string) bool {
	// Dovecot substitutes the configured database name for the driver.
	// A severity prefix, however, is not part of an informational verdict.
	if strings.Contains(s, ": ") {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < ' ' || c == 0x7f {
			return false
		}
	}
	return s != ""
}

func isASCIIDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}
