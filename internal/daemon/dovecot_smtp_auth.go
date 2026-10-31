package daemon

import "strings"

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
