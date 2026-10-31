package daemon

import "strings"

// Informational auth messages can contain arbitrary client names and logged
// passwords. Match their trusted prefix, not a verdict in the untrusted body:
// drivers use different verdicts, and syslog can truncate the body anywhere.
func isDovecotAuthRequestInfo(line string) bool {
	seg := dovecotAuthSegment(dovecotServiceMessage(line))
	if strings.HasPrefix(seg, "Debug: ") {
		return true
	}
	open := strings.IndexByte(seg, '(')
	return open > 0 && isDovecotAuthRequestName(seg[:open])
}

// Severity prefixes remain so the caller can preserve error diagnostics.
func dovecotAuthSegment(msg string) string {
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

func isDovecotAuthRequestName(s string) bool {
	// Dovecot substitutes the configured database name for the driver.
	// Only leading severity markers distinguish diagnostics from that name.
	for _, severity := range []string{"Error: ", "Warning: ", "Fatal: ", "Panic: "} {
		if strings.HasPrefix(s, severity) {
			return false
		}
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
