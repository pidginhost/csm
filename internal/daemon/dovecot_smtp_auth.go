package daemon

import (
	"net"
	"strings"
)

// dovecotRejectionVerdicts end a Dovecot auth_verbose line in which one
// password database rejected the credentials. The PAM form is what passdb-pam
// logs for PAM_AUTH_ERR, which a missing user and a wrong password share.
var dovecotRejectionVerdicts = []struct {
	suffix string
	exist  mailboxExistence
}{
	{"): Password mismatch", mailboxExists},
	{"): unknown user", mailboxMissing},
	{"): pam_authenticate() failed: Authentication failure (Password mismatch?)", mailboxExistenceUnknown},
}

// dovecotSessionlessRejection parses a rejection verdict for a request with
// no login session, which is how an MTA such as Postfix asks Dovecot to check
// SMTP AUTH:
//
//	auth: sql(alice@example.net,203.0.113.5): Password mismatch
//
// One verdict is one database's answer, not the request's result: a later
// database can still accept the login or fail internally. Callers pair it
// with the MTA's own failure line for the same client.
//
// The client name is attacker text before the fields Dovecot appends, so the
// address and master flag are read from the right; a login session marker
// there never parses as an address. A logged password follows the verdict,
// so lines whose fields hold a second "): " are refused: syslog may have cut
// the line right after a verdict forged inside the password, and Dovecot's
// default name characters never allow that sequence.
func dovecotSessionlessRejection(line string) (ip, account string, exist mailboxExistence, ok bool) {
	fields, exist, ok := dovecotRejectionFields(line)
	if !ok {
		return "", "", mailboxExistenceUnknown, false
	}
	return dovecotRejectionClient(fields, exist)
}

// dovecotSessionRejection parses a rejection verdict for a request with a
// login session, which is how the IMAP, POP3 and ManageSieve login processes
// ask Dovecot to check a login:
//
//	auth: passwd-file(alice@example.net,203.0.113.5,<AbCd1234>): unknown user
//
// Dovecot's fields are user,ip[,master][,<session>]. Like the sessionless
// form, one verdict is one database's answer; callers pair it with the login
// summary of the same session, so the same fields are read from the right
// and the same forged verdicts refused.
func dovecotSessionRejection(line string) (session, ip, account string, exist mailboxExistence, ok bool) {
	fields, exist, ok := dovecotRejectionFields(line)
	if !ok {
		return "", "", "", mailboxExistenceUnknown, false
	}
	comma := strings.LastIndexByte(fields, ',')
	if comma < 0 {
		return "", "", "", mailboxExistenceUnknown, false
	}
	session, ok = dovecotSessionField(fields[comma+1:])
	if !ok {
		return "", "", "", mailboxExistenceUnknown, false
	}
	ip, account, exist, ok = dovecotRejectionClient(fields[:comma], exist)
	if !ok {
		return "", "", "", mailboxExistenceUnknown, false
	}
	return session, ip, account, exist, true
}

// dovecotSessionField reads a <session> request field.
func dovecotSessionField(field string) (session string, ok bool) {
	session, opened := strings.CutPrefix(field, "<")
	session, closed := strings.CutSuffix(session, ">")
	// Dovecot's LOGIN_MAX_SESSION_ID_LEN also bounds forwarded identifiers.
	if !opened || !closed || session == "" || len(session) > 64 {
		return "", false
	}
	for _, c := range session {
		if c <= ' ' || c >= 0x7f || strings.ContainsRune("<>,()", c) {
			return "", false
		}
	}
	return session, true
}

// dovecotRejectionFields returns the request fields of a rejection verdict,
// which end at the driver's closing parenthesis, and what the verdict says.
func dovecotRejectionFields(line string) (fields string, exist mailboxExistence, ok bool) {
	seg := dovecotAuthSegment(dovecotServiceMessage(line))
	open := strings.IndexByte(seg, '(')
	if open <= 0 || !isDovecotAuthRequestName(seg[:open]) || strings.Contains(seg[:open], ": ") {
		return "", mailboxExistenceUnknown, false
	}
	inner := seg[open+1:]
	for _, verdict := range dovecotRejectionVerdicts {
		if rest, cut := strings.CutSuffix(inner, verdict.suffix); cut && !strings.Contains(rest, "): ") {
			return rest, verdict.exist, true
		}
	}
	return "", mailboxExistenceUnknown, false
}

// dovecotRejectionClient reads user,ip[,master] from the right.
func dovecotRejectionClient(fields string, verdict mailboxExistence) (ip, account string, exist mailboxExistence, ok bool) {
	fields = strings.TrimSuffix(fields, ",master")
	comma := strings.LastIndexByte(fields, ',')
	if comma < 0 {
		return "", "", mailboxExistenceUnknown, false
	}
	addr := net.ParseIP(fields[comma+1:])
	if addr == nil {
		return "", "", mailboxExistenceUnknown, false
	}
	account, exist = fields[:comma], verdict
	// The spray key folds a final dot, but Dovecot's unknown user is about the
	// dotted string. It says nothing about the mailbox the key names.
	if exist == mailboxMissing && strings.HasSuffix(account, ".") {
		exist = mailboxExistenceUnknown
	}
	// Dovecot sanitizes unavailable or invalid name text to '?' and
	// abbreviates long names with '...'. Neither identifies the mailbox.
	if strings.TrimSpace(account) == "" || strings.Contains(account, "?") || strings.HasSuffix(account, "...") {
		account, exist = "", mailboxExistenceUnknown
	}
	return addr.String(), account, exist, true
}

// dovecotAuthTroubleIPs returns every address named in the request fields of
// a Dovecot auth Error, Warning, Fatal or Panic line. A client name can add
// addresses here, which only withholds evidence for them.
func dovecotAuthTroubleIPs(line string) []string {
	var ips []string
	for _, field := range dovecotAuthTroubleFields(line) {
		if addr := net.ParseIP(field); addr != nil {
			ips = append(ips, addr.String())
		}
	}
	return ips
}

// dovecotAuthTroubleSessions returns every session named in the same fields.
// Every one is read, not just the rightmost, because the line's detail text
// can hold fields too and the session Dovecot appended must not be missed. A
// client name can add sessions, which only withholds evidence for them.
func dovecotAuthTroubleSessions(line string) []string {
	seg := dovecotAuthSegment(dovecotServiceMessage(line))
	if !isDovecotAuthDiagnostic(seg) {
		return nil
	}
	return dovecotSessionsInFields(seg)
}

// Only withholding uses these fields: client text may add a session but must
// never hide a complete one, including a field at the end of a cut log line.
func dovecotSessionsInFields(seg string) []string {
	var sessions []string
	for i := strings.IndexByte(seg, ','); i >= 0; {
		seg = seg[i+1:]
		end := strings.IndexAny(seg, ",)")
		if end < 0 {
			end = len(seg)
		}
		if session, ok := dovecotSessionField(seg[:end]); ok {
			sessions = append(sessions, session)
		}
		i = strings.IndexByte(seg, ',')
	}
	return sessions
}

func isDovecotAuthDiagnostic(seg string) bool {
	for _, severity := range []string{"Error: ", "Warning: ", "Fatal: ", "Panic: "} {
		if strings.HasPrefix(seg, severity) {
			return true
		}
	}
	return false
}

// dovecotAuthTroubleFields returns the fields after each comma of an auth
// Error, Warning, Fatal or Panic line, up to the next comma or parenthesis.
func dovecotAuthTroubleFields(line string) []string {
	seg := dovecotAuthSegment(dovecotServiceMessage(line))
	rest := ""
	for _, severity := range []string{"Error: ", "Warning: ", "Fatal: ", "Panic: "} {
		if r, ok := strings.CutPrefix(seg, severity); ok {
			rest = r
			break
		}
	}
	var fields []string
	for i := strings.IndexByte(rest, ','); i >= 0; {
		rest = rest[i+1:]
		end := strings.IndexAny(rest, ",)")
		if end < 0 {
			break
		}
		fields = append(fields, rest[:end])
		i = strings.IndexByte(rest, ',')
	}
	return fields
}

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
