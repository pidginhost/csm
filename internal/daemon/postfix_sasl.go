package daemon

import (
	"net"
	"strconv"
	"strings"
	"time"
)

// A reconnect error belongs to the next AUTH result from that smtpd worker.
// xsasl_dovecot_server_first can return a temporary failure without replacing
// the previous reply. Do not put that result into any brute-force history.
func (t *smtpAuthTracker) postfixSASLFailureIP(line string) string {
	if t == nil {
		return ""
	}
	process, msg := postfixSMTPDMessage(line)
	if process == "" {
		return ""
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	if isPostfixSASLBackendDiagnostic(msg) {
		if len(t.postfixBackendErrors) >= t.maxTracked {
			t.prunePostfixBackendErrors(now)
		}
		if _, exists := t.postfixBackendErrors[process]; !exists && len(t.postfixBackendErrors) >= t.maxTracked {
			// Preserve safety when the existing tracking budget is exhausted.
			// Dropping an error would turn its next AUTH result into evidence.
			t.postfixBackendOverflowUntil = now.Add(t.window)
			return ""
		}
		if t.postfixBackendErrors == nil {
			t.postfixBackendErrors = make(map[string]time.Time)
		}
		t.postfixBackendErrors[process] = now.Add(t.window)
		return ""
	}
	// A reused worker must not carry a prior client's pending error forward.
	if client, ok := strings.CutPrefix(msg, "connect from "); ok && postfixClientIP(client) != "" {
		delete(t.postfixBackendErrors, process)
		return ""
	}
	ip, reply := postfixSASLFailure(msg)
	if ip == "" {
		return ""
	}
	until := t.postfixBackendErrors[process]
	delete(t.postfixBackendErrors, process)
	if now.Before(until) || now.Before(t.postfixBackendOverflowUntil) ||
		isPostfixSASLBackendReply(reply) || (t.backendDownFn != nil && t.backendDownFn()) {
		return ""
	}
	return ip
}

// Caller holds the SMTP tracker mutex. The existing SMTP window and tracking
// budget bound errors from workers that exit without an AUTH result.
func (t *smtpAuthTracker) prunePostfixBackendErrors(now time.Time) {
	for process, until := range t.postfixBackendErrors {
		if !now.Before(until) {
			delete(t.postfixBackendErrors, process)
		}
	}
}

func postfixSMTPDMessage(line string) (process, msg string) {
	tagEnd := strings.Index(line, ": ")
	if tagEnd < 0 {
		return "", ""
	}
	process = line[strings.LastIndexAny(line[:tagEnd], " \t")+1 : tagEnd]
	if !isPostfixSMTPDTag(process) {
		return "", ""
	}
	return process, line[tagEnd+2:]
}

// Only server-authored diagnostics count. Searching elsewhere in a message
// would let echoed client text suppress another client's authentication result.
func isPostfixSASLBackendDiagnostic(msg string) bool {
	return strings.HasPrefix(msg, "warning: SASL: Connect to Dovecot auth socket '") ||
		strings.HasPrefix(msg, "warning: SASL: Couldn't send handshake: ") ||
		msg == "warning: SASL: Protocol version error" ||
		strings.HasPrefix(msg, "warning: SASL: Protocol version mismatch (") ||
		msg == "warning: SASL: Connected to wrong auth socket (auth-master instead of auth-client)"
}

// postfixSASLFailureIP returns the client address of a postfix smtpd
// "warning: name[addr]: SASL <mech> authentication failed: <reply>" line, or
// "" for any other line. Account names are unavailable on older Postfix.
//
// The client field must open the warning as one space-free token: smtpd
// echoes client-supplied text (RCPT, HELO) into other warnings, and a match
// anywhere in the message would let a client name the address to block.
//
// A reply that blames the authentication server (lost connection, temporary
// failure) is an outage, not a wrong password: counting it would block every
// client that tried to log in while dovecot auth was down.
func postfixSASLFailureIP(line string) string {
	_, msg := postfixSMTPDMessage(line)
	ip, reply := postfixSASLFailure(msg)
	if isPostfixSASLBackendReply(reply) {
		return ""
	}
	return ip
}

func postfixSASLFailure(msg string) (ip, reply string) {
	msg, ok := strings.CutPrefix(msg, "warning: ")
	if !ok {
		return "", ""
	}
	client, rest, ok := strings.Cut(msg, ": SASL ")
	if !ok {
		return "", ""
	}
	ip = postfixClientIP(client)
	if ip == "" {
		return "", ""
	}
	mech, rest, ok := strings.Cut(rest, " ")
	if !ok || mech == "" {
		return "", ""
	}
	// SASL mechanism names cannot contain quoting or whitespace. Postfix
	// echoes invalid AUTH tokens too, so an embedded failure is not a result.
	for _, c := range mech {
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' {
			continue
		}
		return "", ""
	}
	if rest == "authentication failed" {
		return ip, ""
	}
	reply, ok = strings.CutPrefix(rest, "authentication failed:")
	if !ok {
		return "", ""
	}
	// Newer smtpd versions append the attempted username. It is untrusted
	// text and must not turn a credential failure into a backend outage.
	reply, _, _ = strings.Cut(reply, ", sasl_username=")
	return ip, strings.ToLower(strings.TrimSpace(reply))
}

func isPostfixSASLBackendReply(reply string) bool {
	// smtpd_sasl_glue logs the SASL reason, not the SMTP status. Dovecot's
	// malformed backend replies and Cyrus's temporary errors do not all
	// include "temporary" or "authentication server" in that reason.
	switch reply {
	case "authentication backend error", "generic failure", "no memory available", "transient failure (e.g., weak key)":
		return true
	}
	return strings.Contains(reply, "authentication server") || strings.Contains(reply, "temporar")
}

func postfixClientIP(client string) string {
	if strings.ContainsAny(client, " \t\r\n") {
		return ""
	}
	end := strings.LastIndexByte(client, ']')
	if end < 0 {
		return ""
	}
	// smtpd_client_port_logging appends a decimal port to the client field.
	if tail := client[end+1:]; tail != "" {
		port, ok := strings.CutPrefix(tail, ":")
		if !ok {
			return ""
		}
		if _, err := strconv.ParseUint(port, 10, 16); err != nil {
			return ""
		}
	}
	start := strings.LastIndexByte(client[:end], '[')
	if start <= 0 {
		return ""
	}
	ip := net.ParseIP(client[start+1 : end])
	if ip == nil {
		return ""
	}
	return ip.String()
}

// isPostfixSMTPDTag accepts "postfix/smtpd[pid]" and the per-service
// syslog_name form "postfix/submission/smtpd[pid]".
func isPostfixSMTPDTag(tag string) bool {
	i := strings.LastIndex(tag, "/smtpd[")
	if i < 0 || !strings.HasPrefix(tag, "postfix") || !strings.HasSuffix(tag, "]") {
		return false
	}
	pid := tag[i+len("/smtpd[") : len(tag)-1]
	if pid == "" {
		return false
	}
	for i := 0; i < len(pid); i++ {
		if pid[i] < '0' || pid[i] > '9' {
			return false
		}
	}
	return true
}
