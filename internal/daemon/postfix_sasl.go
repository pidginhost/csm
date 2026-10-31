package daemon

import (
	"net"
	"strconv"
	"strings"
)

// postfixSMTPDMessage returns the process tag and message of a postfix smtpd
// log line. Backend warnings omit the client address, so their process tag
// must be retained to withhold that process's subsequent failures.
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

// postfixSASLFailure reports the client address of a postfix smtpd
// "warning: name[addr]: SASL <mech> authentication failed: <reply>" line and
// the reply text. It returns "" for any other line.
//
// The client field must open the warning as one space-free token: smtpd
// echoes client-supplied text (RCPT, HELO) into other warnings, and a match
// anywhere in the message would let a client name the address to block.
//
// The line alone is never evidence: Postfix logs a Dovecot temporary failure
// the same way as a wrong password, and a failed reconnect can repeat an
// earlier reply. Callers pair it with Dovecot's verdict for the request.
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

func isPostfixSASLNonCredentialReply(reply string) bool {
	// smtpd_sasl_glue logs the SASL reason, not the SMTP status. Dovecot's
	// malformed backend replies and Cyrus's temporary errors do not all
	// include "temporary" or "authentication server" in that reason.
	switch reply {
	case "authentication backend error", "generic failure", "no memory available", "transient failure (e.g., weak key)":
		return true
	case "invalid authentication mechanism", "invalid base64 data in initial response", "invalid base64 data in continued response":
		// These fail locally without sending credentials to Dovecot.
		return true
	}
	return strings.Contains(reply, "authentication server") || strings.Contains(reply, "temporar") ||
		strings.HasPrefix(reply, "invalid authentication mechanism:")
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
