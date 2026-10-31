package daemon

import (
	"net"
	"strings"
)

// postfixSASLFailureIP returns the client address of a postfix smtpd
// "warning: name[addr]: SASL <mech> authentication failed: <reply>" line, or
// "" for any other line. Postfix does not log the account it tried.
//
// The client field must open the warning as one space-free token: smtpd
// echoes client-supplied text (RCPT, HELO) into other warnings, and a match
// anywhere in the message would let a client name the address to block.
//
// A reply that blames the authentication server (lost connection, temporary
// failure) is an outage, not a wrong password: counting it would block every
// client that tried to log in while dovecot auth was down.
func postfixSASLFailureIP(line string) string {
	tagEnd := strings.Index(line, ": ")
	if tagEnd < 0 || !isPostfixSMTPDTag(line[strings.LastIndexAny(line[:tagEnd], " \t")+1:tagEnd]) {
		return ""
	}
	msg, ok := strings.CutPrefix(line[tagEnd+2:], "warning: ")
	if !ok {
		return ""
	}
	client, rest, ok := strings.Cut(msg, ": SASL ")
	if !ok || strings.ContainsAny(client, " \t") {
		return ""
	}
	// smtpd_client_port_logging appends ":port" to the client field.
	if i := strings.LastIndexByte(client, ']'); i >= 0 && i < len(client)-1 && client[i+1] == ':' {
		client = client[:i+1]
	}
	if !strings.HasSuffix(client, "]") {
		return ""
	}
	_, reply, ok := strings.Cut(rest, " authentication failed")
	if !ok {
		return ""
	}
	reply = strings.ToLower(reply)
	if strings.Contains(reply, "authentication server") || strings.Contains(reply, "temporar") {
		return ""
	}
	ip := net.ParseIP(client[strings.LastIndexByte(client, '[')+1 : len(client)-1])
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
