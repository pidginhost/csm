package checks

import (
	"strings"

	"github.com/pidginhost/csm/internal/netutil"
)

// DovecotRemoteIP returns the connection's address from a Dovecot login
// line, or "" when the line has none. Only fields outside user=<...> can
// name the connection; even the last rip= may be client text without them.
func DovecotRemoteIP(line string) string {
	_, fields := DovecotLoginFields(line)
	var ip string
	for field := range strings.FieldsFuncSeq(fields, dovecotFieldSeparator) {
		if value, ok := strings.CutPrefix(field, "rip="); ok {
			ip, _ = netutil.ParseIPToken(value)
		}
	}
	return ip
}

// DovecotLoginFields separates the raw login name from the fields that
// follow it. Dovecot does not escape angle brackets inside the name. Its
// closing bracket is therefore read from the right, before the optional
// server session, rather than at the first client-supplied '>'. A missing
// closing bracket withholds all fields. No-auth summaries may omit user=.
func DovecotLoginFields(line string) (user, fields string) {
	start := strings.Index(line, "user=<")
	if start < 0 {
		return "", line
	}
	start += len("user=<")
	end := len(line)
	if session := dovecotFieldIndex(line, "session=<"); session >= start {
		// A session follows the connection fields. A marker before them
		// is still part of the name, including one with a forged rip=.
		lastField := max(dovecotFieldIndex(line, "method="), dovecotFieldIndex(line, "rip="), dovecotFieldIndex(line, "lip="))
		if session > lastField {
			value := line[session+len("session=<"):]
			close := strings.IndexByte(value, '>')
			if close < 0 || ((close+1 == len(value) || dovecotFieldSeparator(rune(value[close+1]))) && !strings.ContainsAny(value[:close], "<")) {
				end = session
			}
		}
	}
	close := strings.LastIndexByte(line[start:end], '>')
	if close < 0 {
		return "", ""
	}
	close += start
	if close+1 < len(line) && !dovecotFieldSeparator(rune(line[close+1])) {
		return "", ""
	}
	return line[start:close], line[close+1:]
}

func dovecotFieldSeparator(r rune) bool {
	return r == ',' || r == ' ' || r == '\t' || r == '\r' || r == '\n'
}

func dovecotFieldIndex(line, key string) int {
	for {
		i := strings.LastIndex(line, key)
		if i <= 0 || dovecotFieldSeparator(rune(line[i-1])) {
			return i
		}
		line = line[:i]
	}
}

// DovecotServiceMessage returns the message only for a Dovecot syslog tag.
func DovecotServiceMessage(line string) string {
	tagEnd := strings.Index(line, ": ")
	if tagEnd < 0 {
		return ""
	}
	prefix := line[:tagEnd]
	tagStart := strings.LastIndexAny(prefix, " \t")
	if tagStart >= 0 {
		prefix = prefix[tagStart+1:]
	}
	if !isDovecotProgramTag(prefix) {
		return ""
	}
	return strings.TrimSpace(line[tagEnd+2:])
}

func isDovecotProgramTag(tag string) bool {
	if tag == "dovecot" {
		return true
	}
	const prefix = "dovecot["
	if !strings.HasPrefix(tag, prefix) || !strings.HasSuffix(tag, "]") {
		return false
	}
	pid := tag[len(prefix) : len(tag)-1]
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

// DovecotLoginSucceeded matches the server status before any client text.
func DovecotLoginSucceeded(line string) bool {
	msg := DovecotServiceMessage(line)
	return strings.HasPrefix(msg, "imap-login: Logged in: user=<") ||
		strings.HasPrefix(msg, "imap-login: Login: user=<") ||
		strings.HasPrefix(msg, "pop3-login: Logged in: user=<") ||
		strings.HasPrefix(msg, "pop3-login: Login: user=<") ||
		strings.HasPrefix(msg, "managesieve-login: Logged in: user=<") ||
		strings.HasPrefix(msg, "managesieve-login: Login: user=<")
}

// DovecotLoginMessage excludes auth database messages and other services
// whose client text can imitate a login summary.
func DovecotLoginMessage(line string) string {
	msg := DovecotServiceMessage(line)
	if strings.HasPrefix(msg, "imap-login:") || strings.HasPrefix(msg, "pop3-login:") || strings.HasPrefix(msg, "managesieve-login:") {
		return msg
	}
	return ""
}
