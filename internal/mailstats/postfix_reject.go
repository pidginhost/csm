package mailstats

import (
	"net"
	"regexp"
	"strings"
	"time"
)

// postfixReplyCode matches the SMTP code and enhanced status that open a
// Postfix reject reply. A milter reply carries the status alone.
var postfixReplyCode = regexp.MustCompile(`^(?:[0-9]{3} )?(?:[0-9]\.[0-9]{1,3}\.[0-9]{1,3} )?`)

// ParsePostfixReject reads a Postfix log line for an SMTP command that
// smtpd or postscreen rejected, or a message a milter rejected. The line
// must come from one of those daemons and open with the reject keyword, so
// client text echoed into other lines is never a reject.
func ParsePostfixReject(line string, loc *time.Location, fallback time.Time) (Reject, bool) {
	tagEnd := strings.Index(line, ": ")
	if tagEnd < 0 || !isPostfixRejectTag(line[strings.LastIndexAny(line[:tagEnd], " \t")+1:tagEnd]) {
		return Reject{}, false
	}
	msg := line[tagEnd+2:]
	r := Reject{Class: ClassOther}
	rest, smtp := strings.CutPrefix(msg, "NOQUEUE: reject: ")
	if !smtp {
		id, after, ok := strings.Cut(msg, ": milter-reject: ")
		if !ok || !isQueueID(id) {
			return Reject{}, false
		}
		r.MsgID, rest = id, after
	}
	command, rest, ok := strings.Cut(rest, " from ")
	if !ok || strings.Trim(command, "ABCDEFGHIJKLMNOPQRSTUVWXYZ-") != "" || command == "" {
		return Reject{}, false
	}
	client, reply, ok := strings.Cut(rest, " ")
	if !ok {
		return Reject{}, false
	}
	if r.IP = postfixPeerIP(client); r.IP == "" {
		return Reject{}, false
	}
	if smtp {
		r.Command = command
	}
	// The first metadata marker bounds the reply, so envelope and HELO
	// text never becomes a reason. Before MAIL, Postfix may log only the
	// protocol and HELO. Multiple markers can also be an unquoted address
	// posing as metadata, so that reply cannot be classified safely.
	end, markers := len(reply), 0
	for _, marker := range []string{"; from=<", "; to=<", "; proto=", "; helo=<"} {
		if i := strings.Index(reply, marker); i >= 0 {
			end = min(end, i)
			markers += strings.Count(reply, marker)
		}
	}
	r.Sender, r.Recipient = postfixEnvelope(reply[end:])
	reply = reply[:end]
	r.Temporary = strings.HasPrefix(reply, "4")
	reason := strings.TrimPrefix(reply, postfixReplyCode.FindString(reply))
	r.At = LineTime(line, loc, fallback)
	r.Detail = detail(reason)
	switch {
	case markers > 1:
	case !smtp:
		r.Class = classifyMilterReject(reason, r.Temporary)
	case strings.HasPrefix(reason, "<"):
		r.Class = classifyPostfixNamed(reason)
	case strings.HasPrefix(reason, "Service unavailable; ") && strings.Contains(reason, " blocked using "):
		r.Class = ClassBlocklisted
	}
	return r, true
}

// isPostfixRejectTag reports a syslog tag of smtpd, postscreen or cleanup,
// under any Postfix instance or service name, with a numeric pid.
func isPostfixRejectTag(tag string) bool {
	name, pid, ok := strings.Cut(strings.TrimSuffix(tag, "]"), "[")
	if !ok || !strings.HasSuffix(tag, "]") || !strings.HasPrefix(name, "postfix") || pid == "" || strings.Trim(pid, "0123456789") != "" {
		return false
	}
	switch name[strings.LastIndexByte(name, '/')+1:] {
	case "smtpd", "postscreen", "cleanup":
		return strings.Contains(name, "/")
	}
	return false
}

func isQueueID(s string) bool {
	return s != "" && strings.Trim(s, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz") == ""
}

// postfixPeerIP returns the address of a "name[addr]:" or "[addr]:port:"
// client field, or "" when the field is not one.
func postfixPeerIP(client string) string {
	client, ok := strings.CutSuffix(client, ":")
	if !ok {
		return ""
	}
	if i := strings.LastIndex(client, "]:"); i >= 0 && strings.Trim(client[i+2:], "0123456789") == "" {
		client = client[:i+1]
	}
	open := strings.LastIndexByte(client, '[')
	if open < 0 || !strings.HasSuffix(client, "]") {
		return ""
	}
	ip := client[open+1 : len(client)-1]
	if net.ParseIP(ip) == nil {
		return ""
	}
	return ip
}

// postfixEnvelope accepts only a complete envelope, respecting quoted
// local parts. A marker inside an address is not a field boundary. If two
// envelopes fit, leave the addresses empty rather than display client text
// as a sender or recipient belonging to the reject.
func postfixEnvelope(s string) (sender, recipient string) {
	found := false
	for {
		_, after, ok := strings.Cut(s, "; from=<")
		if !ok {
			return sender, recipient
		}
		s = after
		n := unquotedIndex(after, '>')
		if n < 0 {
			continue
		}
		from, rest := after[:n], strings.TrimPrefix(after[n+1:], ",")
		to := ""
		if addr, ok := strings.CutPrefix(rest, " to=<"); ok {
			n = unquotedIndex(addr, '>')
			if n < 0 {
				continue
			}
			to, rest = addr[:n], strings.TrimPrefix(addr[n+1:], ",")
		}
		if !strings.HasPrefix(rest, " proto=") {
			continue
		}
		if found {
			return "", ""
		}
		sender, recipient, found = from, to, true
	}
}

// Postfix logs the rejected name unquoted. Every ">: " can therefore end
// that name, even one followed by an unfamiliar policy reason. Only agree
// on a class when every possible boundary gives the same result.
func classifyPostfixNamed(reason string) Class {
	subject, rest, ok := strings.Cut(reason, ">: ")
	if !ok || strings.ContainsAny(subject, " \t\r\n\"") {
		return ClassOther
	}
	class := classifyPostfixReason(rest)
	for {
		_, rest, ok = strings.Cut(rest, ">: ")
		if !ok {
			return class
		}
		if classifyPostfixReason(rest) != class {
			return ClassOther
		}
	}
}

func classifyPostfixReason(reason string) Class {
	switch {
	case strings.HasPrefix(reason, "Recipient address rejected: "):
		tail := strings.TrimPrefix(reason, "Recipient address rejected: ")
		for _, text := range []string{"User unknown", "undeliverable address", "unverified address"} {
			if strings.HasPrefix(tail, text) {
				return ClassUnknownRecipient
			}
		}
	case strings.HasPrefix(reason, "Sender address rejected: "):
		return ClassSenderVerify
	case strings.HasPrefix(reason, "Helo command rejected: "):
		return ClassBadHELO
	case strings.HasPrefix(reason, "Relay access denied"):
		return ClassRelayDenied
	case strings.HasPrefix(reason, "Client host rejected: ") && strings.Contains(reason, "blocked using "):
		return ClassBlocklisted
	}
	return ClassOther
}

// classifyMilterReject classes the reply a milter gave. The text is the
// filter's own: rspamd's default spam reply and its antivirus reply.
func classifyMilterReject(reason string, temporary bool) Class {
	switch {
	case temporary:
	case reason == "Spam message rejected":
		return ClassSpam
	case strings.Contains(reason, ": virus found: "):
		return ClassMalware
	}
	return ClassOther
}
