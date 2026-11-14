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

// postfixRejectKinds are the phrases Postfix writes after the rejected
// name, "<name>: ". The name is client text and is logged unquoted, so it
// can hold a phrase too; Postfix's own phrase always follows it.
var postfixRejectKinds = []struct {
	phrase string
	class  Class
}{
	{"Recipient address rejected: ", ClassUnknownRecipient},
	{"Sender address rejected: ", ClassSenderVerify},
	{"Helo command rejected: ", ClassBadHELO},
	{"Relay access denied", ClassRelayDenied},
	{"Client host rejected: ", ClassOther},
}

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
	// A rejected address can hold the envelope marker. Cutting at the last
	// one keeps Postfix's own reason in the reply whatever the address says.
	if i := strings.LastIndex(reply, "; from=<"); i >= 0 {
		r.Sender, r.Recipient = postfixEnvelope(reply[i+len("; from=<"):])
		reply = reply[:i]
	}
	r.Temporary = strings.HasPrefix(reply, "4")
	reason := strings.TrimPrefix(reply, postfixReplyCode.FindString(reply))
	r.At = LineTime(line, loc, fallback)
	r.Detail = detail(reason)
	switch {
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

// postfixEnvelope reads "S> to=<R> ..." or postscreen's "S>, to=<R>, ...".
func postfixEnvelope(s string) (sender, recipient string) {
	sender, rest, ok := strings.Cut(s, ">")
	if !ok {
		return "", ""
	}
	rest = strings.TrimPrefix(rest, ",")
	if rest, ok = strings.CutPrefix(rest, " to=<"); ok {
		recipient, _, _ = strings.Cut(rest, ">")
	}
	return sender, recipient
}

// classifyPostfixNamed classes a reply that names what it rejected. Every
// kind phrase in it must be the same one: a second kind means the name
// holds reason text, and then no phrase can be trusted.
func classifyPostfixNamed(reason string) Class {
	class, tail, found := ClassOther, "", false
	for _, k := range postfixRejectKinds {
		i := strings.LastIndex(reason, ">: "+k.phrase)
		if i < 0 {
			continue
		}
		if found {
			return ClassOther
		}
		class, tail, found = k.class, reason[i+len(">: ")+len(k.phrase):], true
	}
	if class != ClassUnknownRecipient {
		return class
	}
	// Other recipient refusals, such as an access table entry, are not an
	// unknown mailbox.
	for _, text := range []string{"User unknown", "undeliverable address", "unverified address"} {
		if strings.HasPrefix(tail, text) {
			return ClassUnknownRecipient
		}
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
