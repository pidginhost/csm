package mailstats

import (
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/pidginhost/csm/internal/eximlog"
)

// Class is the kind of reason an SMTP reject gave.
type Class string

const (
	ClassSpam             Class = "spam"
	ClassMalware          Class = "malware"
	ClassUnknownRecipient Class = "unknown_recipient"
	ClassSenderVerify     Class = "sender_verify"
	ClassBadHELO          Class = "bad_helo"
	ClassRelayDenied      Class = "relay_denied"
	ClassAuthRequired     Class = "auth_required"
	ClassSuspended        Class = "suspended"
	ClassMailboxFull      Class = "mailbox_full"
	ClassBlocklisted      Class = "blocklisted"
	ClassRateLimited      Class = "rate_limited"
	ClassOther            Class = "other"
)

// Classes lists every class in display order.
var Classes = []Class{
	ClassSpam, ClassMalware, ClassUnknownRecipient, ClassSenderVerify,
	ClassBadHELO, ClassRelayDenied, ClassAuthRequired, ClassSuspended,
	ClassMailboxFull, ClassBlocklisted, ClassRateLimited, ClassOther,
}

// Reject is one SMTP command an Exim ACL rejected.
type Reject struct {
	At        time.Time `json:"at"`
	Class     Class     `json:"class"`
	Temporary bool      `json:"temporary,omitempty"`
	IP        string    `json:"ip,omitempty"`
	Sender    string    `json:"sender,omitempty"`
	Recipient string    `json:"recipient,omitempty"`
	Detail    string    `json:"detail"`
	MsgID     string    `json:"msg_id,omitempty"`
}

// rejectVerb matches the verb Exim logs for an ACL reject: "rejected" or
// "temporarily rejected", then the ACL's where-name. The names are upper
// case except "after DATA", "during MIME ACL checks" and "connection", so
// reason text such as "Message rejected as spam" does not match.
var rejectVerb = regexp.MustCompile(` (temporarily )?rejected (?:[A-Z]|after |during |connection )`)

var smtpCode = regexp.MustCompile(`^[0-9]{3} (?:[0-9]\.[0-9]{1,3}\.[0-9]{1,3} )?`)

// rejectTexts are the stock reasons, prefix texts first. A prefix text
// opens the reason. A mid text, which cPanel writes after other words, can
// appear anywhere in it.
var rejectTexts = []struct {
	class Class
	text  string
	mid   bool
}{
	{ClassUnknownRecipient, "No Such User Here", false},
	{ClassUnknownRecipient, "No such person at this address", false},
	{ClassSenderVerify, "Sender verify failed", false},
	{ClassSenderVerify, "Could not complete sender verify", false},
	{ClassRelayDenied, "Rejected relay attempt", false},
	{ClassRelayDenied, "relay not permitted", false},
	{ClassAuthRequired, "SMTP AUTH is required", false},
	{ClassMailboxFull, "Mailbox is full", false},
	{ClassMalware, "contains a virus or other harmful content", true},
	{ClassUnknownRecipient, "account or domain may not exist", true},
	{ClassBadHELO, "Invalid HELO name", true},
	{ClassSuspended, "has been suspended", true},
	{ClassBlocklisted, "is in an RBL", true},
	{ClassBlocklisted, "is listed", true},
	{ClassRateLimited, "ratelimited", true},
}

// ParseReject reads an Exim log line for an SMTP command an ACL rejected.
// The verb must directly follow the peer and the fields Exim logs with it,
// so the same words in a HELO, address or reason cannot make a line a
// reject. Lines where sender text could pose as the reason get ClassOther.
func ParseReject(line string, loc *time.Location, fallback time.Time) (Reject, bool) {
	h := strings.Index(line, " H=")
	if h < 0 {
		return Reject{}, false
	}
	msgID, ok := rejectPrefix(line[:h])
	if !ok {
		return Reject{}, false
	}
	peer := line[h+len(" H="):]
	verbs := rejectVerb.FindAllStringSubmatchIndex(peer, -1)
	if len(verbs) == 0 {
		return Reject{}, false
	}
	v, fieldsEnd, sender := verbs[0], verbs[0][0], ""
	// The sender is the last field before the verb, but for the A= field
	// Exim adds for an authenticated client. A verb inside a quoted sender
	// comes first, so the real one is looked for after the sender.
	if f := strings.Index(peer, " F=<"); f >= 0 && f < v[0] {
		start := f + len(" F=<")
		n := unquotedIndex(peer[start:], '>')
		if n < 0 {
			return Reject{}, false
		}
		verb := start + n + 1
		if auth, ok := strings.CutPrefix(peer[verb:], " A="); ok {
			sp := strings.IndexByte(auth, ' ')
			if sp <= 0 {
				return Reject{}, false
			}
			verb += len(" A=") + sp
		}
		i := slices.IndexFunc(verbs, func(m []int) bool { return m[0] == verb })
		if i < 0 {
			return Reject{}, false
		}
		v, fieldsEnd, sender = verbs[i], f, peer[start:start+n]
	}
	ip, end := readPeer(peer[:fieldsEnd])
	if end == 0 {
		return Reject{}, false
	}
	r := Reject{At: LineTime(line, loc, fallback), Class: ClassOther, Temporary: v[2] >= 0,
		IP: ip, Sender: sender, MsgID: msgID}
	after := strings.TrimPrefix(peer[v[0]:], " temporarily")[len(" rejected "):]
	cmd, addr, reason, known := wherePhrase(after)
	if !known {
		r.Detail = detail(after)
		return r, true
	}
	// Remote ident is unquoted client text, a quote lets an address hold
	// spaces, and a second verb means one of them is sender text.
	spoofable := strings.Contains(sender+addr, `"`) || strings.Contains(peer[end:fieldsEnd], " U=") ||
		slices.IndexFunc(verbs, func(m []int) bool { return m[0] >= end && m[0] != v[0] }) >= 0
	switch cmd {
	case "RCPT":
		r.Recipient = addr
	case "MAIL":
		r.Sender = addr
	}
	senderText := peer[:len(peer)-len(reason)]
	reason = strings.TrimPrefix(reason, smtpCode.FindString(reason))
	r.Detail = detail(reason)
	if !spoofable {
		r.Class = classify(reason, r.Temporary, senderText)
	}
	return r, true
}

// rejectPrefix reads what Exim writes before the peer: date, time,
// optional zone and PID, and the message ID an after-DATA reject carries.
func rejectPrefix(prefix string) (msgID string, ok bool) {
	if eximlog.MessagePrefix(prefix) {
		f := strings.Fields(prefix)
		return f[len(f)-1], true
	}
	// A placeholder ID lets MessagePrefix check a prefix that has none.
	return "", eximlog.MessagePrefix(prefix + " 0-0-0")
}

// readPeer reads s, the H= value and the fields Exim logs after it up to
// the sender or the verb. end is the offset just past the client address,
// or 0 when s is not such a peer.
func readPeer(s string) (ip string, end int) {
	ip, end = eximlog.HFieldClientIPAndEnd(s)
	if end == 0 {
		return "", 0
	}
	rest := s[end:]
	if port, cut := strings.CutPrefix(rest, ":"); cut {
		rest = strings.TrimLeft(port, "0123456789")
	}
	for rest != "" {
		if !fieldStart(rest) {
			return "", 0
		}
		n := unquotedIndex(rest[1:], ' ')
		if n < 0 {
			break
		}
		rest = rest[1+n:]
	}
	return ip, end
}

// fieldStart reports whether s opens an Exim field: a space, a key of one
// to three letters, and "=".
func fieldStart(s string) bool {
	eq := strings.IndexByte(s, '=')
	if len(s) < 3 || s[0] != ' ' || eq < 2 || eq > 4 {
		return false
	}
	for _, c := range []byte(s[1:eq]) {
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
			return false
		}
	}
	return true
}

// wherePhrase splits the text after the verb into the command, its address
// and the reason. known is false for a where-name this package does not
// read.
func wherePhrase(s string) (cmd, addr, reason string, known bool) {
	for _, w := range []string{"after DATA: ", `connection in "connect" ACL: `} {
		if reason, ok := strings.CutPrefix(s, w); ok {
			return "", "", reason, true
		}
	}
	for _, cmd := range []string{"RCPT", "MAIL"} {
		if v, ok := strings.CutPrefix(s, cmd+" <"); ok {
			n := unquotedIndex(v, '>')
			if n >= 0 && strings.HasPrefix(v[n+1:], ": ") {
				return cmd, v[:n], v[n+len(">: "):], true
			}
		}
	}
	return "", "", "", false
}

// unquotedIndex returns the index of the first c in s outside a quoted
// string, or -1. A quoted local part can hold spaces and delimiters.
func unquotedIndex(s string, c byte) int {
	quoted := false
	for i := 0; i < len(s); i++ {
		switch {
		case quoted && s[i] == '\\':
			i++
		case s[i] == '"':
			quoted = !quoted
		case !quoted && s[i] == c:
			return i
		}
	}
	return -1
}

// classify matches a reason against the stock texts. A reason can repeat
// the HELO or an address, so a mid text that senderText, the line up to
// the reason, also holds may be the sender's and is skipped.
func classify(reason string, temporary bool, senderText string) Class {
	if reason == "Message rejected as spam" {
		return ClassSpam
	}
	senderText = strings.ToLower(senderText)
	for _, t := range rejectTexts {
		switch {
		case t.class == ClassRateLimited && !temporary:
		case !t.mid && strings.HasPrefix(reason, t.text):
			return t.class
		case t.mid && strings.Contains(reason, t.text) && !strings.Contains(senderText, strings.ToLower(t.text)):
			return t.class
		}
	}
	return ClassOther
}

// detail is s without control characters, cut to 120 runes.
func detail(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	if r := []rune(s); len(r) > 120 {
		s = string(r[:120])
	}
	return s
}
