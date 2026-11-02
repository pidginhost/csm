package antispam

import (
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/pidginhost/csm/internal/eximlog"
)

// scanMarker is the text renderScan logs for one scan, in full. The sender
// field is optional so markers Exim wrote before the upgrade still count.
var scanMarker = regexp.MustCompile(`^CSM-ANTISPAM event=scan mode=(enforce|dry-run) policy=(on|off) ` +
	`(?:result=ok score=(0|-?[1-9][0-9]{0,9}) action="[a-z_ ]*" decision=(unfiltered|reject|tag|none)|` +
	`result=error score=none action="unavailable" decision=none)(?: ip=([0-9A-Fa-f.:]*))?$`)

// rspamdScanMarker is the record CSM's Postfix Lua logs for one scan, in
// full, from the "; " that ends rspamd's own prefix. Its submatches 1 to 5
// are scanMarker's; 6 is the queue ID.
var rspamdScanMarker = regexp.MustCompile(`^; lua; csm_scope\.lua:[0-9]+: CSM-ANTISPAM event=scan mode=(enforce|dry-run) policy=(on|off) ` +
	`result=ok score=(0|-?[1-9][0-9]{0,9}) action="[a-z_ ]*" decision=(unfiltered|reject|tag|none) ip=([0-9A-Fa-f.:]*) qid=([0-9A-Za-z_]*)$`)

// Scan is one scan marker. Score is in integer tenths and valid only when
// OK; IP is invalid when the sender field is absent or empty. MsgID is
// the Exim message ID as the line wrote it, or Postfix's queue ID.
type Scan struct {
	OK       bool
	Mode     string
	Policy   string
	Score    int
	Decision string
	IP       netip.Addr
	MsgID    string
}

// ParseScan reads the marker CSM's scan hook logs (spec section 7). The
// marker must follow the line's timestamp and message ID directly and match
// the rendered grammar in full, so text a sender controls cannot pose as one.
func ParseScan(line string) (Scan, bool) {
	i := strings.Index(line, " CSM-ANTISPAM ")
	// Exim writes a printable ASCII prefix; the fields check alone would
	// also accept Unicode whitespace, including the NEL control character.
	if i < 0 || strings.ContainsFunc(line[:i], notPrintable) || !eximlog.MessagePrefix(line[:i]) {
		return Scan{}, false
	}
	m := scanMarker.FindStringSubmatch(line[i+1:])
	if m == nil {
		return Scan{}, false
	}
	fields := strings.Fields(line[:i])
	return scanOf(m, fields[len(fields)-1])
}

// ParseRspamdScan reads the record CSM's Postfix Lua logs into rspamd's log
// (spec section 5.2). rspamd writes "<time> #<pid>(<process>) <<task>>; ",
// then "<module>; <function>: " and the message. The record must take the
// module and function places, so only csm_scope.lua logs it: before the
// first "; " a message would follow a function's ": ", and what follows
// must match the grammar in full.
func ParseRspamdScan(line string) (Scan, bool) {
	i := strings.Index(line, "; ")
	if i < 0 || strings.Contains(line[:i], ": ") || strings.ContainsFunc(line[:i], notPrintable) {
		return Scan{}, false
	}
	m := rspamdScanMarker.FindStringSubmatch(line[i:])
	if m == nil {
		return Scan{}, false
	}
	return scanOf(m, m[6])
}

// notPrintable reports a rune outside printable ASCII.
func notPrintable(r rune) bool { return r < ' ' || r > '~' }

// scanOf builds the Scan of a marker's mode, policy, score, decision and
// sender submatches.
func scanOf(m []string, msgID string) (Scan, bool) {
	s := Scan{Mode: m[1], Policy: m[2], Decision: "none", MsgID: msgID}
	if m[5] != "" {
		ip, err := netip.ParseAddr(m[5])
		if err != nil {
			return Scan{}, false
		}
		s.IP = ip.Unmap()
	}
	if m[4] == "" {
		return s, true
	}
	if (m[2] == "off") != (m[4] == "unfiltered") {
		// An opted-out recipient's scan never decides; an opted-in one does.
		return Scan{}, false
	}
	// Exim formats $spam_score_int with %d from a signed C int. A digit
	// count alone would also accept values outside its range.
	score, err := strconv.ParseInt(m[3], 10, 32)
	if err != nil {
		return Scan{}, false
	}
	s.OK, s.Score, s.Decision = true, int(score), m[4]
	return s, true
}

// ScanMarker reports whether line is the marker CSM's scan hook logs, and
// whether that scan succeeded.
func ScanMarker(line string) (marker, ok bool) {
	s, marker := ParseScan(line)
	return marker, s.OK
}
