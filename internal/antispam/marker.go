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
var scanMarker = regexp.MustCompile(`^CSM-ANTISPAM event=scan mode=(?:enforce|dry-run) policy=(on|off) ` +
	`(?:result=ok score=(0|-?[1-9][0-9]{0,9}) action="[a-z_ ]*" decision=(unfiltered|reject|tag|none)|` +
	`result=error score=none action="unavailable" decision=none)(?: ip=([0-9A-Fa-f.:]*))?$`)

// Scan is one scan marker. Score is in Exim's integer tenths and valid only
// when OK; IP is invalid when the sender field is absent or empty.
type Scan struct {
	OK       bool
	Policy   string
	Score    int
	Decision string
	IP       netip.Addr
}

// ParseScan reads the marker CSM's scan hook logs (spec section 7). The
// marker must follow the line's timestamp and message ID directly and match
// the rendered grammar in full, so text a sender controls cannot pose as one.
func ParseScan(line string) (Scan, bool) {
	i := strings.Index(line, " CSM-ANTISPAM ")
	// Exim writes a printable ASCII prefix; the fields check alone would
	// also accept Unicode whitespace, including the NEL control character.
	if i < 0 || strings.ContainsFunc(line[:i], func(r rune) bool { return r < ' ' || r > '~' }) || !eximlog.MessagePrefix(line[:i]) {
		return Scan{}, false
	}
	m := scanMarker.FindStringSubmatch(line[i+1:])
	if m == nil {
		return Scan{}, false
	}
	s := Scan{Policy: m[1], Decision: "none"}
	if m[4] != "" {
		ip, err := netip.ParseAddr(m[4])
		if err != nil {
			return Scan{}, false
		}
		s.IP = ip.Unmap()
	}
	if m[3] == "" {
		return s, true
	}
	if (m[1] == "off") != (m[3] == "unfiltered") {
		// An opted-out recipient's scan never decides; an opted-in one does.
		return Scan{}, false
	}
	// Exim formats $spam_score_int with %d from a signed C int. A digit
	// count alone would also accept values outside its range.
	score, err := strconv.ParseInt(m[2], 10, 32)
	if err != nil {
		return Scan{}, false
	}
	s.OK, s.Score, s.Decision = true, int(score), m[3]
	return s, true
}

// ScanMarker reports whether line is the marker CSM's scan hook logs, and
// whether that scan succeeded.
func ScanMarker(line string) (marker, ok bool) {
	s, marker := ParseScan(line)
	return marker, s.OK
}
