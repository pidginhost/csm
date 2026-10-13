package antispam

import (
	"regexp"
	"strings"

	"github.com/pidginhost/csm/internal/eximlog"
)

// scanMarker is the text renderScan logs for one scan, in full.
var scanMarker = regexp.MustCompile(`^CSM-ANTISPAM event=scan mode=(?:enforce|dry-run) policy=(on|off) ` +
	`(?:result=ok score=-?[0-9]{1,10} action="[a-z_ ]*" decision=(unfiltered|reject|tag|none)|` +
	`result=error score=none action="unavailable" decision=none)$`)

// ScanMarker reports whether line is the marker CSM's scan hook logs, and
// whether that scan succeeded (spec section 7). The marker must follow the
// line's timestamp and message ID directly and match the rendered grammar
// in full, so text a sender controls cannot pose as one.
func ScanMarker(line string) (marker, ok bool) {
	i := strings.Index(line, " CSM-ANTISPAM ")
	// Exim writes the prefix with plain spaces; the fields check alone
	// would split on any whitespace.
	if i < 0 || strings.ContainsFunc(line[:i], isControl) || !eximlog.MessagePrefix(line[:i]) {
		return false, false
	}
	m := scanMarker.FindStringSubmatch(line[i+1:])
	switch {
	case m == nil:
		return false, false
	case m[2] == "":
		return true, false
	case (m[1] == "off") != (m[2] == "unfiltered"):
		// An opted-out recipient's scan never decides; an opted-in one does.
		return false, false
	}
	return true, true
}

func isControl(r rune) bool { return r < ' ' || r == 0x7f }
