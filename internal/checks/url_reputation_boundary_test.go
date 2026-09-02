package checks

import (
	"strings"
	"testing"
)

// The known-bad host list was matched as a bare suffix, so any host ending
// in the same characters ("orbit.ly" vs "bit.ly", "this.gd" vs "is.gd")
// was reported as a known exfiltration host. The match respects DNS label
// boundaries: the host itself or a subdomain of it.
func TestKnownBadExfilHostRespectsLabelBoundary(t *testing.T) {
	for _, u := range []string{"https://orbit.ly/widget.js", "https://this.gd/app.js", "https://notpastebin.com/a.js"} {
		if flagged, reason := scriptSrcStrongReason(u); flagged && strings.Contains(reason, "known-bad exfil host") {
			t.Errorf("%s reported as %q", u, reason)
		}
	}
	for _, u := range []string{"https://bit.ly/abc", "https://cdn.bit.ly/abc", "https://pastebin.com/raw/x"} {
		flagged, reason := scriptSrcStrongReason(u)
		if !flagged || !strings.Contains(reason, "known-bad exfil host") {
			t.Errorf("%s not reported as a known-bad host: %v %q", u, flagged, reason)
		}
	}
}
