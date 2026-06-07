package quarantine

import (
	"strings"
	"testing"
)

// FuzzStripControlHeaders feeds arbitrary (attacker-influenced) message bytes
// through the control-header parse/strip path. It must never panic, must never
// leave an X-CSM-* header in the re-injectable output, and must preserve the
// message body verbatim.
func FuzzStripControlHeaders(f *testing.F) {
	f.Add("X-CSM-Forwarder: a@b\r\nX-CSM-Sender: \r\nSubject: hi\r\n\r\nbody")
	f.Add("Subject: no control headers\r\n\r\nbody")
	f.Add("")
	f.Add("X-CSM-Recipient: x@y\nno crlf body separator")
	f.Add("X-CSM-Reasons: a,b\r\nX-Csm-Spoof: nope\r\n\r\n")
	f.Fuzz(func(t *testing.T, msg string) {
		data := []byte(msg)
		_ = parseControlHeaders(data)
		clean := stripControlHeaders(data)

		// No X-CSM- header line may survive in the cleaned header block.
		cleanHdr := string(clean[:headerBlockEnd(clean)])
		for _, line := range strings.Split(cleanHdr, "\n") {
			if hasControlHeaderPrefix(strings.TrimRight(line, "\r")) {
				t.Fatalf("X-CSM header leaked into cleaned output: %q", line)
			}
		}

		// The body (after the header separator) must be unchanged.
		origBody := string(data[headerBlockEnd(data):])
		cleanBody := string(clean[headerBlockEnd(clean):])
		if origBody != cleanBody {
			t.Fatalf("body altered by strip:\norig:  %q\nclean: %q", origBody, cleanBody)
		}
	})
}
