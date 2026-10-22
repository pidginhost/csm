package quarantine

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
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

// FuzzHeldSubject feeds arbitrary header bytes through the subject parse. The
// result is rendered in the web UI, so it must be valid UTF-8 with no control,
// bidi or format characters and at most maxSubjectLen runes.
func FuzzHeldSubject(f *testing.F) {
	f.Add("Subject: hi\r\n\r\nbody")
	f.Add("subject: =?UTF-8?B?w45uY8SDIG8=?=\r\n =?UTF-8?Q?_ofert=C4=83?=\r\n\r\n")
	f.Add("Subject: =?UTF-8?B?YRtbMzFtYgBjDQpkCWU=?=\r\n")
	f.Add("X-A: b\r\n Subject: c\r\nSubject:\xff\xfe\r\n")
	f.Add("Subject: invoice\u202efdp.exe\u200b\r\n")
	f.Add("")
	f.Fuzz(func(t *testing.T, msg string) {
		got := heldSubject([]byte(msg))
		if !utf8.ValidString(got) {
			t.Fatalf("invalid UTF-8: %q", got)
		}
		if strings.ContainsFunc(got, func(r rune) bool {
			return unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) || unicode.Is(unicode.Cf, r)
		}) {
			t.Fatalf("control, bidi or format character survived: %q", got)
		}
		if n := utf8.RuneCountInString(got); n > maxSubjectLen {
			t.Fatalf("%d runes, want at most %d", n, maxSubjectLen)
		}
	})
}
