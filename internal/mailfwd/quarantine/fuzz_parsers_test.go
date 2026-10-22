package quarantine

import (
	"strings"
	"testing"
	"unicode"
)

func FuzzSingleEnvelopeAddress(f *testing.F) {
	for _, seed := range []string{"sender@example.com", `"quoted"@example.net`,
		`"root,x"@example.net`, "root,owner@example.net", `"-flag"@example.net`,
		`"two words"@example.net`, "", "-sender@example.com", "sender@example.com\x00"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if !singleEnvelopeAddress(value) {
			return
		}
		// Neither Exim's list splitting nor dequoting may reveal a second
		// destination, an option prefix or whitespace in an accepted value.
		dequoted := strings.ReplaceAll(value, `"`, "")
		if dequoted == "" || strings.HasPrefix(dequoted, "-") || strings.ContainsAny(dequoted, ",<>") ||
			strings.ContainsFunc(dequoted, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) {
			t.Fatalf("unsafe Exim envelope accepted: %q", value)
		}
	})
}
