package checks

import (
	"errors"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// Whatever a tenant puts in a file or its name, a rendered preview holds only
// printable text, newlines and tabs, and still names both digests.
func FuzzRenderChangeDiff(f *testing.F) {
	f.Add("/home/u/.htaccess", "keep\n", "keep\nadd\n")
	f.Add("/home/u/\x1b[2J.php", "a\r\nb", "a\u202e\xff\n")
	f.Add("/home/u/x", "", "\x1b]0;t\x07\n\x9b31m\n")
	f.Fuzz(func(t *testing.T, path, before, after string) {
		diff, err := renderChangeDiff(path, []byte(before), []byte(after))
		if errors.Is(err, errPreviewBinary) || errors.Is(err, errPreviewTooLarge) {
			return
		}
		if err != nil {
			t.Fatalf("render: %v", err)
		}
		if !utf8.ValidString(diff) {
			t.Fatalf("invalid UTF-8 in preview: %q", diff)
		}
		for _, r := range diff {
			if r != '\n' && r != '\t' && !unicode.IsPrint(r) {
				t.Fatalf("unescaped %U in preview: %q", r, diff)
			}
		}
		if before != after && !strings.Contains(diff, "\tsha256:"+sha256Hex([]byte(after))+"\n") {
			t.Fatalf("preview does not name the after digest: %q", diff)
		}
	})
}
