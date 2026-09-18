package checks

import "testing"

// PHP ends a "//" or "#" comment at a bare carriage return as well as at a
// line feed. A recognizer that reads past the CR treats the next statement as
// comment text and proves a file inert while PHP executes it.
func TestPHPLineCommentEndsAtCarriageReturn(t *testing.T) {
	recognizers := map[string]func([]byte) bool{
		"inert stub":        IsBenignPHPStubBytes,
		"translation cache": func(b []byte) bool { return IsWPTranslationCacheBytesComplete(b, true) },
		"version data":      func(b []byte) bool { return IsWPVersionDataBytesComplete(b, true) },
	}
	bodies := map[string]string{
		"inert stub":        "<?php\n// Silence is golden.",
		"translation cache": "<?php\nreturn ['messages'=>['Save'=>'Salveaza']];",
		"version data":      "<?php\n$wp_version = '7.1';",
	}
	for name, recognize := range recognizers {
		base := bodies[name]
		t.Run(name, func(t *testing.T) {
			if !recognize([]byte(base)) {
				t.Fatalf("control body not recognized: %q", base)
			}
			for _, ok := range []string{
				base + "\n// a\r// b\r\n# c\r",
				base + "\n// comment ends at EOF",
			} {
				if !recognize([]byte(ok)) {
					t.Errorf("CR-separated comments rejected: %q", ok)
				}
			}
			for _, bad := range []string{
				base + "\n// comment\rsystem($_POST['c']);",
				base + "\n# comment\rsystem($_POST['c']);",
			} {
				if recognize([]byte(bad)) {
					t.Errorf("code after a CR-terminated comment accepted: %q", bad)
				}
			}
		})
	}
}
