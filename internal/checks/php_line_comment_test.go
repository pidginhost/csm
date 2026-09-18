package checks

import (
	"strings"
	"testing"
)

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
				strings.Replace(base, "<?php\n", "<?php\n// comment\rprint('EXECUTED');\n", 1),
				strings.Replace(base, "<?php\n", "<?php\n# comment\rprint('EXECUTED');\n", 1),
			} {
				if recognize([]byte(bad)) {
					t.Errorf("code after a CR-terminated comment accepted: %q", bad)
				}
			}
		})
	}
}

// An unknown attribute on an uncalled function is valid PHP. The following
// print runs before the return, so these fixtures prove reachable execution.
func TestPHPInertRecognizersRejectAttributes(t *testing.T) {
	for name, recognize := range map[string]func([]byte) bool{
		"inert stub":        IsBenignPHPStubBytes,
		"translation cache": func(b []byte) bool { return IsWPTranslationCacheBytesComplete(b, true) },
		"version data":      func(b []byte) bool { return IsWPVersionDataBytesComplete(b, true) },
	} {
		t.Run(name, func(t *testing.T) {
			tail := map[string]string{"inert stub": "", "translation cache": "return [];", "version data": "$wp_version = '7.1';"}[name]
			for _, ending := range []string{"\n", "\r", "\r\n"} {
				code := "<?php #[Example] function example() {} print('EXECUTED');" + ending + tail
				if recognize([]byte(code)) {
					t.Errorf("executable attribute line accepted: %q", code)
				}
				comment := "<?php # [Example] function example() {} print('EXECUTED');" + ending + tail
				if !recognize([]byte(comment)) {
					t.Errorf("ordinary hash comment rejected: %q", comment)
				}
			}
			if name == "inert stub" && recognize([]byte("<?php #[Example] function example() {} print('EXECUTED');")) {
				t.Error("executable attribute line at EOF accepted")
			}
		})
	}
}
