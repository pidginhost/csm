package mime

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestEmptyAttachmentDecodeFailureRemainsPartial(t *testing.T) {
	for _, encoded := range []string{"", "Q"} {
		for _, single := range []bool{false, true} {
			t.Run(fmt.Sprintf("encoded=%q/single=%t", encoded, single), func(t *testing.T) {
				var result *ExtractionResult
				if single {
					result = parseEncodedSpool(t, "application/octet-stream", "base64", encoded)
				} else {
					result = parseSpoolWithCleanup(t, "multipart/mixed; boundary=outer", multipartWithEncodedPart("outer", "base64", encoded))
				}
				if len(result.Parts) != 0 {
					t.Fatalf("staged %d parts with no decoded bytes", len(result.Parts))
				}
				wantPartial := encoded != ""
				if result.Partial != wantPartial || (wantPartial && !strings.Contains(result.PartialReason, "decode")) {
					t.Fatalf("partial = %v (%q), want decode failure = %v", result.Partial, result.PartialReason, wantPartial)
				}
			})
		}
	}
}

// Empty parts before and after the last available slot must neither allocate
// staging files nor turn an otherwise complete message into a partial scan.
func TestEmptyAttachmentsDoNotSpendPartBudget(t *testing.T) {
	hPath, dPath := multipartSpool(t,
		attachment{"before.bin", nil},
		attachment{"payload.bin", []byte("scan me")},
		attachment{"after.bin", nil})
	h, d := openPair(t, hPath, dPath)
	limits := DefaultLimits()
	limits.MaxParts = 1
	dir := t.TempDir()
	staged := 0
	limits.PartSink = func(prefix string) (*os.File, error) {
		staged++
		return os.CreateTemp(dir, prefix)
	}
	result, err := ParseSpoolFiles(h, d, limits)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Close()
	if result.Partial || staged != 1 || len(result.Parts) != 1 {
		t.Fatalf("partial = %v (%q), staged = %d, parts = %d", result.Partial, result.PartialReason, staged, len(result.Parts))
	}
	part := result.Parts[0]
	if part.Filename != "payload.bin" || string(partBytes(t, part)) != "scan me" {
		t.Fatalf("wrong attachment staged: %+v", part)
	}
}
