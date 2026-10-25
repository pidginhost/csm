package mime

import (
	"strings"
	"testing"
)

// Display-name truncation must not hide an extension before a control byte,
// or turn a prefix that happens to end in .zip into the archive's actual type.
func TestLongArchiveNamesPreserveExpansion(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{strings.Repeat("a", 256) + ".zip\n.txt", orderedZip(t, archiveEntry{"leaf.txt", []byte("payload")})},
		{strings.Repeat("a", 256) + ".tar.gz\n.txt", orderedTarGz(t, archiveEntry{"leaf.txt", []byte("payload")})},
		{strings.Repeat("a", 251) + ".zip.tar.gz", orderedTarGz(t, archiveEntry{"leaf.txt", []byte("payload")})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			outer := orderedZip(t, archiveEntry{tc.name, tc.data})
			limits := DefaultLimits()
			limits.MaxArchiveDepth = 2
			limits.TempDir = t.TempDir()
			body := buildMultipartBody("BOUND", "outer.zip", "application/zip", outer)
			result := parseWithLimits(t, `multipart/mixed; boundary="BOUND"`, body, limits)
			if result.Partial || len(result.Parts) != 3 {
				t.Fatalf("parts=%d, partial=%v, reason=%q; want both archives and their leaf", len(result.Parts), result.Partial, result.PartialReason)
			}
			leaf := result.Parts[2]
			if leaf.Filename != "leaf.txt" || !leaf.Nested || string(partBytes(t, leaf)) != "payload" {
				t.Fatalf("nested payload was not extracted: %+v", leaf)
			}
		})
	}
}
