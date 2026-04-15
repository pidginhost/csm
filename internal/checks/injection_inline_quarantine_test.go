package checks

import (
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// withQuarantineDirIQ — InlineQuarantine variant of the temp-dir override.
// Distinct from withQuarantineDirT (clean tests) and withQuarantineDir
// (linux remediate tests) to avoid duplicate symbols.
func withQuarantineDirIQ(t *testing.T, dir string) {
	t.Helper()
	old := quarantineDir
	quarantineDir = dir
	t.Cleanup(func() { quarantineDir = old })
}

// makeHighEntropyContent returns a payload of `n` bytes with Shannon
// entropy well above 4.8 — base64 of random bytes, padded out to length.
func makeHighEntropyContent(t *testing.T, n int) []byte {
	t.Helper()
	raw := make([]byte, (n*3)/4+8)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	enc := base64.StdEncoding.EncodeToString(raw)
	return []byte(enc[:n])
}

func TestInlineQuarantineCategoryNotDropperOrWebshellRejects(t *testing.T) {
	finding := alert.Finding{
		Check:   "yara_match",
		Details: "Category: phishing\n",
	}
	got, ok := InlineQuarantine(finding, "/tmp/whatever.php", []byte("anything"))
	if ok || got != "" {
		t.Errorf("non-dropper/webshell should reject, got (%q, %v)", got, ok)
	}
}

func TestInlineQuarantineKnownLibraryPathRejects(t *testing.T) {
	finding := alert.Finding{
		Details: "Category: dropper\n",
	}
	// /vendor/ is in knownLibraryPaths — must always be skipped.
	got, ok := InlineQuarantine(finding, "/home/u/public_html/vendor/lib.php", makeHighEntropyContent(t, 1024))
	if ok || got != "" {
		t.Errorf("vendor path should be skipped, got (%q, %v)", got, ok)
	}
}

func TestInlineQuarantineTooShortRejects(t *testing.T) {
	finding := alert.Finding{Details: "Category: webshell\n"}
	got, ok := InlineQuarantine(finding, "/tmp/x.php", []byte("short"))
	if ok || got != "" {
		t.Errorf("too-short content should be skipped, got (%q, %v)", got, ok)
	}
}

func TestInlineQuarantineLowEntropyRejects(t *testing.T) {
	finding := alert.Finding{Details: "Category: webshell\n"}
	// 1KB of repeating "abcd" — low Shannon entropy and no hex escapes.
	low := []byte(strings.Repeat("abcd", 256))
	got, ok := InlineQuarantine(finding, "/tmp/x.php", low)
	if ok || got != "" {
		t.Errorf("low-entropy content should be skipped, got (%q, %v)", got, ok)
	}
}

func TestInlineQuarantineStatFailureRejects(t *testing.T) {
	finding := alert.Finding{Details: "Category: dropper\n"}
	withMockOS(t, &mockOS{
		stat: func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
	})
	got, ok := InlineQuarantine(finding, "/nonexistent/file.php", makeHighEntropyContent(t, 1024))
	if ok || got != "" {
		t.Errorf("missing file should be skipped, got (%q, %v)", got, ok)
	}
}

func TestInlineQuarantineSuccessMovesAndWritesMeta(t *testing.T) {
	tmp := t.TempDir()
	qdir := filepath.Join(tmp, "quarantine")
	withQuarantineDirIQ(t, qdir)

	src := filepath.Join(tmp, "evil.php")
	payload := makeHighEntropyContent(t, 2048)
	if err := os.WriteFile(src, payload, 0644); err != nil {
		t.Fatal(err)
	}

	finding := alert.Finding{
		Check:   "yara_match",
		Details: "Category: dropper\nRule: webshell_generic\n",
	}
	qPath, ok := InlineQuarantine(finding, src, payload)
	if !ok {
		t.Fatalf("expected quarantine, got ok=false")
	}
	if qPath == "" {
		t.Fatal("expected non-empty quarantine path")
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Errorf("source should be gone, stat err=%v", err)
	}
	if _, err := os.Stat(qPath); err != nil {
		t.Errorf("quarantine file should exist: %v", err)
	}
	if _, err := os.Stat(qPath + ".meta"); err != nil {
		t.Errorf(".meta sidecar should exist: %v", err)
	}
}

func TestExtractCategoryParsesDetailsField(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"Rule: foo\nCategory: dropper\nMatched: x", "dropper"},
		{"Category: webshell", "webshell"},
		{"no category here", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := extractCategory(c.in); got != c.want {
			t.Errorf("extractCategory(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
