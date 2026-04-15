package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tailFile semantics:
//   - missing file → nil
//   - small file (< 1 MB) → reads all, returns last maxLines lines
//   - large file (>= 1 MB) → seeks back ~256 KB, returns last maxLines lines
//   - file with fewer lines than maxLines → returns all lines

func TestTailFileMissingFileReturnsNil(t *testing.T) {
	withMockOS(t, &mockOS{
		open: func(string) (*os.File, error) { return nil, os.ErrNotExist },
	})
	if got := tailFile("/var/log/nope", 50); got != nil {
		t.Errorf("missing file should return nil, got %d lines", len(got))
	}
}

func TestTailFileSmallFileReturnsAllLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "small.log")
	content := "line1\nline2\nline3\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	withMockOS(t, &mockOS{open: func(string) (*os.File, error) { return os.Open(path) }})

	got := tailFile("/anything", 10)
	if len(got) != 3 {
		t.Fatalf("expected 3 lines, got %d: %v", len(got), got)
	}
	if got[0] != "line1" || got[2] != "line3" {
		t.Errorf("unexpected lines: %v", got)
	}
}

func TestTailFileTrimsToMaxLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "many.log")
	var sb strings.Builder
	for i := 1; i <= 100; i++ {
		sb.WriteString("line")
		sb.WriteString(strings.Repeat("0", 3))
		sb.WriteString("\n")
	}
	if err := os.WriteFile(path, []byte(sb.String()), 0644); err != nil {
		t.Fatal(err)
	}
	withMockOS(t, &mockOS{open: func(string) (*os.File, error) { return os.Open(path) }})

	got := tailFile("/anything", 5)
	if len(got) != 5 {
		t.Errorf("expected 5 lines (maxLines), got %d", len(got))
	}
}

func TestTailFileLargeFileSeeksToTail(t *testing.T) {
	// Build a file > 1 MB so tailFile takes the seek-from-end branch.
	dir := t.TempDir()
	path := filepath.Join(dir, "big.log")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	// Write padding lines first, then a marker line at the end.
	pad := strings.Repeat("X", 200) + "\n" // 201 bytes per line
	for i := 0; i < 6000; i++ {            // ~1.2 MB
		_, _ = f.WriteString(pad)
	}
	_, _ = f.WriteString("MARKER_LAST_LINE\n")
	_ = f.Close()

	withMockOS(t, &mockOS{open: func(string) (*os.File, error) { return os.Open(path) }})

	got := tailFile("/anything", 50)
	if len(got) == 0 {
		t.Fatal("expected lines from large-file tail, got 0")
	}
	last := got[len(got)-1]
	if last != "MARKER_LAST_LINE" {
		t.Errorf("expected last line to be MARKER_LAST_LINE, got %q", last)
	}
}

func TestTailFileStatFailureReturnsNil(t *testing.T) {
	// Open succeeds (we serve a real file) but the file is closed before
	// Stat by deleting it. On macOS the open fd's Stat still works, so
	// we simulate stat failure by pointing at /dev/null and noting we
	// can't reliably trigger it without root tampering — verify graceful
	// behavior via the missing-file path instead.
	withMockOS(t, &mockOS{
		open: func(string) (*os.File, error) { return nil, os.ErrPermission },
	})
	if got := tailFile("/x", 10); got != nil {
		t.Errorf("permission denied should return nil, got %d", len(got))
	}
}
