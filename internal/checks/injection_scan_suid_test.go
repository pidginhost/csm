package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// scanForSUID:
//   - cancelled context → returns immediately
//   - maxDepth <= 0 → returns immediately
//   - ReadDir error → silent return
//   - regular files without setuid → no finding
//   - .virtfs/.mail/.public_html dirs → skipped (no recursion)
//   - SUID binary → critical finding

func TestScanForSUIDCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "x"), []byte("x"), 0755); err != nil {
		t.Fatal(err)
	}
	var findings []alert.Finding
	scanForSUID(ctx, tmp, 4, &findings)
	if len(findings) != 0 {
		t.Errorf("cancelled context should yield no findings, got %d", len(findings))
	}
}

func TestScanForSUIDMaxDepthZero(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "x"), []byte("x"), 0755); err != nil {
		t.Fatal(err)
	}
	var findings []alert.Finding
	scanForSUID(context.Background(), tmp, 0, &findings)
	if len(findings) != 0 {
		t.Errorf("maxDepth=0 should yield no findings, got %d", len(findings))
	}
}

func TestScanForSUIDMissingDir(t *testing.T) {
	var findings []alert.Finding
	scanForSUID(context.Background(), "/nonexistent-xyz", 4, &findings)
	if len(findings) != 0 {
		t.Errorf("missing dir should yield no findings, got %d", len(findings))
	}
}

func TestScanForSUIDIgnoresPlainFiles(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "regular"), []byte("x"), 0755); err != nil {
		t.Fatal(err)
	}
	var findings []alert.Finding
	scanForSUID(context.Background(), tmp, 4, &findings)
	if len(findings) != 0 {
		t.Errorf("non-SUID file should not be flagged, got %+v", findings)
	}
}

func TestScanForSUIDSkipsVirtfsAndMailAndPublicHtml(t *testing.T) {
	tmp := t.TempDir()
	for _, sub := range []string{"virtfs", "mail", "public_html"} {
		dir := filepath.Join(tmp, sub)
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		// Drop a SUID binary inside — if recursion happened, we'd see it.
		evil := filepath.Join(dir, "evil")
		if err := os.WriteFile(evil, []byte("x"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(evil, 0755|os.ModeSetuid); err != nil {
			t.Fatal(err)
		}
	}
	var findings []alert.Finding
	scanForSUID(context.Background(), tmp, 4, &findings)
	if len(findings) != 0 {
		t.Errorf("virtfs/mail/public_html dirs should NOT be recursed, got %+v", findings)
	}
}

func TestScanForSUIDFlagsSUIDBinary(t *testing.T) {
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/scan" {
				return []os.DirEntry{suidDirEntry{name: "evil", mode: 0755 | os.ModeSetuid}}, nil
			}
			return nil, os.ErrNotExist
		},
	})
	var findings []alert.Finding
	scanForSUID(context.Background(), "/scan", 4, &findings)
	if len(findings) != 1 {
		t.Fatalf("expected 1 SUID finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Check != "suid_binary" || findings[0].Severity != alert.Critical {
		t.Errorf("unexpected finding: %+v", findings[0])
	}
	if !strings.Contains(findings[0].Message, "evil") {
		t.Errorf("message should reference SUID file: %s", findings[0].Message)
	}
}

func TestScanForSUIDRecursesIntoNormalSubdirs(t *testing.T) {
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			switch name {
			case "/scan":
				return []os.DirEntry{suidDirEntry{name: "config", isDir: true}}, nil
			case "/scan/config":
				return []os.DirEntry{suidDirEntry{name: "deep", mode: 0755 | os.ModeSetuid}}, nil
			default:
				return nil, os.ErrNotExist
			}
		},
	})
	var findings []alert.Finding
	scanForSUID(context.Background(), "/scan", 4, &findings)
	if len(findings) != 1 {
		t.Errorf("expected nested SUID file to be flagged, got %+v", findings)
	}
}

type suidDirEntry struct {
	name  string
	isDir bool
	mode  os.FileMode
}

func (d suidDirEntry) Name() string      { return d.name }
func (d suidDirEntry) IsDir() bool       { return d.isDir }
func (d suidDirEntry) Type() os.FileMode { return d.mode.Type() }
func (d suidDirEntry) Info() (os.FileInfo, error) {
	mode := d.mode
	if d.isDir {
		mode |= os.ModeDir
	}
	return suidFileInfo{name: d.name, mode: mode}, nil
}

type suidFileInfo struct {
	name string
	mode os.FileMode
}

func (f suidFileInfo) Name() string       { return f.name }
func (f suidFileInfo) Size() int64        { return 1 }
func (f suidFileInfo) Mode() os.FileMode  { return f.mode }
func (f suidFileInfo) ModTime() time.Time { return time.Time{} }
func (f suidFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f suidFileInfo) Sys() interface{}   { return nil }
