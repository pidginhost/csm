package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	tmp := t.TempDir()
	suid := filepath.Join(tmp, "evil")
	if err := os.WriteFile(suid, []byte("x"), 0755); err != nil {
		t.Fatal(err)
	}
	// Force the setuid bit.
	if err := os.Chmod(suid, 0755|os.ModeSetuid); err != nil {
		t.Fatal(err)
	}
	var findings []alert.Finding
	scanForSUID(context.Background(), tmp, 4, &findings)
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
	tmp := t.TempDir()
	sub := filepath.Join(tmp, "config")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatal(err)
	}
	suid := filepath.Join(sub, "deep")
	if err := os.WriteFile(suid, []byte("x"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(suid, 0755|os.ModeSetuid); err != nil {
		t.Fatal(err)
	}
	var findings []alert.Finding
	scanForSUID(context.Background(), tmp, 4, &findings)
	if len(findings) != 1 {
		t.Errorf("expected nested SUID file to be flagged, got %+v", findings)
	}
}
