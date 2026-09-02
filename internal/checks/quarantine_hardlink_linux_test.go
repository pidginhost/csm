//go:build linux

package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A hard-linked malware file used to be "quarantined" by adding one more
// link to the same account-owned inode and unlinking the detected name: the
// content stayed live under its other name and the quarantine entry itself
// stayed writable by the account through that name. A multi-link inode must
// be copied into quarantine, and the surviving links must be reported.
func TestQuarantineFileTOCTOUSafe_CopiesMultiLinkFile(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "public_html", "shell.php")
	if err := os.MkdirAll(filepath.Dir(src), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, []byte("<?php /* linked */"), 0o644); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(tmp, "elsewhere", "same.php")
	if err := os.MkdirAll(filepath.Dir(other), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(src, other); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(src)
	if err != nil {
		t.Fatal(err)
	}
	qPath := filepath.Join(tmp, "quarantine", "ts_shell.php")
	if mkErr := os.MkdirAll(filepath.Dir(qPath), 0o700); mkErr != nil {
		t.Fatal(mkErr)
	}

	err = quarantineFileTOCTOUSafe(src, qPath, info)
	if err == nil || !strings.Contains(err.Error(), "hard link") {
		t.Fatalf("surviving hard link not reported: err=%v", err)
	}
	if _, statErr := os.Stat(src); !os.IsNotExist(statErr) {
		t.Fatalf("detected path still present: %v", statErr)
	}
	qInfo, err := os.Stat(qPath)
	if err != nil {
		t.Fatalf("quarantine copy missing: %v", err)
	}
	otherInfo, err := os.Stat(other)
	if err != nil {
		t.Fatalf("surviving link missing: %v", err)
	}
	if os.SameFile(qInfo, otherInfo) {
		t.Fatal("quarantine entry shares the account-owned inode with the surviving link")
	}
	if got, _ := os.ReadFile(qPath); string(got) != "<?php /* linked */" {
		t.Fatalf("quarantine copy content = %q", got)
	}
}
