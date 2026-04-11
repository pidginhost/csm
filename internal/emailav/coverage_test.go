package emailav

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// --- ClamdScanner error paths ------------------------------------------

func TestClamdScannerScanMissingFile(t *testing.T) {
	s := NewClamdScanner("/var/run/nonexistent.sock")
	_, err := s.Scan("/nonexistent/file")
	if err == nil {
		t.Fatal("Scan on missing file should error")
	}
}

func TestClamdScannerScanConnectFails(t *testing.T) {
	// Real file, but the socket path does not exist, so Dial fails.
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.eml")
	if err := os.WriteFile(path, []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}
	s := NewClamdScanner(filepath.Join(dir, "no-such.sock"))
	_, err := s.Scan(path)
	if err == nil {
		t.Fatal("Scan with missing clamd socket should error")
	}
}

// --- Quarantine error paths --------------------------------------------

func TestQuarantineMessageNoSpoolFiles(t *testing.T) {
	qDir := filepath.Join(t.TempDir(), "quarantine")
	emptySpool := t.TempDir() // no -H / -D files at all
	q := NewQuarantine(qDir)
	q.allowedSpoolDirs = []string{emptySpool}

	result := &ScanResult{MessageID: "abc-1X"}
	env := QuarantineEnvelope{From: "a@x", To: []string{"b@y"}, Direction: "inbound"}

	err := q.QuarantineMessage("abc-1X", emptySpool, result, env)
	if err == nil {
		t.Fatal("QuarantineMessage with no spool files should error")
	}
	// The partially-created msgDir must be cleaned up.
	if _, statErr := os.Stat(filepath.Join(qDir, "abc-1X")); !os.IsNotExist(statErr) {
		t.Errorf("msgDir should be removed on no-spool-files failure, got stat err %v", statErr)
	}
}

func TestListMessagesEmptyDir(t *testing.T) {
	qDir := filepath.Join(t.TempDir(), "never-created")
	q := NewQuarantine(qDir)
	msgs, err := q.ListMessages()
	if err != nil {
		t.Fatalf("ListMessages on non-existent dir: %v", err)
	}
	if msgs != nil {
		t.Errorf("ListMessages on non-existent dir = %v, want nil", msgs)
	}
}

func TestListMessagesSkipsNonDirEntries(t *testing.T) {
	qDir := t.TempDir()
	// Stray file at top level should be skipped.
	if err := os.WriteFile(filepath.Join(qDir, "stray.txt"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	q := NewQuarantine(qDir)
	msgs, err := q.ListMessages()
	if err != nil {
		t.Fatalf("ListMessages: %v", err)
	}
	if len(msgs) != 0 {
		t.Errorf("stray file should be skipped, got %d messages", len(msgs))
	}
}

func TestListMessagesSkipsMissingMetadata(t *testing.T) {
	qDir := t.TempDir()
	// Directory with no metadata.json — should be silently skipped.
	if err := os.MkdirAll(filepath.Join(qDir, "orphan-1"), 0700); err != nil {
		t.Fatal(err)
	}
	q := NewQuarantine(qDir)
	msgs, err := q.ListMessages()
	if err != nil {
		t.Fatalf("ListMessages: %v", err)
	}
	if len(msgs) != 0 {
		t.Errorf("orphan dir should be skipped, got %d messages", len(msgs))
	}
}

func TestReleaseMessageMissingMetadata(t *testing.T) {
	qDir := t.TempDir()
	q := NewQuarantine(qDir)
	if err := q.ReleaseMessage("does-not-exist"); err == nil {
		t.Fatal("ReleaseMessage on unknown msgID should error")
	}
}

func TestCleanExpiredNonExistentBaseDir(t *testing.T) {
	q := NewQuarantine(filepath.Join(t.TempDir(), "never"))
	cleaned, err := q.CleanExpired(24 * time.Hour)
	if err != nil {
		t.Fatalf("CleanExpired on non-existent dir: %v", err)
	}
	if cleaned != 0 {
		t.Errorf("CleanExpired cleaned=%d, want 0", cleaned)
	}
}

func TestCleanExpiredSkipsNonDirAndMissingMetadata(t *testing.T) {
	qDir := t.TempDir()
	// A stray file.
	if err := os.WriteFile(filepath.Join(qDir, "stray"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	// A dir with no metadata.json.
	if err := os.MkdirAll(filepath.Join(qDir, "orphan"), 0700); err != nil {
		t.Fatal(err)
	}
	q := NewQuarantine(qDir)
	cleaned, err := q.CleanExpired(1 * time.Hour)
	if err != nil {
		t.Fatalf("CleanExpired: %v", err)
	}
	if cleaned != 0 {
		t.Errorf("CleanExpired should leave these untouched, got cleaned=%d", cleaned)
	}
}

// --- moveFile cross-device fallback ------------------------------------

func TestMoveFileRename(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.bin")
	dst := filepath.Join(dir, "dst.bin")
	if err := os.WriteFile(src, []byte("payload"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := moveFile(src, dst); err != nil {
		t.Fatalf("moveFile: %v", err)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Errorf("src should be gone, got %v", err)
	}
	b, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "payload" {
		t.Errorf("dst contents = %q, want payload", b)
	}
}

func TestMoveFileMissingSource(t *testing.T) {
	dir := t.TempDir()
	err := moveFile(filepath.Join(dir, "nope"), filepath.Join(dir, "out"))
	if err == nil {
		t.Fatal("moveFile on missing src should error")
	}
}
