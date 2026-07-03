//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// DMN-12: an in-place truncation (copytruncate logrotate, or a manual
// truncate) leaves the read cursor past EOF. Without a reset the listener
// tails from the stale offset forever and never sees the freshly rewritten
// file, going permanently blind.
func TestAFAlgTailResetsOnTruncation(t *testing.T) {
	_, appendLine := withAuditLog(t)
	l, err := NewAFAlgAuditListener(make(chan alert.Finding, 4), &config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	readBuf := make([]byte, 16*1024)

	// Advance the cursor by tailing a first record.
	appendLine(sampleAFAlgLine)
	l.tail(readBuf)
	if l.EventCount() != 1 {
		t.Fatalf("EventCount = %d, want 1 after first tail", l.EventCount())
	}
	if l.pos == 0 {
		t.Fatal("read cursor did not advance after first tail")
	}

	// Simulate copytruncate: same inode truncated to zero.
	if err := os.Truncate(auditLogPath, 0); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	// A tail with the cursor past EOF must reset to 0 instead of sitting blind.
	l.tail(readBuf)
	if l.pos != 0 {
		t.Fatalf("pos = %d after truncation, want 0 (offset past EOF not reset)", l.pos)
	}

	// New content written from offset 0 must now be seen.
	appendLine(sampleAFAlgLine)
	l.tail(readBuf)
	if l.EventCount() != 2 {
		t.Fatalf("EventCount = %d, want 2 after post-truncation write", l.EventCount())
	}
}

// DMN-12: a failed rotation re-open must not blind the listener forever. The
// re-open is retried with backoff until the replacement file appears.
func TestAFAlgReopenRetriesWithBackoff(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(good, []byte("# audit log\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := auditLogPath
	auditLogPath = good
	t.Cleanup(func() { auditLogPath = old })

	l, err := NewAFAlgAuditListener(make(chan alert.Finding, 4), &config.Config{})
	if err != nil {
		t.Fatal(err)
	}

	// Rotation fired but the replacement is not on disk yet.
	missing := filepath.Join(dir, "gone.log")
	l.path = missing
	l.reopenPending = true

	now := time.Now()
	if l.reopenIfDue(now) {
		t.Fatal("reopen should report not-ready while the target is missing")
	}
	if !l.reopenPending {
		t.Fatal("a failed reopen must stay pending, not give up forever")
	}

	// Immediate retry is gated by the backoff window.
	if l.reopenIfDue(now) {
		t.Fatal("reopen retried before its backoff elapsed")
	}
	if !l.reopenPending {
		t.Fatal("reopen still pending after a gated retry")
	}

	// Target reappears; after the backoff window the retry succeeds.
	l.path = good
	if !l.reopenIfDue(now.Add(afAlgReopenBackoffMax + time.Second)) {
		t.Fatal("reopen should succeed once the target exists and backoff has elapsed")
	}
	if l.reopenPending {
		t.Fatal("a successful reopen must clear the pending state")
	}
}
