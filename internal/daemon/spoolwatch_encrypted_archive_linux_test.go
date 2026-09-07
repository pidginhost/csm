//go:build linux

package daemon

import (
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	emime "github.com/pidginhost/csm/internal/mime"
)

// Spool findings reached the alert pipeline with a zero Timestamp, so every
// email AV finding was dated 0001-01-01 in alerts, the web UI and the store.
func TestEmitFindingStampsTimestamp(t *testing.T) {
	ch := make(chan alert.Finding, 1)
	sw := &SpoolWatcher{alertCh: ch}

	before := time.Now()
	sw.emitFinding("email_av_test", alert.Warning, "hello")
	after := time.Now()

	got := <-ch
	if got.Timestamp.IsZero() {
		t.Fatal("Timestamp is zero; the finding would be dated 0001-01-01 everywhere it is shown")
	}
	if got.Timestamp.Before(before) || got.Timestamp.After(after) {
		t.Errorf("Timestamp = %v, want a time within [%v, %v]", got.Timestamp, before, after)
	}
}

// An encrypted archive is not a degraded scanner. It gets its own check so an
// operator can tell "a package arrived that nobody can scan" apart from "our
// scanning is broken", and so the two do not share a rate limiter.
func TestEncryptedArchiveWarningNamesArchiveAndEntry(t *testing.T) {
	ch := make(chan alert.Finding, 4)
	sw := &SpoolWatcher{alertCh: ch}

	sw.emitEncryptedArchiveWarning("1x3U8R-0000000BFoO-1j5I", []emime.EncryptedArchiveEntry{
		{ArchiveName: "documents.zip", Filename: "Report.pdf"},
	})

	select {
	case got := <-ch:
		if got.Check != "email_av_encrypted_archive" {
			t.Errorf("Check = %q, want email_av_encrypted_archive", got.Check)
		}
		if got.Severity != alert.Warning {
			t.Errorf("Severity = %v, want Warning", got.Severity)
		}
		for _, want := range []string{"1x3U8R-0000000BFoO-1j5I", "documents.zip", "Report.pdf"} {
			if !strings.Contains(got.Message, want) {
				t.Errorf("Message = %q, want it to contain %q", got.Message, want)
			}
		}
	case <-time.After(time.Second):
		t.Fatal("no finding emitted for an encrypted archive")
	}
}

func TestEncryptedArchiveWarningRateLimited(t *testing.T) {
	ch := make(chan alert.Finding, 4)
	sw := &SpoolWatcher{alertCh: ch}
	entries := []emime.EncryptedArchiveEntry{{ArchiveName: "a.zip", Filename: "b.pdf"}}

	sw.emitEncryptedArchiveWarning("msg-1", entries)
	sw.emitEncryptedArchiveWarning("msg-2", entries)

	if len(ch) != 1 {
		t.Fatalf("emitted %d findings for two back-to-back encrypted archives, want 1", len(ch))
	}
}

// The encrypted-archive limiter must not silence a genuinely degraded scanner.
func TestEncryptedArchiveWarningDoesNotSuppressDegraded(t *testing.T) {
	ch := make(chan alert.Finding, 4)
	sw := &SpoolWatcher{alertCh: ch}

	sw.emitEncryptedArchiveWarning("msg-1", []emime.EncryptedArchiveEntry{{ArchiveName: "a.zip", Filename: "b.pdf"}})
	sw.emitDegradedWarning("all AV engines unavailable")

	if len(ch) != 2 {
		t.Fatalf("emitted %d findings, want 2: the two conditions share no rate limiter", len(ch))
	}
}

func TestEncryptedArchiveWarningSkippedWhenNoEntries(t *testing.T) {
	ch := make(chan alert.Finding, 4)
	sw := &SpoolWatcher{alertCh: ch}

	sw.emitEncryptedArchiveWarning("msg-1", nil)

	if len(ch) != 0 {
		t.Fatalf("emitted %d findings with no encrypted entries, want 0", len(ch))
	}
}
