package checks

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/alert"
)

type recordingSink struct{ records []actionlog.Record }

func (r *recordingSink) Write(rec actionlog.Record) error {
	r.records = append(r.records, rec)
	return nil
}

func withActionSink(t *testing.T) *recordingSink {
	t.Helper()
	sink := &recordingSink{}
	actionlog.SetSink(sink, "host.example.com")
	t.Cleanup(func() { actionlog.SetSink(nil, "") })
	return sink
}

// A quarantine used to leave its only evidence in a sidecar file next to the
// archived copy. The action record carries the digest of what was removed, so
// a reviewer can tell which exact content left the account.
func TestQuarantineRecordsTheDigestOfWhatWasRemoved(t *testing.T) {
	sink := withActionSink(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "shell.php")
	const content = "<?php eval($_POST[0]);"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	before := actionlog.Stat(path)

	qPath := filepath.Join(dir, "quarantine", "shell.php")
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat: %v", err)
	}
	meta := quarantineMetadata(path, info, "webshell_realtime")

	if err := quarantineTarget(path, qPath, info, meta); err != nil {
		t.Fatalf("quarantine: %v", err)
	}

	if len(sink.records) != 1 {
		t.Fatalf("records = %d, want 1", len(sink.records))
	}
	rec := sink.records[0]
	if rec.Op != "respond.quarantine_file" {
		t.Errorf("op = %q, want respond.quarantine_file", rec.Op)
	}
	if rec.Target != path {
		t.Errorf("target = %q, want %q", rec.Target, path)
	}
	if rec.Result != actionlog.Applied {
		t.Errorf("result = %q, want applied", rec.Result)
	}
	if rec.Before == nil || rec.Before.Digest != before.Digest || rec.Before.Digest == "" {
		t.Errorf("before digest = %+v, want the original content digest %q", rec.Before, before.Digest)
	}
	if rec.After == nil || rec.After.Exists {
		t.Errorf("after = %+v, want the original recorded as gone", rec.After)
	}
	if rec.Reason != "webshell_realtime" {
		t.Errorf("reason = %q, want the finding that caused it", rec.Reason)
	}
	if !strings.Contains(rec.Undo, qPath) {
		t.Errorf("undo = %q, want it to name the quarantined copy", rec.Undo)
	}
}

// A quarantine that fails has to be recorded too: "CSM tried and could not" is
// a different operational state from "CSM did nothing".
func TestFailedQuarantineIsRecordedAsFailed(t *testing.T) {
	sink := withActionSink(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "shell.php")
	if err := os.WriteFile(path, []byte("<?php"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat: %v", err)
	}

	orig := quarantineTargetFn
	t.Cleanup(func() { quarantineTargetFn = orig })
	quarantineTargetFn = func(string, string, os.FileInfo, []byte) error {
		return errors.New("read-only file system")
	}

	qPath := filepath.Join(dir, "quarantine", "shell.php")
	if err := quarantineTarget(path, qPath, info, quarantineMetadata(path, info, "webshell")); err == nil {
		t.Fatal("quarantine reported success while the move failed")
	}

	if len(sink.records) != 1 {
		t.Fatalf("records = %d, want 1", len(sink.records))
	}
	rec := sink.records[0]
	if rec.Result != actionlog.Failed {
		t.Errorf("result = %q, want failed", rec.Result)
	}
	if !strings.Contains(rec.Error, "read-only file system") {
		t.Errorf("error = %q, want the failure reason", rec.Error)
	}
	if rec.After == nil || !rec.After.Exists {
		t.Errorf("after = %+v, want the file recorded as still present", rec.After)
	}
}

// A surgical clean rewrites a file in place. Both digests are recorded so a
// reviewer can prove which content was replaced, not just that something was.
func TestCleanRecordsBothDigests(t *testing.T) {
	sink := withActionSink(t)
	restoreQuarantineDir(t)

	path := filepath.Join(t.TempDir(), "index.php")
	const infected = "<?php\n\x00\x0b@include(base64_decode(\"ZXZpbA==\"));\necho 'ok';\n"
	if err := os.WriteFile(path, []byte(infected), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	before := actionlog.Stat(path)

	result := CleanInfectedFile(path)
	if !result.Cleaned {
		t.Fatalf("clean did not run: %+v", result)
	}

	if len(sink.records) == 0 {
		t.Fatal("clean recorded no action")
	}
	rec := sink.records[len(sink.records)-1]
	if rec.Op != "respond.clean_file" {
		t.Fatalf("op = %q, want respond.clean_file", rec.Op)
	}
	if rec.Before == nil || rec.Before.Digest != before.Digest {
		t.Errorf("before digest = %+v, want %q", rec.Before, before.Digest)
	}
	if rec.After == nil || rec.After.Digest == "" || rec.After.Digest == before.Digest {
		t.Errorf("after digest = %+v, want a different digest", rec.After)
	}
	if !strings.Contains(rec.Undo, result.BackupPath) {
		t.Errorf("undo = %q, want it to name the pre-clean backup", rec.Undo)
	}
}

func TestCleanWithNothingToRemoveIsRecordedAsRefused(t *testing.T) {
	sink := withActionSink(t)
	restoreQuarantineDir(t)

	path := filepath.Join(t.TempDir(), "clean.php")
	if err := os.WriteFile(path, []byte("<?php echo \"hello\";"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if result := CleanInfectedFile(path); result.Cleaned {
		t.Fatal("a clean file was rewritten")
	}
	if len(sink.records) == 0 {
		t.Fatal("declined clean recorded no action")
	}
	if got := sink.records[len(sink.records)-1].Result; got != actionlog.Refused {
		t.Fatalf("result = %q, want refused", got)
	}
}

func restoreQuarantineDir(t *testing.T) {
	t.Helper()
	orig := quarantineDir
	quarantineDir = t.TempDir()
	t.Cleanup(func() { quarantineDir = orig })
}

// A refused kill is as important to record as a completed one: it is the
// answer to "why is that process still running".
func TestKillActionRecordsRefusalsAndSuccesses(t *testing.T) {
	finding := alert.Finding{Check: "fake_kernel_thread", Severity: alert.Critical, Message: "kthreadd impostor"}

	for _, tc := range []struct {
		name   string
		err    error
		result actionlog.Result
	}{
		{"killed", nil, actionlog.Applied},
		{"not eligible", errProcessNotEligible, actionlog.Refused},
		{"already exited", os.ErrProcessDone, actionlog.Refused},
		{"signal failed", errors.New("operation not permitted"), actionlog.Failed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sink := withActionSink(t)
			recordKillAction(finding, "4242", "/tmp/.x", tc.err)

			if len(sink.records) != 1 {
				t.Fatalf("records = %d, want 1", len(sink.records))
			}
			rec := sink.records[0]
			if rec.Result != tc.result {
				t.Errorf("result = %q, want %q", rec.Result, tc.result)
			}
			if rec.Op != "respond.kill_process" {
				t.Errorf("op = %q, want respond.kill_process", rec.Op)
			}
			if rec.Target != "pid 4242" {
				t.Errorf("target = %q, want the pid", rec.Target)
			}
			if rec.FindingID != alert.FindingID(finding) {
				t.Errorf("finding_id = %q, want the audit log's ID for the same finding", rec.FindingID)
			}
			if tc.err != nil && rec.Error == "" {
				t.Error("record carries no reason for not killing the process")
			}
		})
	}
}
