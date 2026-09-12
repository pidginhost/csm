package checks

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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
	if rec.RecoveryPath != qPath {
		t.Errorf("recovery path = %q, want %q", rec.RecoveryPath, qPath)
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

	if len(sink.records) != 1 {
		t.Fatalf("clean recorded %d actions, want 1", len(sink.records))
	}
	rec := sink.records[0]
	if rec.Op != "respond.clean_file" {
		t.Fatalf("op = %q, want respond.clean_file", rec.Op)
	}
	if rec.Before == nil || rec.Before.Digest != before.Digest {
		t.Errorf("before digest = %+v, want %q", rec.Before, before.Digest)
	}
	if rec.After == nil || rec.After.Digest == "" || rec.After.Digest == before.Digest {
		t.Errorf("after digest = %+v, want a different digest", rec.After)
	}
	if rec.RecoveryPath != result.BackupPath {
		t.Errorf("recovery path = %q, want %q", rec.RecoveryPath, result.BackupPath)
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
	if len(sink.records) != 1 {
		t.Fatalf("declined clean recorded %d actions, want 1", len(sink.records))
	}
	if got := sink.records[0].Result; got != actionlog.Refused {
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
			recordKillAction(&finding, "4242", "/tmp/.x", tc.err)

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

func TestQuarantineAuditCoversSetupAndCompletedWarnings(t *testing.T) {
	for _, phase := range []string{"setup", "warning", "unlink", "directory", "symlink", "vanished", "replacement"} {
		t.Run(phase, func(t *testing.T) {
			sink := withActionSink(t)
			dir := t.TempDir()
			path := filepath.Join(dir, "target")
			qPath := filepath.Join(dir, "quarantine", "target")
			switch phase {
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink("missing", path); err != nil {
					t.Fatal(err)
				}
			default:
				if err := os.WriteFile(path, []byte("evidence"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			info, statErr := os.Lstat(path)
			if statErr != nil {
				t.Fatal(statErr)
			}
			want := actionlog.Applied
			switch phase {
			case "setup":
				if err := os.WriteFile(filepath.Dir(qPath), nil, 0600); err != nil {
					t.Fatal(err)
				}
				want = actionlog.Failed
			case "warning":
				if err := os.Link(path, path+".link"); err != nil {
					t.Fatal(err)
				}
			case "unlink":
				old := quarantineUnlinkSource
				quarantineUnlinkSource = func(string) error { return syscall.EIO }
				t.Cleanup(func() { quarantineUnlinkSource = old })
				want = actionlog.Failed
			case "symlink":
				want = actionlog.Failed
			case "vanished":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				want = actionlog.Refused
			case "replacement":
				old := quarantineTargetFn
				quarantineTargetFn = func(p, q string, i os.FileInfo, data []byte) error {
					if err := os.WriteFile(p, []byte("changed!"), 0600); err != nil {
						return err
					}
					fresh, err := os.Lstat(p)
					if err != nil {
						return err
					}
					return old(p, q, fresh, data)
				}
				t.Cleanup(func() { quarantineTargetFn = old })
			}
			err := quarantineTarget(path, qPath, info, quarantineMetadata(path, info, "test"))
			if len(sink.records) != 1 {
				t.Fatalf("records=%d error=%v", len(sink.records), err)
			}
			r := sink.records[0]
			if r.Result != want {
				t.Fatalf("result=%s want=%s error=%v", r.Result, want, err)
			}
			// A surviving hard link is only detected by the Linux
			// transaction, so on other platforms the same quarantine
			// completes without a warning to carry.
			if (phase == "warning" && hardlinkWarningSupported) || phase == "unlink" {
				if r.Error == "" || !strings.Contains(r.RecoveryPath, qPath) {
					t.Fatalf("lost recovery: %+v", r)
				}
			}
			if phase == "warning" && !hardlinkWarningSupported && r.Error != "" {
				t.Fatalf("unexpected warning on a platform without hard-link detection: %+v", r)
			}
			if phase == "replacement" {
				if got := actionlog.Stat(qPath).Digest; r.Before.Digest != got {
					t.Fatalf("digest=%s archived=%s", r.Before.Digest, got)
				}
			}
		})
	}
}

func TestAccessCleanActionsAndWriteFailures(t *testing.T) {
	for _, kind := range []string{"php", "htaccess", "legacy-htaccess"} {
		for _, phase := range []string{"success", "backup", "sync"} {
			t.Run(kind+"/"+phase, func(t *testing.T) {
				sink := withActionSink(t)
				restoreQuarantineDir(t)
				withHtaccessBackupRoot(t)
				root := mustEvalSymlinks(t, t.TempDir())
				oldRoots := fixHtaccessAllowedRoots
				fixHtaccessAllowedRoots = []string{root}
				t.Cleanup(func() { fixHtaccessAllowedRoots = oldRoots })
				name, content := ".htaccess", "# keep\nAddHandler cgi-script .alfa\n"
				if kind == "php" {
					name, content = "index.php", "<?php\n@include('/tmp/evil.php');\necho 'safe';\n"
				}
				path := filepath.Join(root, name)
				if err := os.WriteFile(path, []byte(content), 0600); err != nil {
					t.Fatal(err)
				}
				if phase == "backup" {
					old := storeQuarantineBackup
					storeQuarantineBackup = func(string, []byte, QuarantineMeta, os.FileMode) error { return syscall.EIO }
					t.Cleanup(func() { storeQuarantineBackup = old })
				}
				if phase == "sync" {
					old := syncCleanParent
					syncCleanParent = func(int) error { return syscall.EIO }
					t.Cleanup(func() { syncCleanParent = old })
				}
				switch kind {
				case "php":
					CleanInfectedFile(path)
				case "htaccess":
					CleanHtaccessFile(path)
				default:
					fixHtaccess(path, "")
				}
				if len(sink.records) != 1 {
					t.Fatalf("records=%d want 1", len(sink.records))
				}
				r := sink.records[0]
				want := actionlog.Applied
				if phase == "backup" {
					want = actionlog.Failed
				}
				if r.Op != "respond.clean_file" || r.Result != want {
					t.Fatalf("record=%+v want=%s", r, want)
				}
				if phase != "success" && r.Error == "" {
					t.Fatal("failure omitted")
				}
				if phase != "backup" && (r.RecoveryPath == "" || r.Before.Digest == "" || r.After.Digest == "" || r.Before.Digest == r.After.Digest) {
					t.Fatalf("missing recovery or exact changed content: %+v", r)
				}
				if r.Before.Digest != fmt.Sprintf("%x", sha256.Sum256([]byte(content))) {
					t.Fatalf("before digest does not describe the original bytes: %+v", r.Before)
				}
				if phase != "backup" {
					written, err := os.ReadFile(path)
					if err != nil || r.After.Digest != fmt.Sprintf("%x", sha256.Sum256(written)) {
						t.Fatalf("after digest does not describe installed bytes: state=%+v error=%v", r.After, err)
					}
					backup, err := os.ReadFile(r.RecoveryPath)
					if err != nil || string(backup) != content {
						t.Fatalf("recovery does not preserve the original bytes: error=%v", err)
					}
				}
			})
		}
	}
}

func TestFileActionDoesNotOfferStateArchiveRestore(t *testing.T) {
	sink := withActionSink(t)
	restoreQuarantineDir(t)
	path := filepath.Join(t.TempDir(), "index.php")
	if err := os.WriteFile(path, []byte("<?php\n@include('/tmp/evil.php');\necho 'safe';\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if result := CleanInfectedFile(path); !result.Cleaned {
		t.Fatalf("clean=%+v", result)
	}
	if len(sink.records) != 1 || sink.records[0].Undo != "" {
		t.Fatalf("raw quarantine file is not a csm restore archive: %+v", sink.records)
	}
}

func TestQuarantineCollisionDoesNotClaimOldEvidence(t *testing.T) {
	sink := withActionSink(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "source")
	qPath := filepath.Join(dir, "old-copy")
	for name, body := range map[string]string{path: "new evidence", qPath: "old evidence", qPath + ".meta": "{}"} {
		if err := os.WriteFile(name, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := quarantineTarget(path, qPath, info, quarantineMetadata(path, info, "test")); err == nil {
		t.Fatal("collision accepted")
	}
	if len(sink.records) != 1 || sink.records[0].RecoveryPath != "" || sink.records[0].Before.Digest != "" {
		t.Fatalf("claimed unrelated evidence: %+v", sink.records)
	}
}
