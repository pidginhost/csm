package checks

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

func restoreResponseConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := &config.Config{StatePath: t.TempDir()}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.QuarantineFiles = true
	return cfg
}

func restoreFileResponseFixture(t *testing.T, settings string) (*config.Config, string) {
	t.Helper()
	cfg, homes := fileResponseFixture(t, settings)
	if err := os.MkdirAll(homes, 0700); err != nil {
		t.Fatal(err)
	}
	// Fanotify supplies resolved paths. macOS temporary roots contain an
	// ancestor symlink that the production no-follow read must reject.
	homes = mustEvalSymlinks(t, homes)
	withAccountHomeRoots(t, homes)
	return cfg, homes
}

// themeFile returns a path where the path rule alone would clean rather than
// quarantine, so the tests show the response follows the earlier removal.
func themeFile(t *testing.T, content string) string {
	t.Helper()
	dir := filepath.Join(realTempDir(t), "public_html", "wp-content", "themes", "theme", "modules")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "index.php")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if !ShouldCleanInsteadOfQuarantine(path) {
		t.Fatalf("setup: %s is not a path the cleaner owns", path)
	}
	return path
}

func restoredFinding(path string) alert.Finding {
	r, _ := RemovedFileAt(path)
	return alert.Finding{Severity: alert.Critical, Check: RemovedFileRestoredCheck, Message: "File CSM removed was written back: " + path, FilePath: path, DedupKey: r.RestoreKey()}
}

// Bytes CSM quarantined as a whole file are quarantined again when they come
// back, even where the path rule would only try to clean them.
func TestRestoredFileIsQuarantinedAgainAfterAQuarantine(t *testing.T) {
	withActionSink(t)
	withAutoRespQuarantineDir(t, filepath.Join(t.TempDir(), "quarantine"))
	path := themeFile(t, "<?php /* whole-file shell */ echo 1;")
	snapshot := actionlog.Stat(path)
	rememberRemovedFile(path, snapshot.Digest, snapshot.Size, "quarantine")

	actions := AutoQuarantineFiles(restoreResponseConfig(t), []alert.Finding{restoredFinding(path)})

	if len(actions) != 1 || !strings.HasPrefix(actions[0].Message, "AUTO-QUARANTINE: ") {
		t.Fatalf("actions = %+v, want one quarantine", actions)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("restored file still in place: %v", err)
	}
}

func TestRestoredFileResponseRejectsStaleEvidence(t *testing.T) {
	for _, change := range []string{"different content", "different size", "operator restore", "new removal", "no removal"} {
		t.Run(change, func(t *testing.T) {
			cfg, homes := restoreFileResponseFixture(t, "")
			sink := withActionSink(t)
			const content = "previously removed content"
			path := responseFile(t, homes, "alice", "restore.php", []byte(content)).FilePath
			snapshot := actionlog.Stat(path)
			rememberRemovedFile(path, snapshot.Digest, snapshot.Size, "quarantine")
			finding := restoredFinding(path)
			want := content
			switch change {
			case "different content":
				want = strings.Replace(content, "removed", "updated", 1)
			case "different size":
				want = "replacement"
			case "operator restore":
				ForgetRemovedFile(path)
			case "new removal":
				rememberRemovedFile(path, snapshot.Digest, snapshot.Size, "clean")
			case "no removal":
				ForgetRemovedFile(path)
				finding.DedupKey = ""
			}
			if err := os.WriteFile(path, []byte(want), 0600); err != nil {
				t.Fatal(err)
			}
			if got := AutoQuarantineFiles(cfg, []alert.Finding{finding}); len(got) != 0 {
				t.Fatalf("stale restore evidence acted: %+v", got)
			}
			assertResponseFile(t, path, []byte(want))
			if len(sink.records) != 0 {
				t.Fatalf("stale evidence reached remediation: %+v", sink.records)
			}
		})
	}
}

func TestRestoredFileResponseRechecksRemovalAfterReservation(t *testing.T) {
	cfg, homes := restoreFileResponseFixture(t, "")
	withActionSink(t)
	const content = "previously removed content"
	path := responseFile(t, homes, "alice", "restore.php", []byte(content)).FilePath
	snapshot := actionlog.Stat(path)
	rememberRemovedFile(path, snapshot.Digest, snapshot.Size, "quarantine")
	finding := restoredFinding(path)
	write := writeFileResponseState
	writeFileResponseState = func(pathToState string, mode os.FileMode, data any) error {
		ForgetRemovedFile(path)
		return write(pathToState, mode, data)
	}
	t.Cleanup(func() { writeFileResponseState = write })
	if got := AutoQuarantineFiles(cfg, []alert.Finding{finding}); len(got) != 0 {
		t.Fatalf("cancelled restore evidence acted: %+v", got)
	}
	assertResponseFile(t, path, []byte(content))
}

func TestRestoredFileResponseSharesActionBudget(t *testing.T) {
	cfg, homes := restoreFileResponseFixture(t, "  max_file_actions_per_hour: 1\n")
	withActionSink(t)
	const content = "previously removed content"
	for i := 0; i < 2; i++ {
		path := responseFile(t, homes, "alice", fmt.Sprintf("restore%d.php", i), []byte(content)).FilePath
		snapshot := actionlog.Stat(path)
		rememberRemovedFile(path, snapshot.Digest, snapshot.Size, "quarantine")
		got := AutoQuarantineFiles(cfg, []alert.Finding{restoredFinding(path)})
		if i == 0 {
			if len(got) != 1 || !strings.HasPrefix(got[0].Message, "AUTO-QUARANTINE:") {
				t.Fatalf("first response = %+v", got)
			}
		} else {
			if len(got) != 1 || responsePauses(got) != 1 {
				t.Fatalf("restore bypassed action budget: %+v", got)
			}
			assertResponseFile(t, path, []byte(content))
		}
	}
}

func TestRestoredHtaccessRepeatsItsCleaner(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			cfg, homes := restoreFileResponseFixture(t, "")
			cfg.AutoResponse.CleanHtaccess = enabled
			withActionSink(t)
			oldRoots, oldBackup := fixHtaccessAllowedRoots, htaccessBackupDirRoot
			fixHtaccessAllowedRoots = []string{homes}
			htaccessBackupDirRoot = filepath.Join(t.TempDir(), "backups")
			t.Cleanup(func() { fixHtaccessAllowedRoots, htaccessBackupDirRoot = oldRoots, oldBackup })
			const content = "# keep this comment\nAddHandler cgi-script .alfa\n"
			path := responseFile(t, homes, "alice", ".htaccess", []byte(content)).FilePath
			snapshot := actionlog.Stat(path)
			rememberRemovedFile(path, snapshot.Digest, snapshot.Size, "clean")
			got := AutoQuarantineFiles(cfg, []alert.Finding{restoredFinding(path)})
			if enabled {
				if len(got) != 1 || !strings.HasPrefix(got[0].Message, "AUTO-CLEAN:") {
					t.Fatalf("restored directives were not cleaned: %+v", got)
				}
				assertResponseFile(t, path, []byte("# keep this comment\n"))
			} else {
				if len(got) != 0 {
					t.Fatalf("disabled access-file cleaning acted: %+v", got)
				}
				assertResponseFile(t, path, []byte(content))
			}
		})
	}
}

// Bytes CSM cleaned are cleaned again, even where the path rule would remove
// the whole file: the file around the injection is the customer's.
func TestRestoredFileIsCleanedAgainAfterAClean(t *testing.T) {
	withActionSink(t)
	restoreQuarantineDir(t)
	const infected = "<?php\n\x00\x0b@include(base64_decode(\"ZXZpbA==\"));\necho 'ok';\n"
	path := filepath.Join(realTempDir(t), "public_html", "index.php")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(infected), 0o644); err != nil {
		t.Fatal(err)
	}
	if ShouldCleanInsteadOfQuarantine(path) {
		t.Fatalf("setup: %s is a path the cleaner owns", path)
	}
	rememberRemovedFile(path, actionlog.Stat(path).Digest, int64(len(infected)), "clean")

	actions := AutoQuarantineFiles(restoreResponseConfig(t), []alert.Finding{restoredFinding(path)})

	if len(actions) != 1 || !strings.HasPrefix(actions[0].Message, "AUTO-CLEAN: ") {
		t.Fatalf("actions = %+v, want one clean", actions)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "<?php\necho 'ok';\n" {
		t.Fatalf("cleaner did not preserve the legitimate content: %q err=%v", got, err)
	}
}
