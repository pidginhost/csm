//go:build linux

package daemon

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/wpcheck"
)

const restoredPayload = "<?php /* any content CSM removed */ echo 'x';"

// writerPID stands in for the process fanotify names. It must not be the
// daemon itself, whose own writes are never a restore.
const writerPID = 4242

func stubRemovedFileAt(t *testing.T, removed map[string]checks.RemovedFile) {
	t.Helper()
	prev := removedFileAt
	removedFileAt = func(path string) (checks.RemovedFile, bool) {
		r, ok := removed[path]
		return r, ok
	}
	t.Cleanup(func() { removedFileAt = prev })
}

func removalOf(path, content string, seq uint64) checks.RemovedFile {
	sum := sha256.Sum256([]byte(content))
	return checks.RemovedFile{Path: path, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(content)), At: time.Now().Add(-time.Minute), Action: "quarantine", Seq: seq}
}

func analyzeWrite(t *testing.T, path, content string, pid int32) []alert.Finding {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	ch := make(chan alert.Finding, 16)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.analyzeFile(fileEvent{path: path, fd: openRawFd(t, path), pid: pid})
	close(ch)
	var out []alert.Finding
	for f := range ch {
		out = append(out, f)
	}
	return out
}

func restoredFindings(findings []alert.Finding) []alert.Finding {
	var out []alert.Finding
	for _, f := range findings {
		if f.Check == checks.RemovedFileRestoredCheck {
			out = append(out, f)
		}
	}
	return out
}

// A process that writes back, byte for byte, what CSM removed from the same
// path is undoing a response. That is reported on its own, whatever the
// content detectors make of the bytes.
func TestAnalyzeFileReportsRemovedContentWrittenBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "index.php")
	stubRemovedFileAt(t, map[string]checks.RemovedFile{path: removalOf(path, restoredPayload, 7)})

	got := restoredFindings(analyzeWrite(t, path, restoredPayload, writerPID))

	if len(got) != 1 {
		t.Fatalf("restore findings = %+v, want one", got)
	}
	f := got[0]
	if f.Severity != alert.Critical || f.FilePath != path || f.PID != writerPID {
		t.Fatalf("finding = %+v, want Critical for %s written by pid %d", f, path, writerPID)
	}
}

// Each removal gets its own report, so a file written back after CSM removed
// it a second time is not held back as a repeat of the first.
func TestRemovedFileRestoredIsReportedOncePerRemoval(t *testing.T) {
	path := filepath.Join(t.TempDir(), "index.php")
	stubRemovedFileAt(t, map[string]checks.RemovedFile{path: removalOf(path, restoredPayload, 7)})
	first := restoredFindings(analyzeWrite(t, path, restoredPayload, writerPID))
	stubRemovedFileAt(t, map[string]checks.RemovedFile{path: removalOf(path, restoredPayload, 8)})
	second := restoredFindings(analyzeWrite(t, path, restoredPayload, writerPID))

	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("findings = %d then %d, want one per removal", len(first), len(second))
	}
	if first[0].Key() == second[0].Key() {
		t.Fatalf("two removals share one finding identity %q", first[0].Key())
	}
}

func TestAnalyzeFileIgnoresDifferentContentAtARemovedPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "index.php")
	stubRemovedFileAt(t, map[string]checks.RemovedFile{path: removalOf(path, restoredPayload, 7)})

	// Same size, different bytes: only the digest tells them apart.
	replacement := strings.Replace(restoredPayload, "'x'", "'y'", 1)
	if len(replacement) != len(restoredPayload) || replacement == restoredPayload {
		t.Fatal("setup: replacement must differ in content only")
	}
	if got := restoredFindings(analyzeWrite(t, path, replacement, writerPID)); len(got) != 0 {
		t.Fatalf("new content reported as a restore: %+v", got)
	}
}

func TestAnalyzeFileIgnoresTheDaemonsOwnWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "index.php")
	stubRemovedFileAt(t, map[string]checks.RemovedFile{path: removalOf(path, restoredPayload, 7)})

	if got := restoredFindings(analyzeWrite(t, path, restoredPayload, int32(os.Getpid()))); len(got) != 0 {
		t.Fatalf("the daemon's own write reported as a restore: %+v", got)
	}
}

func TestRemovedFileRestoreRejectsAnObsoleteDescriptor(t *testing.T) {
	for _, replace := range []bool{false, true} {
		t.Run(map[bool]string{false: "removed", true: "replaced"}[replace], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "index.php")
			if err := os.WriteFile(path, []byte(restoredPayload), 0600); err != nil {
				t.Fatal(err)
			}
			fd := openRawFd(t, path)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if replace {
				if err := os.WriteFile(path, []byte("replacement content"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			stubRemovedFileAt(t, map[string]checks.RemovedFile{path: removalOf(path, restoredPayload, 7)})
			ch := make(chan alert.Finding, 1)
			fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
			if fm.checkRemovedFileRestored(fileEvent{path: path, fd: fd, pid: writerPID}, "") || len(ch) != 0 {
				t.Fatal("an old descriptor was reported as a new restore")
			}
		})
	}
}

func TestRemovedFileRestoreAdmitsLedgerPaths(t *testing.T) {
	for _, temporary := range []bool{false, true} {
		t.Run(map[bool]string{false: "unusual extension", true: "temporary file"}[temporary], func(t *testing.T) {
			root := t.TempDir()
			if !temporary {
				old := tempRootPrefixes
				tempRootPrefixes = nil
				t.Cleanup(func() { tempRootPrefixes = old })
			}
			path := filepath.Join(root, "payload.dat")
			if err := os.WriteFile(path, []byte(restoredPayload), 0600); err != nil {
				t.Fatal(err)
			}
			stubRemovedFileAt(t, map[string]checks.RemovedFile{path: removalOf(path, restoredPayload, 7)})
			ch := make(chan alert.Finding, 1)
			fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
			event, admit := fm.classifyEvent(path, openRawFd(t, path))
			if !admit || event.dropperOnly {
				t.Fatalf("ledger path discarded by event routing: admit=%v dropperOnly=%v", admit, event.dropperOnly)
			}
			event.pid = writerPID
			fm.analyzeFile(event)
			if len(ch) != 1 {
				t.Fatalf("restore findings = %d, want one", len(ch))
			}
			if got := <-ch; got.Check != checks.RemovedFileRestoredCheck {
				t.Fatalf("finding = %+v, want restore", got)
			}
		})
	}
}

func TestRemovedFileRestoreStillHonorsWordPressVerification(t *testing.T) {
	path := filepath.Join(t.TempDir(), "index.php")
	if err := os.WriteFile(path, []byte(restoredPayload), 0600); err != nil {
		t.Fatal(err)
	}
	stubRemovedFileAt(t, map[string]checks.RemovedFile{path: removalOf(path, restoredPayload, 7)})
	ch := make(chan alert.Finding, 1)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch, wpCache: &fakeWPVerifier{
		describe: func(string) wpcheck.Verification {
			return wpcheck.Verification{Verdict: wpcheck.VerdictVerified}
		},
	}}
	fm.analyzeFile(fileEvent{path: path, fd: openRawFd(t, path), pid: writerPID})
	if len(ch) != 0 {
		t.Fatalf("verified WordPress content generated %d findings", len(ch))
	}
}

func TestRemovedFileRestoreKeySurvivesSequenceReset(t *testing.T) {
	path := filepath.Join(t.TempDir(), "index.php")
	first := removalOf(path, restoredPayload, 1)
	second := first
	second.At = second.At.Add(time.Second)
	if removedFileRestoredFinding(path, first, "", writerPID).Key() == removedFileRestoredFinding(path, second, "", writerPID).Key() {
		t.Fatal("removals across daemon restarts share a finding key")
	}
}

func TestRemovedFileRestoreRechecksOperatorCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "index.php")
	if err := os.WriteFile(path, []byte(restoredPayload), 0600); err != nil {
		t.Fatal(err)
	}
	previous := removedFileAt
	removed := removalOf(path, restoredPayload, 1)
	calls := 0
	removedFileAt = func(string) (checks.RemovedFile, bool) {
		calls++
		return removed, calls == 1
	}
	t.Cleanup(func() { removedFileAt = previous })
	ch := make(chan alert.Finding, 1)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	if fm.checkRemovedFileRestored(fileEvent{path: path, fd: openRawFd(t, path), pid: writerPID}, "") || len(ch) != 0 {
		t.Fatal("operator cancellation during hashing still raised a restore")
	}
}

func TestRemovedFileRestoreDeduplicatesWithinOneRemoval(t *testing.T) {
	path := filepath.Join(t.TempDir(), "index.php")
	if err := os.WriteFile(path, []byte(restoredPayload), 0600); err != nil {
		t.Fatal(err)
	}
	ledger := map[string]checks.RemovedFile{path: removalOf(path, restoredPayload, 1)}
	stubRemovedFileAt(t, ledger)
	ch := make(chan alert.Finding, 3)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	event := fileEvent{path: path, fd: openRawFd(t, path), pid: writerPID}
	for i := 0; i < 2; i++ {
		fm.checkRemovedFileRestored(event, "")
	}
	if len(ch) != 1 {
		t.Fatalf("same removal generated %d findings, want one", len(ch))
	}
	removed := ledger[path]
	removed.At = removed.At.Add(time.Second)
	removed.Seq++
	ledger[path] = removed
	fm.checkRemovedFileRestored(event, "")
	if len(ch) != 2 {
		t.Fatalf("later removal generated %d total findings, want two", len(ch))
	}
}

func TestRemovedFileRestoreIgnoresUnknownPathsAndSizes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "index.php")
	for _, known := range []bool{false, true} {
		ledger := make(map[string]checks.RemovedFile)
		content := restoredPayload
		if known {
			ledger[path] = removalOf(path, restoredPayload, 1)
			content += " "
		}
		stubRemovedFileAt(t, ledger)
		if got := restoredFindings(analyzeWrite(t, path, content, writerPID)); len(got) != 0 {
			t.Fatalf("known=%v: unexpected restore findings: %+v", known, got)
		}
	}
}

// The finding names the file, which is what ties it to the hosting account.
func TestRemovedFileRestoredFindingAttributesByPath(t *testing.T) {
	path := "/home/alice/public_html/wp-content/themes/x/index.php"
	f := removedFileRestoredFinding(path, removalOf(path, restoredPayload, 1), "", writerPID)
	requireOwner(t, []alert.Finding{f}, checks.RemovedFileRestoredCheck, "")
	res := checks.CorrelateFindings([]alert.Finding{f, {Severity: alert.Critical, Check: "db_rogue_admin", TenantID: "carol"}, {Severity: alert.Critical, Check: "db_rogue_admin", TenantID: "dave"}})
	if len(res.Derived) != 1 || len(res.Unattributed) != 0 {
		t.Fatalf("path-attributed restore finding did not aggregate: %+v", res)
	}
}

// A removal of a file too large to hash leaves no digest, and a read that
// fails yields none either. Two missing digests are not a match.
func TestRemovedFileWithoutDigestIsNeverMatched(t *testing.T) {
	path := filepath.Join(t.TempDir(), "large.php")
	if err := os.WriteFile(path, []byte(restoredPayload), 0o644); err != nil {
		t.Fatal(err)
	}
	removed := removalOf(path, restoredPayload, 7)
	removed.SHA256 = ""
	stubRemovedFileAt(t, map[string]checks.RemovedFile{path: removed})
	// A descriptor that cannot be read makes hashing fail.
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}

	if fm.checkRemovedFileRestored(fileEvent{path: path, fd: fd, pid: writerPID}, "") {
		t.Fatalf("an unhashed removal matched an unreadable write: %+v", <-ch)
	}
}
