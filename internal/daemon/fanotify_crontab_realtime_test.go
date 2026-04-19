//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// withCronSpoolDir redirects cronSpoolWatchDir for a single test so
// checkCrontab's path-prefix gating accepts files under t.TempDir()
// instead of the real /var/spool/cron.
func withCronSpoolDir(t *testing.T, dir string) {
	t.Helper()
	old := cronSpoolWatchDir
	cronSpoolWatchDir = dir
	t.Cleanup(func() { cronSpoolWatchDir = old })
}

// openRawFd opens path read-only and returns a raw fd plus a cleanup
// closure. Uses unix.Open directly to avoid the os.File runtime poller
// integration: os.File.Fd documents that "the runtime poller may close
// the file descriptor at unspecified times", which under -race + coverage
// instrumentation can land between t.TempDir's RemoveAll openat() and its
// readdir() and turn the dir fd into EBADF (observed flake on CI job
// 93822). Production code paths receive fanotify event fds and call
// unix.Close explicitly; the tests now mirror that ownership.
func openRawFd(t *testing.T, path string) int {
	t.Helper()
	fd, err := unix.Open(path, unix.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("unix.Open(%s): %v", path, err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	return fd
}

// TestCheckCrontab_GsocketDefunctFires is the realtime regression for the
// 2026-03-24 production attack: a write to /var/spool/cron/<user> carrying
// the defunct-kernel template must surface a Critical suspicious_crontab
// alert without any polled scan having to run.
func TestCheckCrontab_GsocketDefunctFires(t *testing.T) {
	dir := t.TempDir()
	withCronSpoolDir(t, dir)

	target := filepath.Join(dir, "victim1")
	payload, err := os.ReadFile(filepath.Join("..", "checks", "testdata", "crontabs",
		"gsocket_defunct_kernel_01.crontab"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if writeErr := os.WriteFile(target, payload, 0600); writeErr != nil {
		t.Fatalf("stage crontab: %v", writeErr)
	}
	fd := openRawFd(t, target)

	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkCrontab(fd, target, "test")

	select {
	case got := <-ch:
		if got.Check != "suspicious_crontab" {
			t.Errorf("Check = %q, want suspicious_crontab", got.Check)
		}
		if got.Severity != alert.Critical {
			t.Errorf("Severity = %v, want Critical", got.Severity)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected suspicious_crontab alert, none arrived")
	}
}

// TestCheckCrontab_Base64WrappedFires asserts the deep matcher path is
// wired in: a crontab whose markers only appear after one base64 decode
// must still trip the realtime alert.
func TestCheckCrontab_Base64WrappedFires(t *testing.T) {
	dir := t.TempDir()
	withCronSpoolDir(t, dir)

	target := filepath.Join(dir, "victim2")
	payload, err := os.ReadFile(filepath.Join("..", "checks", "testdata", "crontabs",
		"gsocket_b64_wrapped.crontab"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if writeErr := os.WriteFile(target, payload, 0600); writeErr != nil {
		t.Fatalf("stage: %v", writeErr)
	}
	fd := openRawFd(t, target)

	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkCrontab(fd, target, "test")

	select {
	case got := <-ch:
		if got.Check != "suspicious_crontab" {
			t.Errorf("Check = %q, want suspicious_crontab", got.Check)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected suspicious_crontab alert from base64-wrapped variant, none arrived")
	}
}

// TestCheckCrontab_BenignSilent ensures a normal user crontab does not
// emit a finding. False positives here would alarm the operator on every
// legitimate `crontab -e` save.
func TestCheckCrontab_BenignSilent(t *testing.T) {
	dir := t.TempDir()
	withCronSpoolDir(t, dir)

	target := filepath.Join(dir, "alice")
	benign := []byte("# regular schedule\n*/5 * * * * /usr/bin/php /home/alice/cron.php >/dev/null\n")
	if err := os.WriteFile(target, benign, 0600); err != nil {
		t.Fatalf("stage: %v", err)
	}
	fd := openRawFd(t, target)

	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkCrontab(fd, target, "test")

	select {
	case got := <-ch:
		t.Errorf("benign crontab produced unexpected alert: %+v", got)
	case <-time.After(100 * time.Millisecond):
		// expected: no alert
	}
}

// TestCheckCrontab_RootSkipped defers root-crontab handling to the polled
// CheckCrontabs (which baseline-hashes root). Realtime would double-fire
// otherwise; worse, the polled path is the one the operator expects to
// drive root-crontab review through.
func TestCheckCrontab_RootSkipped(t *testing.T) {
	dir := t.TempDir()
	withCronSpoolDir(t, dir)

	target := filepath.Join(dir, "root")
	bad := []byte("0 * * * * /tmp/x defunct-kernel\n")
	if err := os.WriteFile(target, bad, 0600); err != nil {
		t.Fatalf("stage: %v", err)
	}
	fd := openRawFd(t, target)

	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkCrontab(fd, target, "test")

	select {
	case got := <-ch:
		t.Errorf("root crontab should be skipped by realtime path, got alert: %+v", got)
	case <-time.After(100 * time.Millisecond):
		// expected: no alert
	}
}
