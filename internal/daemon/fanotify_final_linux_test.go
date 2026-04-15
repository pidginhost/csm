//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// Tests for uncovered branches in fanotify.go not exercised by the
// existing fanotify_*_linux_test.go files.

// --- analyzeFile: PHP in /.ssh triggers php_in_sensitive_dir_realtime -----

func TestAnalyzeFilePHPInSSHDirAlerts(t *testing.T) {
	dir := t.TempDir()
	sshDir := filepath.Join(dir, ".ssh")
	if err := os.MkdirAll(sshDir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(sshDir, "evil.php")
	if err := os.WriteFile(path, []byte("<?php echo 1; ?>"), 0644); err != nil {
		t.Fatal(err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}

	fm.analyzeFile(fileEvent{path: path, fd: int(f.Fd())})

	select {
	case got := <-ch:
		if got.Check != "php_in_sensitive_dir_realtime" {
			t.Errorf("Check = %q, want php_in_sensitive_dir_realtime", got.Check)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected php_in_sensitive_dir_realtime alert")
	}
}

// --- analyzeFile: known webshell filename → webshell_realtime -------------

func TestAnalyzeFileKnownWebshellNameAlerts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c99.php")
	if err := os.WriteFile(path, []byte("<?php // c99 ?>"), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}

	fm.analyzeFile(fileEvent{path: path, fd: int(f.Fd())})

	select {
	case got := <-ch:
		if got.Check != "webshell_realtime" {
			t.Errorf("Check = %q, want webshell_realtime", got.Check)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected webshell_realtime alert")
	}
}

// --- analyzeFile: .haxor extension → webshell_realtime -------------------

func TestAnalyzeFileHaxorExtensionAlerts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "thing.haxor")
	if err := os.WriteFile(path, []byte("# backdoor"), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.analyzeFile(fileEvent{path: path, fd: int(f.Fd())})

	select {
	case got := <-ch:
		if got.Check != "webshell_realtime" {
			t.Errorf("Check = %q, want webshell_realtime", got.Check)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected webshell_realtime alert")
	}
}

// --- analyzeFile: executable in /tmp triggers executable_in_tmp_realtime --

func TestAnalyzeFileExecutableInTmpAlerts(t *testing.T) {
	// Write an executable (mode 0755) into /tmp/csm-test-... and use its real path.
	tmp, err := os.CreateTemp("/tmp", "csm-test-binary-*")
	if err != nil {
		t.Skipf("create tmp: %v", err)
	}
	path := tmp.Name()
	defer func() {
		_ = os.Remove(path)
	}()
	if _, writeErr := tmp.Write([]byte("#!/bin/sh\necho hi\n")); writeErr != nil {
		t.Fatal(writeErr)
	}
	_ = tmp.Close()
	if chmodErr := os.Chmod(path, 0755); chmodErr != nil {
		t.Fatalf("chmod: %v", chmodErr)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = f.Close() }()

	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.analyzeFile(fileEvent{path: path, fd: int(f.Fd())})

	select {
	case got := <-ch:
		if got.Check != "executable_in_tmp_realtime" {
			t.Errorf("Check = %q, want executable_in_tmp_realtime", got.Check)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected executable_in_tmp_realtime alert")
	}
}

// --- analyzeFile: non-executable in /tmp does not alert -------------------

func TestAnalyzeFileNonExecutableInTmpNoAlert(t *testing.T) {
	tmp, err := os.CreateTemp("/tmp", "csm-test-data-*")
	if err != nil {
		t.Skipf("create tmp: %v", err)
	}
	path := tmp.Name()
	defer func() { _ = os.Remove(path) }()
	_, _ = tmp.WriteString("not executable\n")
	_ = tmp.Close()
	if chmodErr := os.Chmod(path, 0644); chmodErr != nil {
		t.Fatalf("chmod: %v", chmodErr)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = f.Close() }()

	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.analyzeFile(fileEvent{path: path, fd: int(f.Fd())})

	select {
	case got := <-ch:
		t.Errorf("unexpected alert for non-exec tmp file: %+v", got)
	case <-time.After(100 * time.Millisecond):
		// OK
	}
}

// --- analyzeFile: .htaccess with php_value directive triggers injection ---

func TestAnalyzeFileHtaccessInjectionRoutes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".htaccess")
	if err := os.WriteFile(path, []byte("php_value auto_prepend_file /tmp/evil.php\n"), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.analyzeFile(fileEvent{path: path, fd: int(f.Fd())})

	select {
	case got := <-ch:
		if got.Check != "htaccess_injection_realtime" {
			t.Errorf("Check = %q, want htaccess_injection_realtime", got.Check)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected htaccess_injection_realtime alert")
	}
}

// --- analyzeFile: .user.ini with allow_url_include on alerts --------------

func TestAnalyzeFileUserINIAllowURLIncludeAlerts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".user.ini")
	if err := os.WriteFile(path, []byte("allow_url_include=on\n"), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.analyzeFile(fileEvent{path: path, fd: int(f.Fd())})

	select {
	case <-ch:
		// OK - any alert fired is the checkUserINI branch was reached
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected alert for allow_url_include=on")
	}
}

// --- analyzeFile: executable in .config takes precedence over /tmp check --

func TestAnalyzeFileExecutableInConfigAlerts(t *testing.T) {
	dir := t.TempDir()
	confDir := filepath.Join(dir, ".config")
	if err := os.MkdirAll(confDir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(confDir, "miner")
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho miner\n"), 0755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.analyzeFile(fileEvent{path: path, fd: int(f.Fd())})

	select {
	case got := <-ch:
		if got.Check != "executable_in_config_realtime" {
			t.Errorf("Check = %q, want executable_in_config_realtime", got.Check)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected executable_in_config_realtime alert")
	}
}

// --- analyzeFile: suppressed path → no alert ------------------------------

func TestAnalyzeFileSuppressedPathSkips(t *testing.T) {
	dir := t.TempDir()
	cachedDir := filepath.Join(dir, "cache")
	if err := os.MkdirAll(cachedDir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cachedDir, "c99.php") // would normally alert as known webshell
	if err := os.WriteFile(path, []byte("<?php ?>"), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	cfg := &config.Config{}
	cfg.Suppressions.IgnorePaths = []string{"*/cache/*"}

	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: cfg, alertCh: ch}
	fm.analyzeFile(fileEvent{path: path, fd: int(f.Fd())})

	select {
	case got := <-ch:
		t.Errorf("expected suppression to skip alert, got %+v", got)
	case <-time.After(100 * time.Millisecond):
		// OK
	}
}

// --- analyzeFile: PHP in wp-content/uploads (critical path) ---------------

func TestAnalyzeFilePHPInUploadsAlerts(t *testing.T) {
	dir := t.TempDir()
	uploadsDir := filepath.Join(dir, "wp-content", "uploads")
	if err := os.MkdirAll(uploadsDir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(uploadsDir, "dropper.php")
	if err := os.WriteFile(path, []byte("<?php echo 'evil'; ?>"), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.analyzeFile(fileEvent{path: path, fd: int(f.Fd())})

	select {
	case got := <-ch:
		if got.Check != "php_in_uploads_realtime" {
			t.Errorf("Check = %q, want php_in_uploads_realtime", got.Check)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected php_in_uploads_realtime alert")
	}
}

// --- analyzeFile: index.php in uploads is not alerted ---------------------

func TestAnalyzeFileIndexPhpInUploadsNoAlert(t *testing.T) {
	dir := t.TempDir()
	uploadsDir := filepath.Join(dir, "wp-content", "uploads")
	if err := os.MkdirAll(uploadsDir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(uploadsDir, "index.php")
	if err := os.WriteFile(path, []byte("<?php // Silence is golden\n"), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.analyzeFile(fileEvent{path: path, fd: int(f.Fd())})

	select {
	case got := <-ch:
		t.Errorf("expected no alert for index.php in uploads, got %+v", got)
	case <-time.After(100 * time.Millisecond):
		// OK
	}
}

// --- analyzeFile: PHP in wp-content/languages triggers sensitive dir ------

func TestAnalyzeFilePHPInLanguagesAlerts(t *testing.T) {
	dir := t.TempDir()
	langDir := filepath.Join(dir, "wp-content", "languages")
	if err := os.MkdirAll(langDir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(langDir, "injected.php")
	if err := os.WriteFile(path, []byte("<?php // evil ?>"), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.analyzeFile(fileEvent{path: path, fd: int(f.Fd())})

	select {
	case got := <-ch:
		if got.Check != "php_in_sensitive_dir_realtime" {
			t.Errorf("Check = %q, want php_in_sensitive_dir_realtime", got.Check)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected php_in_sensitive_dir_realtime alert")
	}
}

// --- analyzeFile: PHP in languages with .l10n.php suffix skipped ---------

func TestAnalyzeFileL10nInLanguagesNoAlert(t *testing.T) {
	dir := t.TempDir()
	langDir := filepath.Join(dir, "wp-content", "languages")
	if err := os.MkdirAll(langDir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(langDir, "strings-en_US.l10n.php")
	if err := os.WriteFile(path, []byte("<?php // compiled translations\n"), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.analyzeFile(fileEvent{path: path, fd: int(f.Fd())})

	select {
	case got := <-ch:
		t.Errorf("expected no alert for .l10n.php, got %+v", got)
	case <-time.After(100 * time.Millisecond):
		// OK
	}
}

// --- analyzeFile: executable in .config triggers executable_in_config ----

// --- isInteresting: paths outside watched directories are filtered --------

func TestIsInterestingUninterestingPathsRejected(t *testing.T) {
	fm := &FileMonitor{cfg: &config.Config{}}
	// Paths that should NOT trigger any isInteresting rule:
	// - not PHP/webshell ext/.htaccess/.user.ini
	// - not under /home/ (no CGI, HTML, or ZIP triggers)
	// - not in /.config/, /tmp/, /dev/shm/, /var/tmp/
	// - not a credential log filename
	// - not PHP in a sensitive dir
	uninteresting := []string{
		"/var/cache/apt/archives/something.deb",
		"/var/log/daemon.log.1",
		"/usr/share/man/man1/ls.1.gz",
		"/etc/hostname",
		"/boot/vmlinuz-6.1.0",
	}
	for _, p := range uninteresting {
		if fm.isInteresting(p) {
			t.Errorf("isInteresting(%q) = true, want false", p)
		}
	}
}

// --- handleEvent: queue full increments droppedEvents counter -------------

func TestHandleEventQueueFullDropsAndCounts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "evil.php")
	if err := os.WriteFile(path, []byte("<?php ?>"), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{
		cfg:        &config.Config{},
		alertCh:    ch,
		analyzerCh: make(chan fileEvent, 1),
	}
	// Pre-fill so the second enqueue fails.
	fm.analyzerCh <- fileEvent{path: "dummy"}

	// Dup fd so handleEvent can close it safely.
	dupFd, err := unix.Dup(int(f.Fd()))
	if err != nil {
		t.Fatal(err)
	}

	fm.handleEvent(dupFd, 0)

	if atomic.LoadInt64(&fm.droppedEvents) != 1 {
		t.Errorf("droppedEvents = %d, want 1", atomic.LoadInt64(&fm.droppedEvents))
	}
}

// --- processEvents: buffer with multiple events, some negative fds --------

func TestProcessEventsSkipsNegativeFd(t *testing.T) {
	// Build a buffer with one event carrying Fd=-1 (skip path in
	// processEvents). Since handleEvent requires a valid fd, this tests
	// only that processEvents increments the offset and doesn't panic.
	fm := &FileMonitor{
		cfg:        &config.Config{},
		alertCh:    make(chan alert.Finding, 1),
		analyzerCh: make(chan fileEvent, 1),
	}

	buf := make([]byte, metadataSize)
	meta := (*fanotifyEventMetadata)(unsafePtr(buf))
	meta.EventLen = uint32(metadataSize)
	meta.Vers = 3
	meta.Fd = -1
	meta.Pid = 0

	// Must not panic.
	fm.processEvents(buf)
}

// --- Stop: writing to pipe (already closed via pipeClosed=1) is a no-op --

func TestFileMonitorStopWithPipeClosedDoesNotBlock(t *testing.T) {
	// Build a FileMonitor with a valid fanotify fd replacement and a pipe.
	// We use plain pipe fds; stop will close() the "fanotify fd" field, but
	// we're going to set it to -1 so that close() is a no-op.
	var fds [2]int
	if err := unix.Pipe2(fds[:], unix.O_NONBLOCK|unix.O_CLOEXEC); err != nil {
		t.Skipf("pipe2: %v", err)
	}
	_ = unix.Close(fds[0])
	_ = unix.Close(fds[1])

	fm := &FileMonitor{
		fd:      -1,
		pipeFds: fds,
		stopCh:  make(chan struct{}),
	}
	atomic.StoreInt32(&fm.pipeClosed, 1) // signal: skip pipe write

	// Must not block or panic.
	done := make(chan struct{})
	go func() {
		fm.Stop()
		close(done)
	}()
	select {
	case <-done:
		// OK
	case <-time.After(time.Second):
		t.Fatal("Stop blocked when pipe is marked closed")
	}

	select {
	case <-fm.stopCh:
		// OK
	default:
		t.Error("stopCh should be closed")
	}
}

// unsafePtr is a tiny helper to get an unsafe.Pointer from the first byte
// of a slice without import gymnastics in each test.
func unsafePtr(b []byte) unsafe.Pointer { return unsafe.Pointer(&b[0]) }
