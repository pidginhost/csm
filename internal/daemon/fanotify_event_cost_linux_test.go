//go:build linux

package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"golang.org/x/sys/unix"
)

// What a filesystem-scoped mark costs per event decides where the real-time
// monitor's CPU goes on a host whose watch roots share one filesystem: the
// daemon then receives every close-write on the machine and discards most of
// them. Measure the two paths through the reader -- an event the path filter
// discards, and one it admits -- so the cost of a wide scope can be stated in
// events per second rather than guessed at.
//
// Run with:
//
//	scripts/go-linux.sh go test ./internal/daemon -run XXX -bench 'BenchmarkFanotifyEvent' -benchtime 2000x

// eventCostDir returns a scratch directory outside /tmp, /var/tmp and
// /dev/shm, because the path filter admits everything written in those trees
// and a discarded-event measurement taken there would measure the admit path.
// It also has to sit on a local filesystem: the repository is mounted through
// virtiofs in the test container, where closing a descriptor costs a guest-host
// round trip and swamps everything this measures.
func eventCostDir(tb testing.TB) string {
	tb.Helper()
	dir, err := os.MkdirTemp("/run", "eventcost-")
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = os.RemoveAll(dir) })
	abs, err := filepath.Abs(dir)
	if err != nil {
		tb.Fatal(err)
	}
	return abs
}

func eventCostMonitor(tb testing.TB) *FileMonitor {
	tb.Helper()
	fm := &FileMonitor{
		fd: -1, pipeFds: [2]int{-1, -1},
		cfg: &config.Config{}, stopCh: make(chan struct{}),
		analyzerCh:          make(chan fileEvent, analyzerChBufferSize),
		accountRootPatterns: []string{"/home/*"},
	}
	fm.initQueueHealth()
	return fm
}

// benchmarkReaderPath drives the real reader entry point over pre-opened
// descriptors, which is what the kernel hands it for every close-write.
func benchmarkReaderPath(b *testing.B, name string) {
	fm := eventCostMonitor(b)
	dir := eventCostDir(b)
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("<?php return true;"), 0o600); err != nil {
		b.Fatal(err)
	}

	fds := make([]int, b.N)
	for i := range fds {
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			b.Fatalf("open: %v (raise the descriptor limit or lower -benchtime)", err)
		}
		fds[i] = fd
	}
	// Drain admitted events so a full queue does not turn the measurement
	// into the drop path.
	admitted := 0
	done := make(chan struct{})
	go func() {
		defer close(done)
		for event := range fm.analyzerCh {
			admitted++
			_ = unix.Close(event.fd)
		}
	}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fm.handleEvent(fds[i], 0, FAN_CLOSE_WRITE)
	}
	b.StopTimer()

	close(fm.analyzerCh)
	<-done
	b.ReportMetric(float64(admitted)/float64(b.N), "admitted/op")
}

// BenchmarkFanotifyEventDiscarded measures an event for a file no detector
// wants: the cost a wide watch scope adds for every unrelated write on the
// machine.
func BenchmarkFanotifyEventDiscarded(b *testing.B) {
	benchmarkReaderPath(b, "payload.dat")
}

// BenchmarkFanotifyEventAdmitted measures an event that reaches the analyzer
// queue, without the analysis itself.
func BenchmarkFanotifyEventAdmitted(b *testing.B) {
	benchmarkReaderPath(b, "payload.php")
}

// BenchmarkPathFilter isolates the string-only filter from the descriptor work
// around it, so the readlink and the filter can be told apart.
func BenchmarkPathFilter(b *testing.B) {
	fm := eventCostMonitor(b)
	paths := []string{
		"/var/lib/mysql/db/table.ibd",
		"/var/log/nginx/access.log",
		"/home/account/public_html/wp-config.php",
		"/usr/share/doc/package/README",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fm.isInteresting(paths[i%len(paths)])
	}
}

// BenchmarkProcFDReadlink isolates the per-event path resolution, the one
// syscall the reader cannot avoid while events carry descriptors.
func BenchmarkProcFDReadlink(b *testing.B) {
	dir := eventCostDir(b)
	path := filepath.Join(dir, "payload.dat")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		b.Fatal(err)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	procPath := fmt.Sprintf("/proc/self/fd/%d", fd)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := os.Readlink(procPath); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkCloseEventFD isolates the descriptor close every event ends with,
// so the filesystem the scratch directory lives on cannot be mistaken for the
// cost of the reader path itself.
func BenchmarkCloseEventFD(b *testing.B) {
	dir := eventCostDir(b)
	path := filepath.Join(dir, "payload.dat")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		b.Fatal(err)
	}
	fds := make([]int, b.N)
	for i := range fds {
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			b.Fatalf("open: %v", err)
		}
		fds[i] = fd
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = unix.Close(fds[i])
	}
}

// BenchmarkAnalyzeAdmittedPHP measures what an admitted event costs once the
// analyzer looks at it, which is the other half of the picture: the reader
// decides how many events reach this, and this decides what they cost.
func BenchmarkAnalyzeAdmittedPHP(b *testing.B) {
	dir := eventCostDir(b)
	docroot := filepath.Join(dir, "account", "public_html")
	if err := os.MkdirAll(docroot, 0o755); err != nil {
		b.Fatal(err)
	}
	path := filepath.Join(docroot, "index.php")
	body := []byte("<?php\n$config = require __DIR__ . '/config.php';\necho render($config);\n")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		b.Fatal(err)
	}
	fm := eventCostMonitor(b)
	fm.accountRootPatterns = []string{filepath.Join(dir, "*")}
	fm.docRootPatterns = []string{docroot}

	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	event := fileEvent{path: path, fd: fd}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fm.analyzeFile(event)
	}
}

// BenchmarkFanotifyEventTempRoot measures a write in the shared temporary
// trees that carries no signal -- a PHP session file, a package work file, a
// database temporary. These are the bulk of what those trees produce, and the
// reader decides them from the descriptor it already holds.
func BenchmarkFanotifyEventTempRoot(b *testing.B) {
	fm := eventCostMonitor(b)
	dir, err := os.MkdirTemp("/tmp", "eventcost-temp-")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "sess_a1b2c3d4e5")
	if err := os.WriteFile(path, []byte("session|a:0:{}"), 0o600); err != nil {
		b.Fatal(err)
	}

	fds := make([]int, b.N)
	for i := range fds {
		fd, openErr := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if openErr != nil {
			b.Fatalf("open: %v", openErr)
		}
		fds[i] = fd
	}
	admitted := 0
	done := make(chan struct{})
	go func() {
		defer close(done)
		for event := range fm.analyzerCh {
			admitted++
			_ = unix.Close(event.fd)
		}
	}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fm.handleEvent(fds[i], 0, FAN_CLOSE_WRITE)
	}
	b.StopTimer()

	close(fm.analyzerCh)
	<-done
	b.ReportMetric(float64(admitted)/float64(b.N), "admitted/op")
}
