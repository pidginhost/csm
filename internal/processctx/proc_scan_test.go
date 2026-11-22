package processctx

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// writeScanProc adds /proc/<pid> with an exe link, a real uid and a start
// time in clock ticks since boot.
func writeScanProc(t *testing.T, root string, pid int, exe string, uid int, startTicks int64) {
	t.Helper()
	dir := filepath.Join(root, strconv.Itoa(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	status := fmt.Sprintf("Name:\tx\nPid:\t%d\nPPid:\t1\nUid:\t%d\t%d\t%d\t%d\n", pid, uid, uid, uid, uid)
	stat := fmt.Sprintf("%d (x) S 1 %d %d 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 %d 0 0\n", pid, pid, pid, startTicks)
	for name, body := range map[string]string{"status": status, "stat": stat, "cmdline": "x\x00"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(exe, filepath.Join(dir, "exe")); err != nil {
		t.Fatal(err)
	}
}

func scanProcRoot(t *testing.T, btime int64) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "stat"), fmt.Appendf(nil, "cpu 0 0 0 0\nbtime %d\n", btime), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "self"), 0o755); err != nil {
		t.Fatal(err)
	}
	return root
}

// A server keeps the configuration it read at start, so the earliest root
// process of the server is what decides whether a configuration applies. A
// process another user started from the same binary must not count.
func TestEarliestRootStart(t *testing.T) {
	const btime = 1_800_000_000
	root := scanProcRoot(t, btime)
	writeScanProc(t, root, 100, "/usr/sbin/pure-ftpd", 0, 5000)
	// Upgraded while running: the kernel marks the old binary deleted.
	writeScanProc(t, root, 200, "/usr/sbin/pure-ftpd (deleted)", 0, 3000)
	writeScanProc(t, root, 300, "/home/user/pure-ftpd", 1001, 1000)
	writeScanProc(t, root, 400, "/usr/bin/other", 0, 10)
	writeScanProc(t, root, 500, "/usr/local/sbin/pure-ftpd-mysql", 0, 4000)

	pid, started, ok := EarliestRootStart(root, []string{"pure-ftpd", "pure-ftpd-mysql"})
	if !ok || pid != 200 {
		t.Fatalf("EarliestRootStart = %d, %v, %v; want pid 200", pid, started, ok)
	}
	if want := time.Unix(btime+30, 0); !started.Equal(want) {
		t.Fatalf("started = %v, want %v", started, want)
	}
}

func TestEarliestRootStartNone(t *testing.T) {
	root := scanProcRoot(t, 1_800_000_000)
	writeScanProc(t, root, 300, "/home/user/pure-ftpd", 1001, 1000)
	writeScanProc(t, root, 400, "/usr/bin/other", 0, 10)
	if pid, started, ok := EarliestRootStart(root, []string{"pure-ftpd"}); ok || pid != 0 || !started.IsZero() {
		t.Fatalf("EarliestRootStart = %d, %v, %v; want none", pid, started, ok)
	}
	if _, _, ok := EarliestRootStart(filepath.Join(root, "missing"), []string{"pure-ftpd"}); ok {
		t.Fatal("an unreadable proc root reported a server")
	}
}
