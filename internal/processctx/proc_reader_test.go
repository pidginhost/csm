package processctx

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeProcRoot writes a minimal /proc/<pid> tree under a temp dir.
func fakeProcRoot(t *testing.T, pid int, status, cmdline string) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, strconv.Itoa(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	must := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	must("status", status)
	must("cmdline", cmdline)
	// exe is normally a symlink; use a regular file for read-back parity.
	must("exe", "")
	if err := os.Remove(filepath.Join(dir, "exe")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/usr/bin/ncat", filepath.Join(dir, "exe")); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestReadProcEntryHappyPath(t *testing.T) {
	root := fakeProcRoot(t, 1234,
		"Name:\tncat\nPid:\t1234\nPPid:\t1\nUid:\t1001\t1001\t1001\t1001\n",
		"ncat\x00203.0.113.10\x00587\x00",
	)
	r := NewProcReader(root, 100*time.Millisecond)
	e, err := r.Read(1234)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if e.PID != 1234 || e.PPID != 1 || e.UID != 1001 {
		t.Errorf("scalars: %+v", e)
	}
	if !e.UIDKnown || !e.ProcRead {
		t.Errorf("expected confirmed UID and proc-read marker: %+v", e)
	}
	if e.Comm != "ncat" {
		t.Errorf("Comm: want ncat, got %q", e.Comm)
	}
	if e.Exe != "/usr/bin/ncat" {
		t.Errorf("Exe: want /usr/bin/ncat, got %q", e.Exe)
	}
	if len(e.Cmdline) != 3 || e.Cmdline[0] != "ncat" || e.Cmdline[2] != "587" {
		t.Errorf("Cmdline: %+v", e.Cmdline)
	}
}

func TestReadStartedAtParsesProcStatStartTime(t *testing.T) {
	root := fakeProcRoot(t, 1234,
		"Name:\tncat\nPid:\t1234\nPPid:\t1\nUid:\t1001\t1001\t1001\t1001\n",
		"ncat\x00203.0.113.10\x00587\x00",
	)
	if err := os.WriteFile(filepath.Join(root, "stat"), []byte("btime 1700000000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	stat := "1234 (ncat worker) S 1 1 1 0 -1 4194560 0 0 0 0 1 2 3 4 20 0 1 0 12345 0 0\n"
	if err := os.WriteFile(filepath.Join(root, "1234", "stat"), []byte(stat), 0o644); err != nil {
		t.Fatal(err)
	}
	oldHZ := clockTicksPerSecondOverride
	clockTicksPerSecondOverride = 100
	t.Cleanup(func() { clockTicksPerSecondOverride = oldHZ })

	r := NewProcReader(root, 100*time.Millisecond)
	got, ok := r.ReadStartedAt(1234)
	if !ok {
		t.Fatal("ReadStartedAt failed")
	}
	want := time.Unix(1700000000, 0).Add(123*time.Second + 450*time.Millisecond)
	if !got.Equal(want) {
		t.Fatalf("StartedAt = %v, want %v", got, want)
	}
}

func TestProcStatStartTimeHandlesParenInComm(t *testing.T) {
	stat := []byte("1234 (worker) pool) S 1 1 1 0 -1 4194560 0 0 0 0 1 2 3 4 20 0 1 0 98765 0 0\n")
	got, ok := procStatStartTime(stat)
	if !ok {
		t.Fatal("procStatStartTime failed")
	}
	if got != 98765 {
		t.Fatalf("starttime = %d, want 98765", got)
	}
}

func TestReadProcEntryProcessGoneIsNotError(t *testing.T) {
	root := t.TempDir() // empty: /proc/<pid> does not exist
	r := NewProcReader(root, 100*time.Millisecond)
	_, err := r.Read(99999)
	if err != ErrProcessGone {
		t.Errorf("want ErrProcessGone, got %v", err)
	}
}

func TestReadProcEntryTruncatedCmdlineNoPanic(t *testing.T) {
	// A trailing NUL with no payload after must not panic.
	root := fakeProcRoot(t, 1, "Name:\ta\nPid:\t1\nPPid:\t0\nUid:\t0\t0\t0\t0\n", "\x00\x00\x00")
	r := NewProcReader(root, 100*time.Millisecond)
	e, err := r.Read(1)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(e.Cmdline) != 0 {
		t.Errorf("trailing-NUL only cmdline: want empty, got %+v", e.Cmdline)
	}
}

func TestReadWithDeadlineTimesOut(t *testing.T) {
	done := make(chan struct{})
	start := time.Now()
	_, ok := runBytesWithDeadline(25*time.Millisecond, func() ([]byte, error) {
		defer close(done)
		time.Sleep(100 * time.Millisecond)
		return []byte("late"), nil
	})
	elapsed := time.Since(start)
	if ok {
		t.Fatal("expected timeout")
	}
	if elapsed > 200*time.Millisecond {
		t.Errorf("deadline helper took too long; elapsed=%v", elapsed)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("deadline read goroutine did not return")
	}
	waitForProcReadSlots(t, 0)
}

func TestParseStatusUIDFromTabbedFormat(t *testing.T) {
	// /proc/<pid>/status uses tab-separated fields. Confirm we pick the
	// first (real) UID of four (real, effective, saved, fsuid).
	got := parseStatusUID("Name:\tx\nUid:\t1001\t2002\t3003\t4004\n")
	if got != 1001 {
		t.Errorf("want 1001, got %d", got)
	}
}

func TestParseStatusUIDKnownDistinguishesRootFromUnknown(t *testing.T) {
	uid, ok := parseStatusUIDKnown("Name:\tx\nUid:\t0\t0\t0\t0\n")
	if !ok || uid != 0 {
		t.Fatalf("root UID should be known zero, got uid=%d ok=%v", uid, ok)
	}
	uid, ok = parseStatusUIDKnown("Name:\tx\n")
	if ok || uid != 0 {
		t.Fatalf("missing UID should be unknown zero, got uid=%d ok=%v", uid, ok)
	}
}

func TestParseCmdlineHandlesEmbeddedNULs(t *testing.T) {
	got := parseCmdline([]byte("a\x00b\x00c\x00"))
	if len(got) != 3 || got[0] != "a" || got[2] != "c" {
		t.Errorf("got %+v", got)
	}
}

func TestParseCmdlineRedactsSensitiveArgs(t *testing.T) {
	got := parseCmdline([]byte("cmd\x00--password=secret\x00--token\x00abc123\x00--safe\x00ok\x00"))
	want := []string{"cmd", "--password=<redacted>", "--token", "<redacted>", "--safe", "ok"}
	if len(got) != len(want) {
		t.Fatalf("len: want %d, got %d (%+v)", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("arg[%d]: want %q, got %q (all=%+v)", i, want[i], got[i], got)
		}
	}
}

func TestParseCmdlineTruncatesLongArgs(t *testing.T) {
	long := strings.Repeat("x", maxCmdlineArgLen+20)
	got := parseCmdline([]byte("cmd\x00" + long + "\x00"))
	if len(got) != 2 {
		t.Fatalf("got %+v", got)
	}
	if len(got[1]) != maxCmdlineArgLen {
		t.Fatalf("arg length: want %d, got %d", maxCmdlineArgLen, len(got[1]))
	}
}
