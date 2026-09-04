//go:build linux

package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	"github.com/pidginhost/csm/internal/checks"
)

// fakeAFAlgProc builds a procfs whose boot time is fixed, holding one process with
// the given exe and start time (in seconds after boot).
func fakeAFAlgProc(t *testing.T, pid int, exe string, bootTime, startAfterBoot int64) {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "stat"),
		[]byte(fmt.Sprintf("cpu 1 2 3\nbtime %d\n", bootTime)), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, strconv.Itoa(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Field 22 is starttime in clock ticks; fields 1-21 are placeholders.
	fields := make([]string, 52)
	for i := range fields {
		fields[i] = "0"
	}
	fields[0] = strconv.Itoa(pid)
	fields[1] = "(worker)"
	fields[2] = "S"
	fields[21] = strconv.FormatInt(startAfterBoot*100, 10)
	if err := os.WriteFile(filepath.Join(dir, "stat"),
		[]byte(joinFields(fields)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(exe, filepath.Join(dir, "exe")); err != nil {
		t.Fatal(err)
	}

	old := procRootDir
	procRootDir = root
	t.Cleanup(func() { procRootDir = old })
}

func joinFields(f []string) string {
	out := ""
	for i, v := range f {
		if i > 0 {
			out += " "
		}
		out += v
	}
	return out
}

func currentUID() string { return strconv.Itoa(syscall.Getuid()) }

// The audit line can be a tick old. If the PID has since been recycled, killing
// it destroys an unrelated process -- as root, on a production host.
func TestAFAlgKillTarget_RefusesRecycledPID(t *testing.T) {
	const pid = 4242
	// Process started well after the audit event: it cannot be the offender.
	fakeAFAlgProc(t, pid, "/usr/bin/php", 1_000_000, 500)
	ev := checks.AFAlgEvent{
		PID:       strconv.Itoa(pid),
		Exe:       "/usr/bin/php",
		UID:       currentUID(),
		Timestamp: "1000400.000", // 100 seconds before the process started
	}

	if _, ok, reason := afAlgKillTarget(ev); ok {
		t.Errorf("killed a recycled pid; reason=%q", reason)
	}
}

// A different executable behind the PID is the same story.
func TestAFAlgKillTarget_RefusesDifferentExecutable(t *testing.T) {
	const pid = 4243
	fakeAFAlgProc(t, pid, "/usr/sbin/mysqld", 1_000_000, 100)
	ev := checks.AFAlgEvent{
		PID:       strconv.Itoa(pid),
		Exe:       "/usr/bin/php",
		UID:       currentUID(),
		Timestamp: "1000200.000",
	}

	if _, ok, reason := afAlgKillTarget(ev); ok {
		t.Errorf("killed a process whose executable does not match; reason=%q", reason)
	}
}

// The offender itself is still killed: the guard must not disarm the reaction.
func TestAFAlgKillTarget_AllowsTheOffender(t *testing.T) {
	const pid = 4244
	fakeAFAlgProc(t, pid, "/usr/bin/php", 1_000_000, 100)
	ev := checks.AFAlgEvent{
		PID:       strconv.Itoa(pid),
		Exe:       "/usr/bin/php",
		UID:       currentUID(),
		Timestamp: "1000200.000", // after the process started
	}

	got, ok, reason := afAlgKillTarget(ev)
	if !ok {
		t.Fatalf("refused to kill the offending process: %s", reason)
	}
	if got != pid {
		t.Errorf("pid = %d, want %d", got, pid)
	}
}

// An event with no executable recorded cannot be verified, so it must not kill.
func TestAFAlgKillTarget_RefusesUnverifiableEvent(t *testing.T) {
	const pid = 4245
	fakeAFAlgProc(t, pid, "/usr/bin/php", 1_000_000, 100)
	ev := checks.AFAlgEvent{PID: strconv.Itoa(pid), Timestamp: "1000200.000"}

	if _, ok, _ := afAlgKillTarget(ev); ok {
		t.Error("killed on an event carrying no executable to verify against")
	}
}
