//go:build linux

package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/checks"
)

// fakeAFAlgProc builds a procfs holding one process with the given executable
// and start time, both measured against a fixed system uptime.
func fakeAFAlgProc(t *testing.T, pid int, exe string, uptime, startAfterBoot int64) {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "uptime"),
		[]byte(fmt.Sprintf("%d.00 0.00\n", uptime)), 0o644); err != nil {
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
	fields[1] = "(worker (pool))"
	fields[2] = "S"
	fields[21] = strconv.FormatInt(startAfterBoot*100, 10)
	if err := os.WriteFile(filepath.Join(dir, "stat"),
		[]byte(joinFields(fields)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "status"),
		[]byte("Name:\tworker\nUid:\t"+currentUID()+"\t"+currentUID()+"\n"), 0o644); err != nil {
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

func eventTimestamp(ago time.Duration) string {
	return strconv.FormatFloat(float64(time.Now().Add(-ago).UnixNano())/float64(time.Second), 'f', 9, 64)
}

// The audit line can be a tick old. If the PID has since been recycled, killing
// it destroys an unrelated process -- as root, on a production host.
func TestAFAlgKillTarget_RefusesRecycledPID(t *testing.T) {
	const pid = 4242
	// Process started well after the audit event: it cannot be the offender.
	fakeAFAlgProc(t, pid, "/usr/bin/php", 1_000, 500)
	ev := checks.AFAlgEvent{
		PID:       strconv.Itoa(pid),
		Exe:       "/usr/bin/php",
		UID:       currentUID(),
		Timestamp: eventTimestamp(600 * time.Second),
	}

	if _, ok, reason := afAlgKillTarget(ev); ok {
		t.Errorf("killed a recycled pid; reason=%q", reason)
	}
}

// A different executable behind the PID is the same story.
func TestAFAlgKillTarget_RefusesDifferentExecutable(t *testing.T) {
	const pid = 4243
	fakeAFAlgProc(t, pid, "/usr/sbin/mysqld", 1_000, 100)
	ev := checks.AFAlgEvent{
		PID:       strconv.Itoa(pid),
		Exe:       "/usr/bin/php",
		UID:       currentUID(),
		Timestamp: eventTimestamp(800 * time.Second),
	}

	if _, ok, reason := afAlgKillTarget(ev); ok {
		t.Errorf("killed a process whose executable does not match; reason=%q", reason)
	}
}

// The offender itself is still killed: the guard must not disarm the reaction.
func TestAFAlgKillTarget_AllowsTheOffender(t *testing.T) {
	const pid = 4244
	fakeAFAlgProc(t, pid, "/usr/bin/php", 1_000, 100)
	ev := checks.AFAlgEvent{
		PID:       strconv.Itoa(pid),
		Exe:       "/usr/bin/php",
		UID:       currentUID(),
		Timestamp: eventTimestamp(800 * time.Second),
	}

	got, ok, reason := afAlgKillTarget(ev)
	if !ok {
		t.Fatalf("refused to kill the offending process: %s", reason)
	}
	if got != pid {
		t.Errorf("pid = %d, want %d", got, pid)
	}
}

func TestAFAlgKillTarget_AllowsDeletedOffenderExecutable(t *testing.T) {
	const pid = 4249
	fakeAFAlgProc(t, pid, "/usr/bin/php (deleted)", 1_000, 100)
	ev := checks.AFAlgEvent{
		PID:       strconv.Itoa(pid),
		Exe:       "/usr/bin/php",
		UID:       currentUID(),
		Timestamp: eventTimestamp(800 * time.Second),
	}

	got, ok, reason := afAlgKillTarget(ev)
	if !ok {
		t.Fatalf("refused the offending process after its executable was unlinked: %s", reason)
	}
	if got != pid {
		t.Fatalf("pid = %d, want %d", got, pid)
	}
}

// An event with no executable recorded cannot be verified, so it must not kill.
func TestAFAlgKillTarget_RefusesUnverifiableEvent(t *testing.T) {
	const pid = 4245
	fakeAFAlgProc(t, pid, "/usr/bin/php", 1_000, 100)
	ev := checks.AFAlgEvent{PID: strconv.Itoa(pid), Timestamp: eventTimestamp(800 * time.Second)}

	if _, ok, _ := afAlgKillTarget(ev); ok {
		t.Error("killed on an event carrying no executable to verify against")
	}
}

func TestAFAlgKillTarget_RequiresRecordedUID(t *testing.T) {
	const pid = 4246
	fakeAFAlgProc(t, pid, "/usr/bin/php", 1_000, 100)
	ev := checks.AFAlgEvent{
		PID:       strconv.Itoa(pid),
		Exe:       "/usr/bin/php",
		Timestamp: eventTimestamp(800 * time.Second),
	}

	if _, ok, _ := afAlgKillTarget(ev); ok {
		t.Fatal("killed without an event UID to verify")
	}
}

func TestAFAlgKillTarget_RejectsSubsecondRecycle(t *testing.T) {
	const pid = 4247
	fakeAFAlgProc(t, pid, "/usr/bin/php", 1_000, 1_000)
	ev := checks.AFAlgEvent{
		PID:       strconv.Itoa(pid),
		Exe:       "/usr/bin/php",
		UID:       currentUID(),
		Timestamp: eventTimestamp(500 * time.Millisecond),
	}

	if _, ok, _ := afAlgKillTarget(ev); ok {
		t.Fatal("killed a PID recycled half a second after the audit event")
	}
}

func TestAFAlgKillTarget_RejectsNonFiniteTimestamp(t *testing.T) {
	const pid = 4248
	fakeAFAlgProc(t, pid, "/usr/bin/php", 1_000, 100)
	ev := checks.AFAlgEvent{
		PID:       strconv.Itoa(pid),
		Exe:       "/usr/bin/php",
		UID:       currentUID(),
		Timestamp: "NaN",
	}

	if _, ok, _ := afAlgKillTarget(ev); ok {
		t.Fatal("killed when the event timestamp was not finite")
	}
}
