//go:build linux

package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
)

// fakeProc builds a synthetic /proc tree in a temp dir. Each entry maps a
// pid to its comm and ppid. Returns the root to assign to procRootDir.
func fakeProc(t *testing.T, procs map[int32]struct {
	comm string
	ppid int32
}) string {
	t.Helper()
	root := t.TempDir()
	for pid, p := range procs {
		dir := filepath.Join(root, fmt.Sprintf("%d", pid))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "comm"), []byte(p.comm+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		status := fmt.Sprintf("Name:\t%s\nPid:\t%d\nPPid:\t%d\n", p.comm, pid, p.ppid)
		if err := os.WriteFile(filepath.Join(dir, "status"), []byte(status), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func overrideProcRoot(t *testing.T, root string) {
	t.Helper()
	old := procRootDir
	procRootDir = root
	t.Cleanup(func() { procRootDir = old })
}

func TestProcAncestryFindsPackageManager(t *testing.T) {
	// Real-world chain from the kmod-lve incident: cpio <- weak-modules <- dnf.
	root := fakeProc(t, map[int32]struct {
		comm string
		ppid int32
	}{
		100: {comm: "cpio", ppid: 90},
		90:  {comm: "weak-modules", ppid: 80},
		80:  {comm: "dnf", ppid: 1},
	})
	overrideProcRoot(t, root)

	if !procAncestryIsPackageManager(100) {
		t.Fatal("cpio under dnf must be recognized as package-manager ancestry")
	}
}

func TestProcAncestryWriterIsPackageManagerItself(t *testing.T) {
	root := fakeProc(t, map[int32]struct {
		comm string
		ppid int32
	}{
		200: {comm: "rpm", ppid: 1},
	})
	overrideProcRoot(t, root)

	if !procAncestryIsPackageManager(200) {
		t.Fatal("rpm writing directly must be recognized")
	}
}

func TestProcAncestryNoPackageManager(t *testing.T) {
	root := fakeProc(t, map[int32]struct {
		comm string
		ppid int32
	}{
		100: {comm: "cpio", ppid: 90},
		90:  {comm: "bash", ppid: 1},
	})
	overrideProcRoot(t, root)

	if procAncestryIsPackageManager(100) {
		t.Fatal("cpio under plain bash must NOT be demote-eligible")
	}
}

func TestProcAncestryMissingProcess(t *testing.T) {
	overrideProcRoot(t, t.TempDir())

	if procAncestryIsPackageManager(424242) {
		t.Fatal("missing /proc entry must fail closed (no demotion)")
	}
}

func TestProcAncestryMissingStatusFailsClosed(t *testing.T) {
	root := fakeProc(t, map[int32]struct {
		comm string
		ppid int32
	}{
		100: {comm: "cpio", ppid: 80},
		80:  {comm: "dnf", ppid: 1},
	})
	overrideProcRoot(t, root)
	if err := os.Remove(filepath.Join(root, "100", "status")); err != nil {
		t.Fatal(err)
	}

	if procAncestryIsPackageManager(100) {
		t.Fatal("missing status must fail closed before reaching package-manager parent")
	}
}

func TestProcAncestryMalformedPPidFailsClosed(t *testing.T) {
	root := fakeProc(t, map[int32]struct {
		comm string
		ppid int32
	}{
		100: {comm: "cpio", ppid: 80},
		80:  {comm: "dnf", ppid: 1},
	})
	overrideProcRoot(t, root)
	statusPath := filepath.Join(root, "100", "status")
	if err := os.WriteFile(statusPath, []byte("Name:\tcpio\nPid:\t100\nPPid:\tnot-a-pid\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if procAncestryIsPackageManager(100) {
		t.Fatal("malformed PPid must fail closed before reaching package-manager parent")
	}
}

func TestProcAncestryMissingPPidFailsClosed(t *testing.T) {
	root := fakeProc(t, map[int32]struct {
		comm string
		ppid int32
	}{
		100: {comm: "cpio", ppid: 80},
		80:  {comm: "dnf", ppid: 1},
	})
	overrideProcRoot(t, root)
	statusPath := filepath.Join(root, "100", "status")
	if err := os.WriteFile(statusPath, []byte("Name:\tcpio\nPid:\t100\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if procAncestryIsPackageManager(100) {
		t.Fatal("missing PPid must fail closed without looping or demoting")
	}
}

func TestProcAncestryDepthCap(t *testing.T) {
	// dnf sits deeper than maxAncestryDepth; the walk must give up before
	// reaching it rather than scanning unbounded chains.
	procs := map[int32]struct {
		comm string
		ppid int32
	}{}
	const top = int32(100)
	deep := top + int32(maxAncestryDepth) + 3
	for pid := top; pid < deep; pid++ {
		procs[pid] = struct {
			comm string
			ppid int32
		}{comm: "bash", ppid: pid + 1}
	}
	procs[deep] = struct {
		comm string
		ppid int32
	}{comm: "dnf", ppid: 1}
	root := fakeProc(t, procs)
	overrideProcRoot(t, root)

	if procAncestryIsPackageManager(top) {
		t.Fatal("package manager beyond depth cap must not qualify")
	}
}

func TestPkgManagerAncestryPrefersBPFProbe(t *testing.T) {
	// BPF probe says yes -> no /proc walk needed (procRootDir is empty).
	overrideProcRoot(t, t.TempDir())
	oldProbe := checks.AncestryProbe
	checks.AncestryProbe = func(pid uint32) bool { return pid == 555 }
	t.Cleanup(func() { checks.AncestryProbe = oldProbe })

	if !pkgManagerAncestry(555) {
		t.Fatal("BPF probe hit must qualify")
	}
	if pkgManagerAncestry(556) {
		t.Fatal("probe miss with empty /proc must not qualify")
	}
}

func TestPkgManagerAncestryFallsBackToProcWalk(t *testing.T) {
	oldProbe := checks.AncestryProbe
	checks.AncestryProbe = nil
	t.Cleanup(func() { checks.AncestryProbe = oldProbe })

	root := fakeProc(t, map[int32]struct {
		comm string
		ppid int32
	}{
		300: {comm: "cpio", ppid: 80},
		80:  {comm: "dnf", ppid: 1},
	})
	overrideProcRoot(t, root)

	if !pkgManagerAncestry(300) {
		t.Fatal("nil BPF probe must fall back to /proc walk")
	}
}

func TestDemoteTmpExecGates(t *testing.T) {
	now := time.Now()
	override := func(t *testing.T, window, ancestry bool) {
		t.Helper()
		oldW, oldA := tmpExecPkgWindow, tmpExecPkgAncestry
		tmpExecPkgWindow = func(time.Time) bool { return window }
		tmpExecPkgAncestry = func(int32) bool { return ancestry }
		t.Cleanup(func() { tmpExecPkgWindow, tmpExecPkgAncestry = oldW, oldA })
	}

	t.Run("non_root_file_never_demotes", func(t *testing.T) {
		override(t, true, true)
		if ok, _ := demoteTmpExec(1000, 42, now); ok {
			t.Fatal("uid != 0 must never demote: non-root attackers cannot qualify")
		}
	})
	t.Run("unknown_pid_never_demotes", func(t *testing.T) {
		override(t, true, true)
		if ok, _ := demoteTmpExec(0, 0, now); ok {
			t.Fatal("pid 0 (no process attribution) must never demote")
		}
	})
	t.Run("no_pkg_window_never_demotes", func(t *testing.T) {
		override(t, false, true)
		if ok, _ := demoteTmpExec(0, 42, now); ok {
			t.Fatal("ancestry alone without active package window must not demote")
		}
	})
	t.Run("no_ancestry_never_demotes", func(t *testing.T) {
		override(t, true, false)
		if ok, _ := demoteTmpExec(0, 42, now); ok {
			t.Fatal("package window alone without ancestry must not demote")
		}
	})
	t.Run("all_gates_pass_demotes_with_reason", func(t *testing.T) {
		override(t, true, true)
		ok, reason := demoteTmpExec(0, 42, now)
		if !ok {
			t.Fatal("root file + window + ancestry must demote")
		}
		if reason == "" {
			t.Fatal("demotion must carry a reason for the alert annotation")
		}
	})
}

// --- analyzeFile wiring: demoted /tmp executable emits Warning, annotated ---

func TestAnalyzeFileTmpExecDemotedToWarning(t *testing.T) {
	tmp, err := os.CreateTemp("/tmp", "csm-test-demote-*")
	if err != nil {
		t.Skipf("create tmp: %v", err)
	}
	path := tmp.Name()
	defer func() { _ = os.Remove(path) }()
	if _, writeErr := tmp.Write([]byte("#!/bin/sh\necho hi\n")); writeErr != nil {
		t.Fatal(writeErr)
	}
	_ = tmp.Close()
	if chmodErr := os.Chmod(path, 0o755); chmodErr != nil {
		t.Fatalf("chmod: %v", chmodErr)
	}
	fd := openRawFd(t, path)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		t.Fatalf("fstat: %v", err)
	}
	wantPID := int32(4242)

	oldDemote := tmpExecDemote
	tmpExecDemote = func(uid uint32, pid int32, now time.Time) (bool, string) {
		if uid != st.Uid || pid != wantPID {
			return false, ""
		}
		return true, "package manager ancestry during active package window"
	}
	t.Cleanup(func() { tmpExecDemote = oldDemote })

	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.analyzeFile(fileEvent{path: path, fd: fd, pid: wantPID})

	select {
	case got := <-ch:
		if got.Check != "executable_in_tmp_realtime" {
			t.Errorf("Check = %q, want executable_in_tmp_realtime", got.Check)
		}
		if got.Severity != alert.Warning {
			t.Errorf("Severity = %v, want Warning (demoted)", got.Severity)
		}
		if !strings.Contains(got.Details, "[demoted:") {
			t.Errorf("Details = %q, want demotion annotation", got.Details)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("demotion must rescore the finding, never suppress it")
	}
}

// Default decision path: a non-root-owned file stays Critical even when
// window and ancestry are forced true, proving the uid gate end to end.
func TestAnalyzeFileTmpExecNonRootStaysCritical(t *testing.T) {
	tmp, err := os.CreateTemp("/tmp", "csm-test-uidgate-*")
	if err != nil {
		t.Skipf("create tmp: %v", err)
	}
	path := tmp.Name()
	defer func() { _ = os.Remove(path) }()
	if _, writeErr := tmp.Write([]byte("#!/bin/sh\necho hi\n")); writeErr != nil {
		t.Fatal(writeErr)
	}
	_ = tmp.Close()
	if chmodErr := os.Chmod(path, 0o755); chmodErr != nil {
		t.Fatalf("chmod: %v", chmodErr)
	}
	if os.Getuid() == 0 {
		// Running as root (CI containers): hand the file to nobody so the
		// uid gate is actually exercised.
		if chownErr := os.Chown(path, 65534, 65534); chownErr != nil {
			t.Fatalf("chown: %v", chownErr)
		}
	}
	fd := openRawFd(t, path)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		t.Fatalf("fstat: %v", err)
	}
	if st.Uid == 0 {
		t.Fatal("test setup must use a non-root-owned file to exercise the uid gate")
	}

	oldW, oldA := tmpExecPkgWindow, tmpExecPkgAncestry
	tmpExecPkgWindow = func(time.Time) bool { return true }
	tmpExecPkgAncestry = func(int32) bool { return true }
	t.Cleanup(func() { tmpExecPkgWindow, tmpExecPkgAncestry = oldW, oldA })

	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.analyzeFile(fileEvent{path: path, fd: fd, pid: 4242})

	select {
	case got := <-ch:
		if got.Severity != alert.Critical {
			t.Errorf("Severity = %v, want Critical: non-root /tmp executables never demote", got.Severity)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected executable_in_tmp_realtime alert")
	}
}
