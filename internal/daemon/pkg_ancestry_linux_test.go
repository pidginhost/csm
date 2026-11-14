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

	if !procAncestryEvidence(100, nil).packageManager {
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

	if !procAncestryEvidence(200, nil).packageManager {
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

	if procAncestryEvidence(100, nil).packageManager {
		t.Fatal("cpio under plain bash must NOT be demote-eligible")
	}
}

func TestProcAncestryMissingProcess(t *testing.T) {
	overrideProcRoot(t, t.TempDir())

	if procAncestryEvidence(424242, nil).packageManager {
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

	if procAncestryEvidence(100, nil).packageManager {
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

	if procAncestryEvidence(100, nil).packageManager {
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

	if procAncestryEvidence(100, nil).packageManager {
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

	if procAncestryEvidence(top, nil).packageManager {
		t.Fatal("package manager beyond depth cap must not qualify")
	}
}

func TestAncestryEvidencePrefersCachedProbe(t *testing.T) {
	// Cached probe says yes -> no /proc walk needed (procRootDir is empty).
	overrideProcRoot(t, t.TempDir())
	oldProbe := cachedAncestryEvidence
	cachedAncestryEvidence = func(pid uint32, _ []string) ancestryEvidence {
		return ancestryEvidence{packageManager: pid == 555}
	}
	t.Cleanup(func() { cachedAncestryEvidence = oldProbe })

	if !ancestryEvidenceFor(555).packageManager {
		t.Fatal("cached probe hit must qualify")
	}
	if !ancestryEvidenceFor(556).none() {
		t.Fatal("probe miss with empty /proc must not qualify")
	}
}

func TestAncestryEvidenceFallsBackToProcWalk(t *testing.T) {
	oldProbe := cachedAncestryEvidence
	cachedAncestryEvidence = nil
	t.Cleanup(func() { cachedAncestryEvidence = oldProbe })

	root := fakeProc(t, map[int32]struct {
		comm string
		ppid int32
	}{
		300: {comm: "cpio", ppid: 80},
		80:  {comm: "dnf", ppid: 1},
	})
	overrideProcRoot(t, root)

	if !ancestryEvidenceFor(300).packageManager {
		t.Fatal("nil cached probe must fall back to /proc walk")
	}
}

func TestDemoteTmpExecGates(t *testing.T) {
	now := time.Now()
	override := func(t *testing.T, window, ancestry bool) {
		t.Helper()
		oldW, oldA := tmpExecPkgWindow, tmpExecAncestry
		tmpExecPkgWindow = func(time.Time) bool { return window }
		tmpExecAncestry = func(int32) ancestryEvidence { return ancestryEvidence{packageManager: ancestry} }
		t.Cleanup(func() { tmpExecPkgWindow, tmpExecAncestry = oldW, oldA })
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

	oldW, oldA := tmpExecPkgWindow, tmpExecAncestry
	tmpExecPkgWindow = func(time.Time) bool { return true }
	tmpExecAncestry = func(int32) ancestryEvidence { return ancestryEvidence{packageManager: true} }
	t.Cleanup(func() { tmpExecPkgWindow, tmpExecAncestry = oldW, oldA })

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

// A root-owned executable written under a temp root is reported whatever its
// directory is called. A directory name proves nothing about who wrote the
// file, so only the provenance check may rescore it.
func TestAnalyzeFileTmpExecRootOwnedWorkDirIsReported(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: the file under test must be root-owned")
	}
	for _, tc := range []struct {
		name     string
		dir      string
		demote   bool
		severity alert.Severity
	}{
		{"panel work directory", "cpanel.TMP.work.", false, alert.Critical},
		{"panel staging directory", "cPanel-", false, alert.Critical},
		{"initramfs build directory", "dracut.", false, alert.Critical},
		{"initramfs build with package provenance", "dracut.", true, alert.Warning},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, err := os.MkdirTemp("/tmp", tc.dir)
			if err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(dir) })
			path := filepath.Join(dir, "tool")
			if err := os.WriteFile(path, []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
				t.Fatalf("write: %v", err)
			}
			fd := openRawFd(t, path)

			oldDemote := tmpExecDemote
			tmpExecDemote = func(uint32, int32, time.Time) (bool, string) {
				return tc.demote, "package manager ancestry during active package window"
			}
			t.Cleanup(func() { tmpExecDemote = oldDemote })

			ch := make(chan alert.Finding, 4)
			fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
			fm.analyzeFile(fileEvent{path: path, fd: fd, pid: 4242})

			select {
			case got := <-ch:
				if got.Check != "executable_in_tmp_realtime" {
					t.Errorf("Check = %q, want executable_in_tmp_realtime", got.Check)
				}
				if got.Severity != tc.severity {
					t.Errorf("Severity = %v, want %v", got.Severity, tc.severity)
				}
				if got.FilePath != path {
					t.Errorf("FilePath = %q, want %q", got.FilePath, path)
				}
				if demoted := strings.Contains(got.Details, "[demoted:"); demoted != tc.demote {
					t.Errorf("Details = %q, demotion annotation = %v, want %v", got.Details, demoted, tc.demote)
				}
			case <-time.After(200 * time.Millisecond):
				t.Fatal("root-owned executable in a temp work directory raised no finding")
			}
		})
	}
}

// writeProcStatus replaces one fake process's status file so a test can state
// the credentials the walker reads.
func writeProcStatus(t *testing.T, root string, pid, ppid int32, uidLine string) {
	t.Helper()
	status := fmt.Sprintf("Name:\tx\nPid:\t%d\nPPid:\t%d\n%s", pid, ppid, uidLine)
	if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("%d", pid), "status"), []byte(status), 0o644); err != nil {
		t.Fatal(err)
	}
}

// An initramfs builder is named only by its comm, which any process can set.
// The name counts only on a process whose real and effective user is root.
func TestProcAncestryInitramfsBuilderNeedsRoot(t *testing.T) {
	cases := []struct {
		name    string
		comm    string
		uidLine string
		want    bool
	}{
		{"dracut_as_root", "dracut", "Uid:\t0\t0\t0\t0\n", true},
		{"mkinitramfs_as_root", "mkinitramfs", "Uid:\t0\t0\t0\t0\n", true},
		{"dracut_as_user", "dracut", "Uid:\t1000\t1000\t1000\t1000\n", false},
		{"setuid_helper_named_dracut", "dracut", "Uid:\t1000\t0\t0\t0\n", false},
		{"dropped_privileges", "dracut", "Uid:\t0\t1000\t1000\t1000\n", false},
		{"no_uid_line", "dracut", "", false},
		{"malformed_uid_line", "dracut", "Uid:\troot\troot\n", false},
		{"other_root_process", "bash", "Uid:\t0\t0\t0\t0\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := fakeProc(t, map[int32]struct {
				comm string
				ppid int32
			}{
				300: {"cp", 200},
				200: {tc.comm, 1},
			})
			writeProcStatus(t, root, 200, 1, tc.uidLine)
			overrideProcRoot(t, root)
			if got := procAncestryEvidence(300, nil).initramfsBuilder; got != tc.want {
				t.Fatalf("initramfsBuilder = %v, want %v", got, tc.want)
			}
		})
	}
}

// The initramfs arm stands without a package window or a panel, but never for
// a file a non-root user owns.
func TestDemoteTmpExecInitramfsArm(t *testing.T) {
	oldW, oldA := tmpExecPkgWindow, tmpExecAncestry
	tmpExecPkgWindow = func(time.Time) bool { return false }
	tmpExecAncestry = func(int32) ancestryEvidence { return ancestryEvidence{initramfsBuilder: true} }
	t.Cleanup(func() { tmpExecPkgWindow, tmpExecAncestry = oldW, oldA })

	ok, reason := demoteTmpExec(0, 42, time.Now())
	if !ok || !strings.Contains(reason, "initramfs") {
		t.Fatalf("root file from an initramfs build = (%v, %q), want demotion naming it", ok, reason)
	}
	if ok, _ := demoteTmpExec(1000, 42, time.Now()); ok {
		t.Fatal("a non-root file must never demote")
	}
}
