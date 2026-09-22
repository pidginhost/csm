//go:build linux

package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeProcExe adds the /proc/<pid>/exe symlink to an existing synthetic tree.
func writeProcExe(t *testing.T, root string, pid int32, target string) {
	t.Helper()
	link := filepath.Join(root, fmt.Sprintf("%d", pid), "exe")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

// overrideExeStat describes binaries the test cannot create, keyed by path.
func overrideExeStat(t *testing.T, owned map[string]struct {
	mode os.FileMode
	uid  uint32
}) {
	t.Helper()
	old := exeStat
	exeStat = func(path string) (os.FileMode, uint32, error) {
		if e, ok := owned[path]; ok {
			return e.mode, e.uid, nil
		}
		return 0, 0, os.ErrNotExist
	}
	t.Cleanup(func() { exeStat = old })
}

// cPanel runs its nightly maintenance as a chain of its own scripts under
// /usr/local/cpanel. None of them is a package manager, so before exe-path
// provenance the whole chain was invisible to the demotion.
func TestProcAncestryEvidenceFindsPanelTool(t *testing.T) {
	root := fakeProc(t, map[int32]struct {
		comm string
		ppid int32
	}{
		300: {comm: "tar", ppid: 290},
		290: {comm: "modsec_vendor", ppid: 280},
		280: {comm: "upcp", ppid: 1},
	})
	overrideProcRoot(t, root)
	writeProcExe(t, root, 280, "/usr/local/cpanel/scripts/upcp")
	overrideExeStat(t, map[string]struct {
		mode os.FileMode
		uid  uint32
	}{"/usr/local/cpanel/scripts/upcp": {mode: 0o755, uid: 0}})

	ev := procAncestryEvidence(300, cpanelRoots)
	if !ev.panelTool {
		t.Fatal("tar under upcp must be recognized as panel-tool ancestry")
	}
	if ev.packageManager {
		t.Fatal("no package manager in the chain")
	}
}

// A process that renamed itself after a cPanel script proves nothing. comm is
// settable by the process; only the exe it actually ran counts.
func TestProcAncestryEvidenceIgnoresSpoofedComm(t *testing.T) {
	root := fakeProc(t, map[int32]struct {
		comm string
		ppid int32
	}{
		400: {comm: "upcp", ppid: 1},
	})
	overrideProcRoot(t, root)
	writeProcExe(t, root, 400, "/home/badguy/upcp")
	overrideExeStat(t, map[string]struct {
		mode os.FileMode
		uid  uint32
	}{"/home/badguy/upcp": {mode: 0o755, uid: 1000}})

	if procAncestryEvidence(400, cpanelRoots).panelTool {
		t.Fatal("a process named upcp outside the panel root must not be trusted")
	}
}

// The package-manager arm keeps working on hosts with no panel root, and a
// chain with no exe link at all must not fault the walk.
func TestProcAncestryEvidenceStillFindsPackageManager(t *testing.T) {
	root := fakeProc(t, map[int32]struct {
		comm string
		ppid int32
	}{
		500: {comm: "cpio", ppid: 490},
		490: {comm: "dnf", ppid: 1},
	})
	overrideProcRoot(t, root)

	ev := procAncestryEvidence(500, nil)
	if !ev.packageManager {
		t.Fatal("cpio under dnf must still be recognized")
	}
	if ev.panelTool {
		t.Fatal("no panel tool in the chain")
	}
}

// A vanished process cannot prove provenance, so the walk reports nothing
// rather than assuming the chain was trusted.
func TestProcAncestryEvidenceMissingProcessProvesNothing(t *testing.T) {
	overrideProcRoot(t, t.TempDir())

	ev := procAncestryEvidence(600, cpanelRoots)
	if ev.packageManager || ev.panelTool {
		t.Fatalf("missing process yielded evidence %+v", ev)
	}
}

// cPanel's nightly maintenance stages executables under /var/tmp and there is
// no package-manager log to corroborate it. The exe under the panel root is
// the whole evidence, so it has to demote on its own.
func TestDemoteTmpExecPanelToolNeedsNoPackageWindow(t *testing.T) {
	oldW, oldA := tmpExecPkgWindow, tmpExecAncestry
	tmpExecPkgWindow = func(time.Time) bool { return false }
	tmpExecAncestry = func(int32) ancestryEvidence { return ancestryEvidence{panelTool: true} }
	t.Cleanup(func() { tmpExecPkgWindow, tmpExecAncestry = oldW, oldA })
	overridePanelToolRoots(t, cpanelRoots)

	ok, reason := demoteTmpExec(0, 4242, time.Now())
	if !ok {
		t.Fatal("panel-tool ancestry must demote without a package window")
	}
	if !strings.Contains(reason, "control panel") {
		t.Fatalf("reason = %q, want it to name control panel maintenance", reason)
	}
}

// A package-manager comm is attacker-settable, so that arm keeps needing a
// real transaction in the window. Losing this gate would let any process that
// renamed itself "rpm" demote its own drop.
func TestDemoteTmpExecPackageArmStillNeedsWindow(t *testing.T) {
	oldW, oldA := tmpExecPkgWindow, tmpExecAncestry
	tmpExecPkgWindow = func(time.Time) bool { return false }
	tmpExecAncestry = func(int32) ancestryEvidence { return ancestryEvidence{packageManager: true} }
	t.Cleanup(func() { tmpExecPkgWindow, tmpExecAncestry = oldW, oldA })

	if ok, _ := demoteTmpExec(0, 4242, time.Now()); ok {
		t.Fatal("package-manager ancestry without an active window must not demote")
	}
}
