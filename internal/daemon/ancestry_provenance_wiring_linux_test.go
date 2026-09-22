//go:build linux

package daemon

import (
	"os"
	"os/exec"
	"testing"

	"github.com/pidginhost/csm/internal/checks"
)

// Start a fresh process so another test cannot initialize ProcessCtx first.
func TestAncestryProvenanceWithoutBPFStartup(t *testing.T) {
	if os.Getenv("CSM_TEST_ANCESTRY_STARTUP") == "1" {
		if checks.AncestryProvenance == nil {
			t.Fatal("Linux ancestry must be wired before any optional BPF monitor starts")
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestAncestryProvenanceWithoutBPFStartup$")
	cmd.Env = append(os.Environ(), "CSM_TEST_ANCESTRY_STARTUP=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("fresh process: %v\n%s", err, out)
	}
}

// The /proc walk needs no BPF, so every Linux host must get ancestry
// provenance for sensitive-file findings. Wiring it only under the bpf build
// tag left the scheduled and fanotify paths scoring the same write
// differently on a host without BPF.
func TestWireAncestryProvenanceInstallsProcWalk(t *testing.T) {
	old := checks.AncestryProvenance
	checks.AncestryProvenance = nil
	t.Cleanup(func() { checks.AncestryProvenance = old })

	root := fakeProc(t, map[int32]struct {
		comm string
		ppid int32
	}{
		700: {comm: "tar", ppid: 690},
		690: {comm: "upcp", ppid: 1},
	})
	overrideProcRoot(t, root)
	writeProcExe(t, root, 690, "/usr/local/cpanel/scripts/upcp")
	overrideExeStat(t, map[string]struct {
		mode os.FileMode
		uid  uint32
	}{"/usr/local/cpanel/scripts/upcp": {mode: 0o755, uid: 0}})
	overridePanelToolRoots(t, cpanelRoots)

	wireAncestryProvenance()
	if checks.AncestryProvenance == nil {
		t.Fatal("AncestryProvenance not wired")
	}
	if got := checks.AncestryProvenance(700); got != panelToolAncestryReason {
		t.Fatalf("provenance = %q, want %q", got, panelToolAncestryReason)
	}
}
