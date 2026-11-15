//go:build linux && kernelintegration

package daemon

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"golang.org/x/sys/unix"
)

// These temp work directory tests bind-mount directories, which the ordinary
// test jobs are not allowed to do.

func TestKernelTmpVouchRejectsMountedPlacement(t *testing.T) {
	for _, attack := range []string{"bind alias", "bind work"} {
		t.Run(attack, func(t *testing.T) { tmpUnsafePlacement(t, attack) })
	}
}

// The event descriptor belongs to the writer's mount. A daemon that systemd
// gave its own mount namespace never shares a mount with the processes it
// watches, so a descriptor opened through another mount of the same directory
// is still the file the path names, and the vouch covers it.
func TestKernelTmpVouchCoversDescriptorFromAnotherMount(t *testing.T) {
	stubTmpExecWriters(t)
	work := tmpWorkDirForTest(t)
	ch := make(chan alert.Finding, 8)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	t.Cleanup(fm.tmpVouches.close)
	writeTmpExecAs(t, fm, filepath.Join(work, "proof"), tmpProvenPID)
	if got := drainFindings(ch); len(got) != 1 || got[0].Severity != alert.Warning {
		t.Fatalf("proof: %+v", got)
	}
	alias := tmpWorkDirForTest(t)
	if err := unix.Mount(work, alias, "", unix.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount(alias, 0); err != nil {
			t.Error(err)
		}
	})
	path := filepath.Join(work, "tool")
	makeTmpExec(t, path)
	endAlertCooldown(fm)
	fm.analyzeFile(fileEvent{path: path, fd: openRawFd(t, filepath.Join(alias, "tool")), pid: tmpGonePID})
	got := drainFindings(ch)
	if len(got) != 1 || got[0].Severity != alert.Warning || got[0].FilePath != path {
		t.Fatalf("descriptor from another mount: %+v, want the grouped Warning", got)
	}
}

// Occupant descriptors may use another mount of the same work directory, but
// a mount inside it must not import an unrelated process's proof.
func TestKernelTmpOccupantMountPlacement(t *testing.T) {
	for _, nested := range []bool{false, true} {
		t.Run(strconv.FormatBool(nested), func(t *testing.T) {
			stubTmpExecWriters(t)
			work := tmpWorkDirForTest(t)
			source, target := work, tmpWorkDirForTest(t)
			if nested {
				source, target = target, filepath.Join(work, "mounted")
				if err := os.Mkdir(target, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if err := unix.Mount(source, target, "", unix.MS_BIND, ""); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := unix.Unmount(target, 0); err != nil {
					t.Error(err)
				}
			})
			proc := t.TempDir()
			overrideProcRoot(t, proc)
			occupantProc(t, proc, tmpProvenPID, target, rootUIDLine)
			ch := make(chan alert.Finding, 8)
			fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
			t.Cleanup(fm.tmpVouches.close)
			writeTmpExecAs(t, fm, filepath.Join(work, "tool"), tmpGonePID)
			want := alert.Warning
			if nested {
				want = alert.Critical
			}
			if got := drainFindings(ch); len(got) != 1 || got[0].Severity != want {
				t.Fatalf("findings = %+v, want one %v", got, want)
			}
		})
	}
}
