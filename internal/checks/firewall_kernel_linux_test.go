//go:build linux && nftkernel

package checks

import (
	"os/exec"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/state"
)

// Use real terse output: a mock cannot prove that nft still lists every
// required component or that the engine and standalone hashes agree.
func TestKernelCheckFirewallStandaloneUsesAppliedBaseline(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	fd, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	if unshareErr := unix.Unshare(unix.CLONE_NEWNET); unshareErr != nil {
		t.Fatal(unshareErr)
	}
	defer func() {
		if restoreErr := unix.Setns(fd, unix.CLONE_NEWNET); restoreErr != nil {
			t.Fatalf("restore network namespace: %v", restoreErr)
		}
	}()
	previous := getIPBlocker()
	defer SetIPBlocker(previous)
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	fc := &firewall.FirewallConfig{Enabled: true, IPv6: true, DropIPv4Options: true}
	e, err := firewall.NewEngine(fc, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Apply(); err != nil {
		t.Fatal(err)
	}
	SetIPBlocker(e)
	if msgs := firewallCheckMessages(t, st, fc); len(msgs) != 0 {
		t.Fatalf("managed check: %v", msgs)
	}
	SetIPBlocker(nil)
	if err := e.BlockIPForce("198.51.100.9", "test", time.Hour); err != nil {
		t.Fatal(err)
	}
	if msgs := firewallCheckMessages(t, st, fc); len(msgs) != 0 {
		t.Fatalf("standalone check after set update: %v", msgs)
	}
	if out, err := exec.Command("nft", "flush", "chain", "inet", "csm", "prerouting").CombinedOutput(); err != nil {
		t.Fatalf("flush protection: %v: %s", err, out)
	}
	for range 2 {
		msgs := firewallCheckMessages(t, st, fc)
		if len(msgs) != 1 || !mentionsExternalEdit(msgs) {
			t.Fatalf("removed drop must keep reporting tampering: %v", msgs)
		}
	}
	SetIPBlocker(e)
	for _, on := range []bool{false, true, false} {
		next := *fc
		next.DropIPv4Options = on
		e.SetConfig(&next)
		if err := e.Apply(); err != nil {
			t.Fatal(err)
		}
		if msgs := firewallCheckMessages(t, st, fc); len(msgs) != 0 {
			t.Fatalf("protection=%t with stale daemon config: %v", on, msgs)
		}
	}
}
