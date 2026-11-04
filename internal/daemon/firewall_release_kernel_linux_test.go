//go:build linux && nftkernel

package daemon

import (
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
)

// isolatedNetns moves the test's locked OS thread into a fresh network
// namespace, so Apply never touches the host's ruleset.
func isolatedNetns(t *testing.T) {
	t.Helper()
	runtime.LockOSThread()
	fd, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		runtime.UnlockOSThread()
		t.Fatal(err)
	}
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		_ = unix.Close(fd)
		runtime.UnlockOSThread()
		t.Fatalf("kernel firewall tests require CAP_SYS_ADMIN and CAP_NET_ADMIN: %v", err)
	}
	t.Cleanup(func() {
		err := unix.Setns(fd, unix.CLONE_NEWNET)
		_ = unix.Close(fd)
		if err != nil {
			t.Fatalf("restore network namespace: %v", err)
		}
		runtime.UnlockOSThread()
	})
}

// The engine startup prepares is the one that tells the daemon of operator
// releases: unblocking a sprayer there drops its re-block marker.
func TestKernelFirewallReleaseClearsSprayMarker(t *testing.T) {
	isolatedNetns(t)
	const ip = "192.0.2.7"
	cfg := &config.Config{Firewall: &firewall.FirewallConfig{Enabled: true}, StatePath: t.TempDir()}
	d := New(cfg, nil, nil, "")
	spray, _ := releaseDaemon(t)
	d.mailSpray, d.smtpAuthTracker, d.mailAuthTracker = spray.mailSpray, spray.smtpAuthTracker, spray.mailAuthTracker
	sprayBlock(t, d.mailSpray, ip)
	engine, err := d.prepareFirewall(cfg.Firewall, firewallStartupOps{
		newEngine:  firewall.NewEngine,
		apply:      (*firewall.Engine).Apply,
		unproven:   func([]string) ([]string, error) { return nil, nil },
		settled:    func([]string) ([]string, error) { return nil, nil },
		leaseFloor: func() (time.Time, error) { return time.Time{}, nil },
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := engine.UnblockIP(ip); err != nil {
		t.Fatal(err)
	}
	if _, ok := d.mailSpray.blocks[ip]; ok {
		t.Fatal("unblock through the started engine kept the spray marker")
	}
}
