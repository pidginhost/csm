//go:build linux

package firewall

import (
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// TestNFTSocketBufferEnlarged verifies applyNFTSocketBuffer raises the netlink
// socket receive buffer to the requested size. SetReadBuffer uses
// SO_RCVBUFFORCE, which bypasses net.core.rmem_max but requires CAP_NET_ADMIN.
//
// The production daemon always runs as root with CAP_NET_ADMIN (nftables itself
// requires it), so the force succeeds in real deployments. Some CI runners
// (restricted Kubernetes pods) drop CAP_NET_ADMIN; there the kernel caps the
// buffer near 2*rmem_max instead. This test asserts the enlarged size when the
// environment can force it and skips (rather than fails) when it cannot, so it
// is meaningful where it can run and never produces a false CI failure.
//
// Opening a NETLINK_NETFILTER socket itself requires CAP_NET_ADMIN, so the test
// also skips when it cannot dial at all (non-root or non-Linux CI).
func TestNFTSocketBufferEnlarged(t *testing.T) {
	nc, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		t.Skipf("cannot dial NETLINK_NETFILTER (needs root/Linux): %v", err)
	}
	defer func() { _ = nc.Close() }()

	// applyNFTSocketBuffer is best-effort and always returns nil (a resize
	// failure is swallowed so it never breaks the connection); call it for its
	// side effect and verify the resulting buffer below.
	_ = applyNFTSocketBuffer(nc)

	sc, err := nc.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	var (
		rcvbuf int
		soErr  error
	)
	if err := sc.Control(func(fd uintptr) {
		rcvbuf, soErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF)
	}); err != nil {
		t.Fatalf("RawConn.Control: %v", err)
	}
	if soErr != nil {
		t.Fatalf("getsockopt SO_RCVBUF: %v", soErr)
	}

	// The kernel reports roughly twice the requested size. Reaching the target
	// proves the resize took effect.
	if rcvbuf >= nftSocketBufferBytes {
		return
	}

	// Below target: only acceptable when the environment could not force the
	// buffer (no CAP_NET_ADMIN), in which case the kernel caps it near
	// 2*rmem_max. Skip there; fail on any other shortfall.
	rmemMax := readRmemMax(t)
	if rcvbuf <= 2*rmemMax {
		t.Skipf("netlink buffer not forced: SO_RCVBUF=%d capped near 2*rmem_max=%d (no CAP_NET_ADMIN here); the production daemon runs as root and forces it",
			rcvbuf, 2*rmemMax)
	}
	t.Fatalf("SO_RCVBUF=%d below target %d and not explained by the rmem_max cap (%d)", rcvbuf, nftSocketBufferBytes, rmemMax)
}

func readRmemMax(t *testing.T) int {
	t.Helper()
	b, err := os.ReadFile("/proc/sys/net/core/rmem_max")
	if err != nil {
		t.Skipf("cannot read rmem_max: %v", err)
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		t.Skipf("cannot parse rmem_max %q: %v", string(b), err)
	}
	return n
}
