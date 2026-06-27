//go:build linux

package firewall

import (
	"testing"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// TestNFTSocketBufferEnlarged verifies applyNFTSocketBuffer raises the netlink
// socket receive buffer well above the small OS default (net.core.rmem_default,
// typically ~208 KiB). Without this, a full ruleset Apply on a host with a large
// blocklist fails with ENOBUFS ("netlink receive: recvmsg: no buffer space
// available") and the firewall is left unmanaged. SetReadBuffer uses
// SO_RCVBUFFORCE under CAP_NET_ADMIN, so the larger size holds regardless of
// net.core.rmem_max.
//
// Opening a NETLINK_NETFILTER socket requires CAP_NET_ADMIN, so the test skips
// when it cannot dial (non-root or non-Linux CI); when it does run it runs as
// root and the forced resize must take effect.
func TestNFTSocketBufferEnlarged(t *testing.T) {
	nc, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		t.Skipf("cannot dial NETLINK_NETFILTER (needs root/Linux): %v", err)
	}
	defer func() { _ = nc.Close() }()

	if err := applyNFTSocketBuffer(nc); err != nil {
		t.Fatalf("applyNFTSocketBuffer: %v", err)
	}

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
	// The kernel reports roughly twice the requested size; require at least the
	// requested value so the test fails if the buffer was left at the default.
	if rcvbuf < nftSocketBufferBytes {
		t.Fatalf("SO_RCVBUF = %d, want >= %d (OS default is ~212992)", rcvbuf, nftSocketBufferBytes)
	}
}
