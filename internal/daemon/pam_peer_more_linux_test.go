//go:build linux

package daemon

import (
	"net"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// --- non-Unix connection rejected ---------------------------------------

func TestIsTrustedPAMPeerLinuxRejectsTCPConn(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("listen tcp: %v", err)
	}
	defer func() { _ = ln.Close() }()

	doneCh := make(chan net.Conn, 1)
	go func() {
		c, acceptErr := ln.Accept()
		if acceptErr != nil {
			doneCh <- nil
			return
		}
		doneCh <- c
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	server := <-doneCh
	if server == nil {
		t.Fatal("accept failed")
	}
	defer func() { _ = server.Close() }()

	if isTrustedPAMPeer(server) {
		t.Error("TCP connection must not be trusted as PAM peer")
	}
}

// --- Unix socket peer credential extraction -----------------------------

// Use a socketpair so the peer is the current process. The result depends on
// the test process's effective UID, but the cred-extraction branch is
// exercised either way.
func TestIsTrustedPAMPeerLinuxUnixSocketPair(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Skipf("socketpair: %v", err)
	}
	// Wrap one end as a *net.UnixConn via os.File → net.FileConn.
	f := os.NewFile(uintptr(fds[0]), "sp0")
	defer func() {
		_ = f.Close()
		_ = unix.Close(fds[1])
	}()

	conn, err := net.FileConn(f)
	if err != nil {
		t.Skipf("FileConn: %v", err)
	}
	defer func() { _ = conn.Close() }()

	uc, ok := conn.(*net.UnixConn)
	if !ok {
		t.Skipf("expected *net.UnixConn, got %T", conn)
	}

	// Peer cred is the test process itself: trusted iff EUID == 0.
	got := isTrustedPAMPeer(uc)
	want := os.Geteuid() == 0
	if got != want {
		t.Errorf("isTrustedPAMPeer = %v, want %v (EUID=%d)", got, want, os.Geteuid())
	}
}

// --- closed Unix conn: SyscallConn().Control returns an error -----------

func TestIsTrustedPAMPeerLinuxClosedUnixConn(t *testing.T) {
	// Build a real *net.UnixConn then close the underlying fd via the wrapper
	// so SO_PEERCRED returns an error inside Control. Even if Control itself
	// succeeds, the GetsockoptUcred call will fail with EBADF and trusted
	// stays false.
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Skipf("socketpair: %v", err)
	}
	defer func() { _ = unix.Close(fds[1]) }()

	f := os.NewFile(uintptr(fds[0]), "sp0-closed")
	conn, err := net.FileConn(f)
	_ = f.Close() // FileConn dup'd the fd; closing the original is fine
	if err != nil {
		t.Skipf("FileConn: %v", err)
	}
	uc := conn.(*net.UnixConn)
	_ = uc.Close() // close the dup'd fd → cred lookup will fail

	if isTrustedPAMPeer(uc) {
		t.Error("closed unix conn must never be trusted")
	}
}
