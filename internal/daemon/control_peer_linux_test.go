//go:build linux

package daemon

import (
	"net"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func allowCurrentControlPeerUID(t *testing.T) {
	t.Helper()
	setControlPeerRequiredUID(t, currentControlPeerUID(t))
}

func setControlPeerRequiredUID(t *testing.T, uid uint32) {
	t.Helper()
	prev := controlPeerRequiredUID
	controlPeerRequiredUID = uid
	t.Cleanup(func() { controlPeerRequiredUID = prev })
}

func currentControlPeerUID(t *testing.T) uint32 {
	t.Helper()
	uid := os.Geteuid()
	if uid < 0 {
		t.Fatalf("geteuid returned negative uid %d", uid)
	}
	return uint32(uid) // #nosec G115 -- Linux uid_t is uint32 and geteuid is non-negative.
}

func controlPeerSocketPair(t *testing.T) *net.UnixConn {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Skipf("socketpair: %v", err)
	}

	left := os.NewFile(uintptr(fds[0]), "control-peer-left")
	right := os.NewFile(uintptr(fds[1]), "control-peer-right")
	conn, err := net.FileConn(left)
	_ = left.Close()
	if err != nil {
		_ = right.Close()
		t.Skipf("FileConn: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		_ = right.Close()
	})

	uc, ok := conn.(*net.UnixConn)
	if !ok {
		t.Fatalf("FileConn returned %T, want *net.UnixConn", conn)
	}
	return uc
}

func TestVerifyControlPeerLinuxAcceptsRequiredUID(t *testing.T) {
	setControlPeerRequiredUID(t, currentControlPeerUID(t))
	if err := verifyControlPeer(controlPeerSocketPair(t)); err != nil {
		t.Fatalf("verifyControlPeer: %v", err)
	}
}

func TestVerifyControlPeerLinuxRejectsUnexpectedUID(t *testing.T) {
	required := uint32(0)
	if currentControlPeerUID(t) == 0 {
		required = 1
	}
	setControlPeerRequiredUID(t, required)

	err := verifyControlPeer(controlPeerSocketPair(t))
	if err == nil {
		t.Fatal("verifyControlPeer accepted a peer with the wrong uid")
	}
	if !strings.Contains(err.Error(), "peer uid=") {
		t.Fatalf("verifyControlPeer error = %q, want uid mismatch", err)
	}
}

func TestVerifyControlPeerLinuxRejectsCredentiallessConn(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	err := verifyControlPeer(server)
	if err == nil {
		t.Fatal("verifyControlPeer accepted a connection without Unix peer credentials")
	}
	if !strings.Contains(err.Error(), "unsupported connection") {
		t.Fatalf("verifyControlPeer error = %q, want unsupported connection", err)
	}
}

func TestVerifyControlPeerLinuxRejectsNilUnixConn(t *testing.T) {
	var conn *net.UnixConn
	err := verifyControlPeer(conn)
	if err == nil {
		t.Fatal("verifyControlPeer accepted a nil Unix connection")
	}
	if !strings.Contains(err.Error(), "unsupported connection") {
		t.Fatalf("verifyControlPeer error = %q, want unsupported connection", err)
	}
}
