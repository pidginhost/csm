package yaraworker

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// The socket used to be created with the process umask and chmodded to 0600
// afterwards, leaving a window in which any local user could connect (and a
// connection made in that window survives the chmod). The socket must be
// born private: the listen happens under a 0077 umask.
func TestListenPrivateUnixCreatesSocketUnderPrivateUmask(t *testing.T) {
	prev := syscall.Umask(0o022)
	t.Cleanup(func() { syscall.Umask(prev) })

	path := filepath.Join(shortTmpDir(t), "w.sock")
	var seen int
	ln, err := listenPrivateUnix(path, func(p string) (net.Listener, error) {
		seen = syscall.Umask(0)
		syscall.Umask(seen)
		return net.Listen("unix", p)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	if seen != 0o077 {
		t.Fatalf("socket created under umask %04o, want 0077", seen)
	}
	if got := syscall.Umask(0o022); got != 0o022 {
		t.Fatalf("process umask left at %04o after listen, want restored 0022", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode = %04o, want 0600", info.Mode().Perm())
	}
}

func TestListenPrivateUnixRestoresUmaskWhenListenFails(t *testing.T) {
	prev := syscall.Umask(0o022)
	t.Cleanup(func() { syscall.Umask(prev) })

	if _, err := listenPrivateUnix("unused", func(string) (net.Listener, error) {
		return nil, errors.New("bind failed")
	}); err == nil {
		t.Fatal("listen failure was not returned")
	}
	if got := syscall.Umask(0o022); got != 0o022 {
		t.Fatalf("process umask left at %04o after listen failure, want restored 0022", got)
	}
}
