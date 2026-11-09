package challenge

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
)

// maxSocketPath is the longest path a client can connect to: sun_path holds
// 108 bytes including the terminating NUL.
const maxSocketPath = 107

// CheckSocketPlacement checks where the challenge socket would live: an
// absolute path a client can connect to, a group that exists, a parent owned
// by the daemon's user that nobody else can write (so nobody can plant or
// swap the path), and nothing but a stale socket at the path. The server and
// doctor share it so their rules cannot drift.
func CheckSocketPlacement(path, group string) (gid int, err error) {
	if !filepath.IsAbs(path) {
		return 0, fmt.Errorf("challenge.listen_addr: unix socket path %q must be absolute", path)
	}
	if len(path) > maxSocketPath {
		return 0, fmt.Errorf("challenge.listen_addr: socket path too long for the %d-byte limit: %s", maxSocketPath, path)
	}
	g, err := user.LookupGroup(group)
	if err != nil {
		return 0, fmt.Errorf("challenge.listen_group %q: %v", group, err)
	}
	gid, err = strconv.Atoi(g.Gid)
	if err != nil {
		return 0, fmt.Errorf("challenge.listen_group %q: gid %q: %v", group, g.Gid, err)
	}
	parent := filepath.Dir(path)
	fi, err := os.Lstat(parent)
	if err != nil {
		return 0, fmt.Errorf("challenge socket directory %s: %w", parent, err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.IsDir() || !ok || int64(st.Uid) != int64(os.Geteuid()) || fi.Mode().Perm()&0o022 != 0 {
		return 0, fmt.Errorf("challenge socket directory %s must be a directory owned by uid %d that group and others cannot write", parent, os.Geteuid())
	}
	switch fi, err := os.Lstat(path); {
	case err == nil && fi.Mode()&os.ModeSocket == 0:
		return 0, fmt.Errorf("challenge socket path %s exists and is not a socket; move it away", path)
	case err != nil && !errors.Is(err, os.ErrNotExist):
		return 0, fmt.Errorf("challenge socket path %s: %w", path, err)
	}
	return gid, nil
}

// listenUnixSocket binds the challenge socket so that no local user outside
// group can connect at any moment: it binds inside a fresh 0700 directory,
// sets group and mode there, then renames the socket into place, which also
// replaces a stale socket atomically.
func listenUnixSocket(path, group string) (net.Listener, error) {
	gid, err := CheckSocketPlacement(path, group)
	if err != nil {
		return nil, err
	}
	tmpDir, err := os.MkdirTemp(filepath.Dir(path), ".cs")
	if err != nil {
		return nil, fmt.Errorf("challenge socket: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()
	tmp := filepath.Join(tmpDir, "s")
	if len(tmp) > maxSocketPath {
		return nil, fmt.Errorf("challenge.listen_addr: socket path too long for the %d-byte limit: %s leaves no room to create it safely", maxSocketPath, filepath.Dir(path))
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: tmp, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("challenge socket bind: %w", err)
	}
	fail := func(err error) (net.Listener, error) {
		_ = ln.Close()
		return nil, err
	}
	if err := os.Lchown(tmp, -1, gid); err != nil {
		return fail(fmt.Errorf("challenge socket group: %w", err))
	}
	// #nosec G302 -- the proxy's group must be able to connect; others cannot.
	if err := os.Chmod(tmp, 0o660); err != nil {
		return fail(fmt.Errorf("challenge socket mode: %w", err))
	}
	if err := os.Rename(tmp, path); err != nil {
		return fail(fmt.Errorf("challenge socket: %w", err))
	}
	// The bound name is gone; Shutdown removes the final path instead.
	ln.SetUnlinkOnClose(false)
	return ln, nil
}
