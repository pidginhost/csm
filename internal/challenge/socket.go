package challenge

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// maxSocketPath is the longest path a client can connect to: sun_path holds
// 108 bytes including the terminating NUL.
const maxSocketPath = 107

// CheckSocketPlacement checks where the challenge socket would live: an
// absolute path a client can connect to, a group that exists, a parent owned
// by the daemon's user that nobody else can write (so nobody can plant or
// swap the path), and nothing but a socket at the path. The server and
// doctor share it so their rules cannot drift.
func CheckSocketPlacement(path, group string) (gid int, err error) {
	if !filepath.IsAbs(path) {
		return 0, fmt.Errorf("challenge.listen_addr: unix socket path %q must be absolute", path)
	}
	if filepath.Clean(path) != path {
		return 0, fmt.Errorf("challenge.listen_addr: unix socket path %q must be clean (no redundant separators or dot components)", path)
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
	if err := checkSocketAncestors(parent); err != nil {
		return 0, err
	}
	switch fi, err := os.Lstat(path); {
	case err == nil && fi.Mode()&os.ModeSocket == 0:
		return 0, fmt.Errorf("challenge socket path %s exists and is not a socket; move it away", path)
	case err != nil && !errors.Is(err, os.ErrNotExist):
		return 0, fmt.Errorf("challenge socket path %s: %w", path, err)
	}
	return gid, nil
}

// A protected parent is insufficient if a tenant can replace it through a
// writable ancestor. Follow only trusted links and directories, including
// the directories used to resolve symlink targets and dot components.
func checkSocketAncestors(parent string) error {
	current, rest, links := "/", strings.Split(strings.TrimPrefix(parent, "/"), "/"), 0
	for {
		fi, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("challenge socket directory %s: %w", current, err)
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || !fi.IsDir() || (st.Uid != 0 && int64(st.Uid) != int64(os.Geteuid())) ||
			(fi.Mode().Perm()&0o022 != 0 && fi.Mode()&os.ModeSticky == 0) {
			return fmt.Errorf("challenge socket directory %s can be replaced by another user; use a protected directory", current)
		}
		if len(rest) == 0 {
			return nil
		}
		name := rest[0]
		rest = rest[1:]
		switch name {
		case "", ".":
			continue
		case "..":
			current = filepath.Dir(current)
			continue
		}
		next := filepath.Join(current, name)
		fi, err = os.Lstat(next)
		if err != nil {
			return fmt.Errorf("challenge socket directory %s: %w", next, err)
		}
		st, ok = fi.Sys().(*syscall.Stat_t)
		if !ok || (st.Uid != 0 && int64(st.Uid) != int64(os.Geteuid())) {
			return fmt.Errorf("challenge socket directory %s must be owned by root or uid %d", next, os.Geteuid())
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			current = next
			continue
		}
		links++
		if links > 40 {
			return fmt.Errorf("challenge socket directory %s: too many symbolic links", next)
		}
		target, err := os.Readlink(next)
		if err != nil {
			return fmt.Errorf("challenge socket directory %s: %w", next, err)
		}
		if filepath.IsAbs(target) {
			current = "/"
		}
		rest = append(strings.Split(target, "/"), rest...)
	}
}

type socketListener struct {
	*net.UnixListener
	path string
	info os.FileInfo
	once sync.Once
	err  error
}

func (l *socketListener) Addr() net.Addr {
	return &net.UnixAddr{Name: l.path, Net: "unix"}
}

func (l *socketListener) Close() error {
	l.once.Do(func() {
		// Another server or an operator may have replaced the path. A
		// repeated Close must not remove that replacement either. Keep the
		// bound inode alive until after the check to prevent inode reuse.
		if fi, err := os.Lstat(l.path); err == nil && os.SameFile(l.info, fi) {
			if err := os.Remove(l.path); err != nil && !errors.Is(err, os.ErrNotExist) {
				l.err = err
			}
		}
		l.err = errors.Join(l.err, l.UnixListener.Close())
	})
	return l.err
}

func checkStaleSocket(path string) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("challenge socket path %s: %w", path, err)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("challenge socket path %s exists and is not a socket; move it away", path)
	}
	conn, err := net.DialTimeout("unix", path, time.Second)
	if err == nil {
		_ = conn.Close()
		return fmt.Errorf("challenge socket %s is already listening", path)
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		return fmt.Errorf("challenge socket %s cannot be confirmed stale: %w", path, err)
	}
	return nil
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
	if chownErr := os.Lchown(tmp, -1, gid); chownErr != nil {
		return fail(fmt.Errorf("challenge socket group: %w", chownErr))
	}
	if aclErr := clearSocketACL(tmp); aclErr != nil {
		return fail(fmt.Errorf("challenge socket permissions: %w", aclErr))
	}
	// #nosec G302 -- the proxy's group must be able to connect; others cannot.
	if chmodErr := os.Chmod(tmp, 0o660); chmodErr != nil {
		return fail(fmt.Errorf("challenge socket mode: %w", chmodErr))
	}
	info, err := os.Lstat(tmp)
	if err != nil {
		return fail(fmt.Errorf("challenge socket identity: %w", err))
	}
	if err := checkStaleSocket(path); err != nil {
		return fail(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fail(fmt.Errorf("challenge socket: %w", err))
	}
	// The wrapper owns cleanup of the published name on every close path.
	ln.SetUnlinkOnClose(false)
	return &socketListener{UnixListener: ln, path: path, info: info}, nil
}
