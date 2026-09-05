// Package safepath pins directories for operations on tenant-controlled names.
package safepath

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"
)

// Dir owns an open directory. Operations accept single basenames only and
// never resolve a symlink, including in the final component.
type Dir struct {
	file *os.File
}

// OpenDir opens an operator-controlled root. Its ancestors must be trusted;
// use OpenTarget to traverse anything beneath it controlled by an account.
func OpenDir(path string) (*Dir, error) {
	// #nosec G304 -- this opens the operator-controlled anchor; all tenant components are traversed with descriptor-relative no-follow operations
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return &Dir{file: f}, nil
}

func (d *Dir) Close() error { return d.file.Close() }

func (d *Dir) Sync() error { return d.file.Sync() }

func validName(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, "/\x00")
}

// fileFD returns f's integer descriptor for a descriptor-relative syscall.
// Callers must keep f alive across the call.
func fileFD(f *os.File) int {
	// #nosec G115 -- an open descriptor is a small non-negative value; os.File only exposes it as uintptr
	return int(f.Fd())
}

// adoptFD wraps a descriptor produced by a syscall whose error was already checked.
func adoptFD(fd int, name string) *os.File {
	// #nosec G115 -- a syscall that reported success returns a non-negative descriptor
	return os.NewFile(uintptr(fd), name)
}

func (d *Dir) OpenFile(name string, flags int, mode os.FileMode) (*os.File, error) {
	if !validName(name) {
		return nil, fmt.Errorf("invalid basename %q", name)
	}
	fd, err := unix.Openat(fileFD(d.file), name, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, uint32(mode.Perm()))
	// The integer descriptor does not keep os.File's finalizer alive.
	runtime.KeepAlive(d)
	if err != nil {
		return nil, &os.PathError{Op: "openat", Path: name, Err: err}
	}
	return adoptFD(fd, name), nil
}

func (d *Dir) Stat(name string) (os.FileInfo, error) {
	f, err := d.OpenFile(name, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return f.Stat()
}

func (d *Dir) CreateTemp() (*os.File, error) {
	return d.OpenFile(".csm-restore-"+rand.Text(), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
}

// CreatePrivateTemp isolates transaction names from writers of the parent.
// The parent may rename this directory, so callers must keep using its handle.
func (d *Dir) CreatePrivateTemp() (*Dir, string, error) {
	name := ".csm-restore-" + rand.Text()
	err := unix.Mkdirat(fileFD(d.file), name, 0700)
	runtime.KeepAlive(d)
	if err != nil {
		return nil, "", err
	}
	f, err := d.OpenFile(name, os.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, "", err
	}
	var stat unix.Stat_t
	err = unix.Fstat(fileFD(f), &stat)
	runtime.KeepAlive(f)
	if err != nil {
		_ = f.Close()
		return nil, "", err
	}
	if int(stat.Uid) != os.Geteuid() || stat.Mode&0077 != 0 {
		_ = f.Close()
		return nil, "", fmt.Errorf("private restore directory changed while opening")
	}
	return &Dir{file: f}, name, nil
}

// RemoveDir removes only an empty directory; it never traverses its contents.
func (d *Dir) RemoveDir(name string) error {
	return d.unlink(name, unix.AT_REMOVEDIR)
}

func (d *Dir) Remove(name string) error {
	return d.unlink(name, 0)
}

func (d *Dir) unlink(name string, flags int) error {
	if !validName(name) {
		return fmt.Errorf("invalid basename %q", name)
	}
	err := unix.Unlinkat(fileFD(d.file), name, flags)
	runtime.KeepAlive(d)
	if err != nil {
		return &os.PathError{Op: "unlinkat", Path: name, Err: err}
	}
	return nil
}

// RenameTo never replaces an existing destination. ExchangeTo atomically
// swaps two existing names. Neither operation follows either name's symlink.
func (d *Dir) RenameTo(name string, dest *Dir, destName string) error {
	return d.rename(name, dest, destName, false)
}

func (d *Dir) ExchangeTo(name string, dest *Dir, destName string) error {
	return d.rename(name, dest, destName, true)
}

func (d *Dir) rename(name string, dest *Dir, destName string, exchange bool) error {
	if !validName(name) || !validName(destName) {
		return fmt.Errorf("invalid rename basenames %q, %q", name, destName)
	}
	err := renameat(fileFD(d.file), name, fileFD(dest.file), destName, exchange)
	runtime.KeepAlive(d)
	runtime.KeepAlive(dest)
	if err != nil {
		return &os.LinkError{Op: "renameat", Old: name, New: destName, Err: err}
	}
	return nil
}

// Target keeps both the trusted root and the destination's parent open.
// Check detects a renamed parent; I/O uses Parent even if that check races.
type Target struct {
	Parent *Dir
	Name   string
	root   *Dir
	relDir string
}

func OpenTarget(rootPath, relative string, createParents bool) (*Target, error) {
	if !filepath.IsLocal(relative) || filepath.Clean(relative) != relative || relative == "." {
		return nil, fmt.Errorf("invalid relative restore path %q", relative)
	}
	root, err := OpenDir(rootPath)
	if err != nil {
		return nil, err
	}
	relDir := filepath.Dir(relative)
	parent, err := root.walk(relDir, createParents)
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	return &Target{Parent: parent, Name: filepath.Base(relative), root: root, relDir: relDir}, nil
}

func (t *Target) Close() {
	_ = t.Parent.Close()
	_ = t.root.Close()
}

func (t *Target) Check() error {
	current, err := t.root.walk(t.relDir, false)
	if err != nil {
		return fmt.Errorf("restore parent changed: %w", err)
	}
	defer func() { _ = current.Close() }()
	want, err := t.Parent.file.Stat()
	if err != nil {
		return err
	}
	got, err := current.file.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(want, got) {
		return fmt.Errorf("restore parent changed")
	}
	return nil
}

func (d *Dir) walk(relative string, create bool) (*Dir, error) {
	fd, err := unix.Openat(fileFD(d.file), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	runtime.KeepAlive(d)
	if err != nil {
		return nil, err
	}
	current := &Dir{file: adoptFD(fd, ".")}
	if relative == "." {
		return current, nil
	}
	for _, name := range strings.Split(relative, string(filepath.Separator)) {
		if !validName(name) {
			_ = current.Close()
			return nil, fmt.Errorf("invalid directory component %q", name)
		}
		next, openErr := current.OpenFile(name, os.O_RDONLY|unix.O_DIRECTORY, 0)
		if os.IsNotExist(openErr) && create {
			// Public document roots need traversable parents. A concurrent
			// creator is harmless only if the no-follow open accepts its inode.
			mkdirErr := unix.Mkdirat(fileFD(current.file), name, 0755)
			runtime.KeepAlive(current)
			if mkdirErr != nil && mkdirErr != unix.EEXIST {
				_ = current.Close()
				return nil, mkdirErr
			}
			next, openErr = current.OpenFile(name, os.O_RDONLY|unix.O_DIRECTORY, 0)
		}
		// A concurrent restore may have created the directory but not yet
		// persisted its entry. Each successful restore needs its own sync.
		if openErr == nil && create {
			if syncErr := current.Sync(); syncErr != nil {
				_ = next.Close()
				openErr = syncErr
			}
		}
		_ = current.Close()
		if openErr != nil {
			return nil, openErr
		}
		current = &Dir{file: next}
	}
	return current, nil
}
