package main

import (
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// fileSystem is every file operation the command performs, so a test can
// fail each one and check that nothing private or partial is left behind.
type fileSystem interface {
	OpenFile(name string, flag int, perm os.FileMode) (file, error)
	CreateTemp(dir, pattern string) (file, error)
	Lstat(name string) (os.FileInfo, error)
	Link(oldname, newname string) error
	Rename(oldname, newname string) error
	Remove(name string) error
	MkdirAll(path string, perm os.FileMode) error
	EvalSymlinks(path string) (string, error)
}

type file interface {
	io.ReadWriteCloser
	Stat() (os.FileInfo, error)
	Sync() error
	Chmod(os.FileMode) error
	Name() string
	Fd() uintptr
}

type osFS struct{}

func (osFS) OpenFile(name string, flag int, perm os.FileMode) (file, error) {
	f, err := os.OpenFile(name, flag, perm) // #nosec G304 -- every caller opens an operator-chosen private path
	if err != nil {
		return nil, err
	}
	return f, nil
}

func (osFS) CreateTemp(dir, pattern string) (file, error) {
	f, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return nil, err
	}
	return f, nil
}

func (osFS) Lstat(name string) (os.FileInfo, error)       { return os.Lstat(name) }
func (osFS) Link(oldname, newname string) error           { return os.Link(oldname, newname) }
func (osFS) Rename(oldname, newname string) error         { return os.Rename(oldname, newname) }
func (osFS) Remove(name string) error                     { return os.Remove(name) }
func (osFS) MkdirAll(path string, perm os.FileMode) error { return os.MkdirAll(path, perm) }
func (osFS) EvalSymlinks(path string) (string, error)     { return filepath.EvalSymlinks(path) }

// readFile reads a whole operator-supplied input: a regular file, opened
// without following a symlink or waiting for a FIFO's writer.
func readFile(fsys fileSystem, path string) ([]byte, error) {
	f, err := fsys.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		f.Close()
		return nil, os.ErrInvalid
	}
	b, readErr := io.ReadAll(f)
	if closeErr := f.Close(); readErr != nil || closeErr != nil {
		return nil, os.ErrInvalid
	}
	return b, nil
}
