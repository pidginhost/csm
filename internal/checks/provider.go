package checks

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// ---------------------------------------------------------------------------
// OS abstraction — filesystem read operations
// ---------------------------------------------------------------------------

// OS abstracts filesystem operations (read and write) used by check functions.
// Production code uses realOS{}; tests swap in a mockOS via SetOS().
type OS interface {
	ReadFile(name string) ([]byte, error)
	ReadDir(name string) ([]os.DirEntry, error)
	Stat(name string) (os.FileInfo, error)
	Lstat(name string) (os.FileInfo, error)
	Readlink(name string) (string, error)
	Open(name string) (*os.File, error)
	WriteFile(name string, data []byte, perm os.FileMode) error
	MkdirAll(path string, perm os.FileMode) error
	Remove(name string) error
	Glob(pattern string) ([]string, error)
}

type realOS struct{}

var errNonRegularFile = errors.New("not a regular file")
var errFileChanged = errors.New("file changed while reading")

// #nosec G304 -- filesystem abstraction; check functions pass trusted paths.
func (realOS) ReadFile(name string) ([]byte, error)       { return os.ReadFile(name) }
func (realOS) ReadDir(name string) ([]os.DirEntry, error) { return os.ReadDir(name) }
func (realOS) Stat(name string) (os.FileInfo, error)      { return os.Stat(name) }
func (realOS) Lstat(name string) (os.FileInfo, error)     { return os.Lstat(name) }
func (realOS) Readlink(name string) (string, error)       { return os.Readlink(name) }

// #nosec G304 -- filesystem abstraction; check functions pass trusted paths.
func (realOS) openRegularFile(name string, extraFlags int) (*os.File, error) {
	fd, err := unix.Open(name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK|extraFlags, 0)
	if err != nil {
		return nil, err
	}
	// #nosec G115 -- unix.Open returns a non-negative descriptor whenever err is nil.
	file := os.NewFile(uintptr(fd), name)
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, errNonRegularFile
	}
	return file, nil
}

// ReadRegularFile opens without blocking on a path raced to a FIFO, then
// verifies the opened object before reading from the inode bound to the fd.
func (r realOS) ReadRegularFile(name string) ([]byte, error) {
	file, err := r.openRegularFile(name, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(file)
}

// ReadRegularFilePrefix bounds consumers that need only an admission prefix.
// Refusing symlinks and matching the opened inode to the caller's snapshot
// stop a path replacement from redirecting a content-based admission decision.
func (r realOS) ReadRegularFilePrefix(name string, expected os.FileInfo, limit int64) ([]byte, error) {
	file, err := r.openRegularFile(name, unix.O_NOFOLLOW)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !sameFileSnapshot(expected, opened) {
		return nil, errFileChanged
	}
	prefix, err := io.ReadAll(io.LimitReader(file, limit))
	if err != nil {
		return prefix, err
	}
	after, err := file.Stat()
	if err != nil {
		return prefix, err
	}
	if !sameFileSnapshot(opened, after) {
		return prefix, errFileChanged
	}
	return prefix, nil
}

func sameFileSnapshot(expected, actual os.FileInfo) bool {
	return expected != nil && actual != nil &&
		os.SameFile(expected, actual) &&
		expected.Mode() == actual.Mode() &&
		expected.Size() == actual.Size() &&
		expected.ModTime().Equal(actual.ModTime())
}

// #nosec G304 -- filesystem abstraction; check functions pass trusted paths.
func (realOS) Open(name string) (*os.File, error) { return os.Open(name) }

// #nosec G306 -- callers pass explicit perm; intent is operator-readable mode.
func (realOS) WriteFile(name string, data []byte, perm os.FileMode) error {
	return os.WriteFile(name, data, perm)
}

func (realOS) MkdirAll(path string, perm os.FileMode) error { return os.MkdirAll(path, perm) }
func (realOS) Remove(name string) error                     { return os.Remove(name) }

func (realOS) Glob(pattern string) ([]string, error) { return filepath.Glob(pattern) }

// osFS is the package-level filesystem provider. All check functions use
// this instead of calling os.ReadFile / os.ReadDir / etc. directly.
var osFS OS = realOS{}

// SetOS replaces the filesystem provider. Used by tests to inject mocks.
func SetOS(o OS) { osFS = o }

// ---------------------------------------------------------------------------
// CmdRunner abstraction — external command execution
// ---------------------------------------------------------------------------

// CmdRunner abstracts external command execution used by check functions.
// Production code uses realCmd{}; tests swap in a mockCmdRunner via SetCmdRunner().
//
// RunContext returns stdout+stderr merged (CombinedOutput) and is fine for
// tools that only write to stdout. RunContextStdout returns stdout only and
// should be used when the command prints structured output (JSON, a URL, ...)
// on stdout and chatter (warnings, PHP notices, MySQL deprecations) on stderr
// -- mixing them there would corrupt the parse. RunContextStdout also surfaces
// context.DeadlineExceeded on timeout so callers can distinguish "no output"
// from "empty output".
type CmdRunner interface {
	Run(name string, args ...string) ([]byte, error)
	RunAllowNonZero(name string, args ...string) ([]byte, error)
	RunContext(parent context.Context, name string, args ...string) ([]byte, error)
	RunContextStdout(parent context.Context, name string, args ...string) ([]byte, error)
	RunWithEnv(name string, args []string, extraEnv ...string) ([]byte, error)
	LookPath(file string) (string, error)
}

type realCmd struct{}

func (realCmd) Run(name string, args ...string) ([]byte, error) {
	return runCmdReal(name, args...)
}

func (realCmd) RunAllowNonZero(name string, args ...string) ([]byte, error) {
	return runCmdAllowNonZeroReal(name, args...)
}

func (realCmd) RunContext(parent context.Context, name string, args ...string) ([]byte, error) {
	return runCmdCombinedContextReal(parent, name, args...)
}

func (realCmd) RunContextStdout(parent context.Context, name string, args ...string) ([]byte, error) {
	return runCmdStdoutContextReal(parent, name, args...)
}

func (realCmd) RunWithEnv(name string, args []string, extraEnv ...string) ([]byte, error) {
	return runCmdWithEnvReal(name, args, extraEnv...)
}

func (realCmd) LookPath(file string) (string, error) {
	return lookupSystemCommand(file)
}

// cmdExec is the package-level command runner. All check functions use
// this instead of calling runCmd / exec.Command directly.
var cmdExec CmdRunner = realCmd{}

// SetCmdRunner replaces the command runner. Used by tests to inject mocks.
func SetCmdRunner(r CmdRunner) { cmdExec = r }
