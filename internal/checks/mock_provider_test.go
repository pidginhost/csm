package checks

import (
	"context"
	"os"
	"testing"
)

// ---------------------------------------------------------------------------
// Mock OS — function-field based mock for table-driven tests
// ---------------------------------------------------------------------------

type mockOS struct {
	readFile func(string) ([]byte, error)
	readDir  func(string) ([]os.DirEntry, error)
	stat     func(string) (os.FileInfo, error)
	lstat    func(string) (os.FileInfo, error)
	readlink func(string) (string, error)
	open     func(string) (*os.File, error)
	glob     func(string) ([]string, error)
}

func (m *mockOS) ReadFile(name string) ([]byte, error) {
	if m.readFile != nil {
		return m.readFile(name)
	}
	return nil, os.ErrNotExist
}

func (m *mockOS) ReadDir(name string) ([]os.DirEntry, error) {
	if m.readDir != nil {
		return m.readDir(name)
	}
	return nil, os.ErrNotExist
}

func (m *mockOS) Stat(name string) (os.FileInfo, error) {
	if m.stat != nil {
		return m.stat(name)
	}
	return nil, os.ErrNotExist
}

func (m *mockOS) Lstat(name string) (os.FileInfo, error) {
	if m.lstat != nil {
		return m.lstat(name)
	}
	return nil, os.ErrNotExist
}

func (m *mockOS) Readlink(name string) (string, error) {
	if m.readlink != nil {
		return m.readlink(name)
	}
	return "", os.ErrNotExist
}

func (m *mockOS) Open(name string) (*os.File, error) {
	if m.open != nil {
		return m.open(name)
	}
	return nil, os.ErrNotExist
}

func (m *mockOS) Glob(pattern string) ([]string, error) {
	if m.glob != nil {
		return m.glob(pattern)
	}
	return nil, nil
}

// ---------------------------------------------------------------------------
// Mock CmdRunner
// ---------------------------------------------------------------------------

type mockCmd struct {
	run             func(string, ...string) ([]byte, error)
	runAllowNonZero func(string, ...string) ([]byte, error)
	runContext      func(context.Context, string, ...string) ([]byte, error)
	runWithEnv      func(string, []string, ...string) ([]byte, error)
	lookPath        func(string) (string, error)
}

func (m *mockCmd) Run(name string, args ...string) ([]byte, error) {
	if m.run != nil {
		return m.run(name, args...)
	}
	return nil, nil
}

// RunContext falls back to the simpler `run` mock when no `runContext` is
// provided. This lets tests that don't care about the context set just
// `mockCmd{run: ...}` and have it work for both Run() and RunContext()
// callers (e.g., audit functions that route through auditRunCmd).
func (m *mockCmd) RunContext(parent context.Context, name string, args ...string) ([]byte, error) {
	if m.runContext != nil {
		return m.runContext(parent, name, args...)
	}
	if m.run != nil {
		return m.run(name, args...)
	}
	return nil, nil
}

// RunAllowNonZero falls back to `run` when `runAllowNonZero` is unset.
// Same motivation as RunContext above.
func (m *mockCmd) RunAllowNonZero(name string, args ...string) ([]byte, error) {
	if m.runAllowNonZero != nil {
		return m.runAllowNonZero(name, args...)
	}
	if m.run != nil {
		return m.run(name, args...)
	}
	return nil, nil
}

func (m *mockCmd) RunWithEnv(name string, args []string, extraEnv ...string) ([]byte, error) {
	if m.runWithEnv != nil {
		return m.runWithEnv(name, args, extraEnv...)
	}
	if m.run != nil {
		return m.run(name, args...)
	}
	return nil, nil
}

func (m *mockCmd) LookPath(file string) (string, error) {
	if m.lookPath != nil {
		return m.lookPath(file)
	}
	return "", os.ErrNotExist
}

// ---------------------------------------------------------------------------
// Test helpers — save/restore pattern
// ---------------------------------------------------------------------------

func withMockOS(t *testing.T, m OS) {
	t.Helper()
	old := osFS
	osFS = m
	t.Cleanup(func() { osFS = old })
}

func withMockCmd(t *testing.T, m CmdRunner) {
	t.Helper()
	old := cmdExec
	cmdExec = m
	t.Cleanup(func() { cmdExec = old })
}

// ---------------------------------------------------------------------------
// Foundation tests — verify the injection mechanism works
// ---------------------------------------------------------------------------

func TestProviderInjectionOS(t *testing.T) {
	called := false
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			called = true
			return []byte("mocked"), nil
		},
	})

	data, err := osFS.ReadFile("/etc/test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != "mocked" {
		t.Errorf("got %q, want mocked", data)
	}
	if !called {
		t.Error("mock was not called")
	}
}

func TestProviderInjectionCmd(t *testing.T) {
	called := false
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			called = true
			return []byte("output"), nil
		},
	})

	out, err := cmdExec.Run("test", "arg")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(out) != "output" {
		t.Errorf("got %q", out)
	}
	if !called {
		t.Error("mock was not called")
	}
}

func TestProviderDefaultsAreReal(t *testing.T) {
	// Verify the defaults are the real implementations (not nil).
	if osFS == nil {
		t.Fatal("osFS default is nil")
	}
	if cmdExec == nil {
		t.Fatal("cmdExec default is nil")
	}
}
