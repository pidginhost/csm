package checks

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/mysqlclient"
	"github.com/pidginhost/csm/internal/redisinfo"
)

// ---------------------------------------------------------------------------
// Mock OS — function-field based mock for table-driven tests
// ---------------------------------------------------------------------------

type mockOS struct {
	readFile  func(string) ([]byte, error)
	readDir   func(string) ([]os.DirEntry, error)
	stat      func(string) (os.FileInfo, error)
	lstat     func(string) (os.FileInfo, error)
	readlink  func(string) (string, error)
	open      func(string) (*os.File, error)
	writeFile func(string, []byte, os.FileMode) error
	mkdirAll  func(string, os.FileMode) error
	remove    func(string) error
	glob      func(string) ([]string, error)
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

func (m *mockOS) WriteFile(name string, data []byte, perm os.FileMode) error {
	if m.writeFile != nil {
		return m.writeFile(name, data, perm)
	}
	// Match the os.ErrNotExist default that every other mock method returns
	// when its function field is unset. The "loud failure" intent (an
	// unconfigured WriteFile mock surfaces as a real test error rather than
	// a silent nil) is preserved by any non-nil error.
	return os.ErrNotExist
}

func (m *mockOS) MkdirAll(path string, perm os.FileMode) error {
	if m.mkdirAll != nil {
		return m.mkdirAll(path, perm)
	}
	return os.ErrNotExist
}

func (m *mockOS) Remove(name string) error {
	if m.remove != nil {
		return m.remove(name)
	}
	return os.ErrNotExist
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
	run              func(string, ...string) ([]byte, error)
	runAllowNonZero  func(string, ...string) ([]byte, error)
	runContext       func(context.Context, string, ...string) ([]byte, error)
	runContextStdout func(context.Context, string, ...string) ([]byte, error)
	runWithEnv       func(string, []string, ...string) ([]byte, error)
	lookPath         func(string) (string, error)
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

// RunContextStdout falls back to `runContext`, then `run`. Tests that want to
// distinguish stdout-only callers from combined-output callers can set
// `runContextStdout` explicitly; otherwise the existing mock continues to
// answer both call sites identically.
func (m *mockCmd) RunContextStdout(parent context.Context, name string, args ...string) ([]byte, error) {
	if m.runContextStdout != nil {
		return m.runContextStdout(parent, name, args...)
	}
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

// withMockPasswd writes content to a temp passwd file and points the package's
// defaultUIDCache at it for the duration of the test. Use this when a test
// exercises a check that calls LookupUser and the uid -> username resolution
// is part of the assertion (safeUsers filter, username-in-message text, etc.).
func withMockPasswd(t *testing.T, content string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	restore := swapDefaultUIDCacheForTest(path)
	t.Cleanup(restore)
}

func withMockCmd(t *testing.T, m CmdRunner) {
	t.Helper()
	old := cmdExec
	cmdExec = m
	t.Cleanup(func() { cmdExec = old })

	// Bridge: runMySQLQuery now routes through internal/mysqlclient
	// (database/sql) instead of exec'ing the mysql CLI. Tests that
	// mock mysql via `mockCmd{runWithEnv: ...}` predate that
	// migration; reroute the new sql path through the same mock so
	// the existing assertions keep working without touching every
	// dbscan/db_clean test fixture.
	if mc, ok := m.(*mockCmd); ok && (mc.runWithEnv != nil || mc.run != nil) {
		mysqlclient.SetPerAccountQueryForTest(func(_ context.Context, creds mysqlclient.Creds, query string, _ ...any) ([]string, error) {
			// Reconstruct the historical CLI argv so existing
			// mock callbacks (which switch on `args[i]`) match.
			args := []string{
				"-N", "-B",
				"-u", creds.User,
				"-h", creds.Host,
				creds.DBName,
				"-e", query,
			}
			out, err := mc.RunWithEnv("mysql", args, "MYSQL_PWD="+creds.Password)
			if err != nil {
				return nil, err
			}
			return splitMockMySQLOutput(out), nil
		})
		mysqlclient.SetRootQueryForTest(func(_ context.Context, schema, query string, _ ...any) ([]string, error) {
			// Root MySQL had no -u/-h/MYSQL_PWD; the historical
			// argv was just `mysql -N -B [<schema>] -e <query>`.
			args := []string{"-N", "-B"}
			if schema != "" {
				args = append(args, schema)
			}
			args = append(args, "-e", query)
			out, err := mc.Run("mysql", args...)
			if err != nil {
				return nil, err
			}
			return splitMockMySQLOutput(out), nil
		})
		mysqlclient.SetRootExecForTest(func(_ context.Context, schema, stmt string, _ ...any) (int64, error) {
			args := []string{"-N", "-B"}
			if schema != "" {
				args = append(args, schema)
			}
			args = append(args, "-e", stmt)
			_, err := mc.Run("mysql", args...)
			return 0, err
		})
		// Redis bridge: redisinfo now goes through go-redis instead of
		// shelling redis-cli. Tests that stub redis-cli via mockCmd
		// continue to drive the new helpers through these hooks.
		redisinfo.SetMemoryUsageForTest(func(_ context.Context) (uint64, uint64, error) {
			out, err := mc.Run("/usr/bin/redis-cli", "info", "memory")
			if err != nil || len(out) == 0 {
				return 0, 0, err
			}
			return parseMockRedisMemory(out), parseMockRedisField(out, "maxmemory:"), nil
		})
		redisinfo.SetKeyspaceStatsForTest(func(_ context.Context) (redisinfo.KeyspaceStat, error) {
			out, err := mc.Run("/usr/bin/redis-cli", "info", "keyspace")
			if err != nil || len(out) == 0 {
				return redisinfo.KeyspaceStat{}, err
			}
			return parseMockRedisKeyspace(out), nil
		})
		redisinfo.SetConfigGetForTest(func(_ context.Context, name string) (string, error) {
			out, err := mc.Run("/usr/bin/redis-cli", "config", "get", name)
			if err != nil || len(out) == 0 {
				return "", err
			}
			// `redis-cli config get <key>` prints two tokens:
			// "<key>\n<value>\n" -- pluck the second.
			fields := strings.Fields(string(out))
			if len(fields) >= 2 {
				return strings.Join(fields[1:], " "), nil
			}
			return "", nil
		})
		t.Cleanup(func() {
			mysqlclient.SetPerAccountQueryForTest(nil)
			mysqlclient.SetRootQueryForTest(nil)
			mysqlclient.SetRootExecForTest(nil)
			redisinfo.SetMemoryUsageForTest(nil)
			redisinfo.SetKeyspaceStatsForTest(nil)
			redisinfo.SetConfigGetForTest(nil)
		})
	}
}

func splitMockMySQLOutput(out []byte) []string {
	if len(out) == 0 {
		return nil
	}
	var lines []string
	for _, line := range strings.Split(string(out), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func parseMockRedisMemory(out []byte) uint64 {
	return parseMockRedisField(out, "used_memory:")
}

func parseMockRedisField(out []byte, prefix string) uint64 {
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		v, _ := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, prefix)), 10, 64)
		return v
	}
	return 0
}

func parseMockRedisKeyspace(out []byte) redisinfo.KeyspaceStat {
	var stat redisinfo.KeyspaceStat
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "db") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) < 2 {
			continue
		}
		for _, kv := range strings.Split(parts[1], ",") {
			kv = strings.TrimSpace(kv)
			eq := strings.IndexByte(kv, '=')
			if eq < 0 {
				continue
			}
			v, perr := strconv.ParseInt(kv[eq+1:], 10, 64)
			if perr != nil {
				continue
			}
			switch kv[:eq] {
			case "keys":
				stat.TotalKeys += v
			case "expires":
				stat.TotalExpires += v
			}
		}
	}
	return stat
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

func TestProviderInjectionOSWrite(t *testing.T) {
	var captured struct {
		path string
		data []byte
		perm os.FileMode
	}
	withMockOS(t, &mockOS{
		writeFile: func(name string, data []byte, perm os.FileMode) error {
			captured.path = name
			captured.data = data
			captured.perm = perm
			return nil
		},
	})

	if err := osFS.WriteFile("/etc/test.conf", []byte("hello"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if captured.path != "/etc/test.conf" || string(captured.data) != "hello" || captured.perm != 0o644 {
		t.Errorf("captured = %+v", captured)
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
