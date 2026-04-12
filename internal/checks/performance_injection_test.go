package checks

import (
	"context"
	"os"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// --- parseMemInfo with mock /proc/meminfo ----------------------------

func TestParseMemInfoMocked(t *testing.T) {
	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			if name == "/proc/meminfo" {
				tmp := t.TempDir() + "/meminfo"
				data := "MemTotal:       16384000 kB\nMemAvailable:    8192000 kB\nSwapTotal:       2048000 kB\nSwapFree:        1024000 kB\n"
				_ = os.WriteFile(tmp, []byte(data), 0644)
				return os.Open(tmp)
			}
			return nil, os.ErrNotExist
		},
	})

	total, avail, swapTotal, swapFree := parseMemInfo()
	if total != 16384000 {
		t.Errorf("total = %d, want 16384000", total)
	}
	if avail != 8192000 {
		t.Errorf("avail = %d", avail)
	}
	if swapTotal != 2048000 {
		t.Errorf("swapTotal = %d", swapTotal)
	}
	if swapFree != 1024000 {
		t.Errorf("swapFree = %d", swapFree)
	}
}

// --- CheckSwapAndOOM with actual memory data -------------------------

func TestCheckSwapAndOOMWithData(t *testing.T) {
	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			if name == "/proc/meminfo" {
				tmp := t.TempDir() + "/meminfo"
				// 90% swap used = should trigger
				data := "MemTotal:       16384000 kB\nMemAvailable:    8192000 kB\nSwapTotal:       2048000 kB\nSwapFree:         100000 kB\n"
				_ = os.WriteFile(tmp, []byte(data), 0644)
				return os.Open(tmp)
			}
			return nil, os.ErrNotExist
		},
	})
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			if name == "dmesg" {
				return []byte(""), nil
			}
			return nil, nil
		},
	})

	findings := CheckSwapAndOOM(context.Background(), &config.Config{}, nil)
	_ = findings
}

// --- CheckMySQLConfig with mysql output ------------------------------

func TestCheckMySQLConfigWithData(t *testing.T) {
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			if name == "mysql" || name == "mysqladmin" {
				return []byte("innodb_buffer_pool_size\t134217728\nmax_connections\t151\nquery_cache_size\t0\n"), nil
			}
			return nil, nil
		},
	})
	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			if name == "/proc/meminfo" {
				tmp := t.TempDir() + "/meminfo"
				_ = os.WriteFile(tmp, []byte("MemTotal: 4096000 kB\n"), 0644)
				return os.Open(tmp)
			}
			return nil, os.ErrNotExist
		},
	})

	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	findings := CheckMySQLConfig(context.Background(), &config.Config{}, store)
	_ = findings
}

// --- CheckRedisConfig with redis output ------------------------------

func TestCheckRedisConfigWithData(t *testing.T) {
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			if name == "redis-cli" {
				return []byte("maxmemory:0\nmaxmemory_policy:noeviction\nrequirepass:\n"), nil
			}
			return nil, nil
		},
	})
	withMockOS(t, &mockOS{})

	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	findings := CheckRedisConfig(context.Background(), &config.Config{}, store)
	_ = findings
}

// --- CheckPHPProcessLoad with proc data ------------------------------

func TestCheckPHPProcessLoadWithData(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			return []string{"/proc/1234/cmdline"}, nil
		},
		readFile: func(name string) ([]byte, error) {
			if name == "/proc/1234/cmdline" {
				return []byte("php-fpm: pool www\x00"), nil
			}
			if name == "/proc/1234/status" {
				return []byte("Name:\tphp-fpm\nVmRSS:\t102400 kB\nUid:\t1000\n"), nil
			}
			return nil, os.ErrNotExist
		},
		open: func(name string) (*os.File, error) {
			if name == "/proc/cpuinfo" {
				tmp := t.TempDir() + "/cpuinfo"
				_ = os.WriteFile(tmp, []byte("processor\t: 0\nprocessor\t: 1\n"), 0644)
				return os.Open(tmp)
			}
			if name == "/proc/meminfo" {
				tmp := t.TempDir() + "/meminfo"
				_ = os.WriteFile(tmp, []byte("MemTotal: 4096000 kB\n"), 0644)
				return os.Open(tmp)
			}
			return nil, os.ErrNotExist
		},
	})
	withMockCmd(t, &mockCmd{})

	findings := CheckPHPProcessLoad(context.Background(), &config.Config{}, nil)
	_ = findings
}
