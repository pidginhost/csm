package checks

import (
	"context"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

func newCrontabTestStore(t *testing.T) *state.Store {
	t.Helper()

	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestCheckCrontabs_RanksUserCrontabsByMtime(t *testing.T) {
	store := newCrontabTestStore(t)
	now := time.Now()
	paths := []string{"/var/spool/cron/aaa-customer", "/var/spool/cron/zzz-customer"}
	var readOrder []string

	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			switch pattern {
			case "/var/spool/cron/*":
				return paths, nil
			case "/etc/cron.d/*":
				return nil, nil
			default:
				return nil, nil
			}
		},
		stat: mtimesByPath(map[string]time.Time{
			paths[0]: now.Add(-24 * time.Hour),
			paths[1]: now,
		}),
		readFile: func(name string) ([]byte, error) {
			readOrder = append(readOrder, name)
			return []byte("MAILTO=\"\"\n0 0 * * * /usr/bin/true\n"), nil
		},
	})

	findings := CheckCrontabs(context.Background(), nil, store)

	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none", findings)
	}
	want := []string{paths[1], paths[0]}
	if !reflect.DeepEqual(readOrder, want) {
		t.Fatalf("read order = %v, want %v", readOrder, want)
	}
}

func TestCheckCrontabsAccountCapDoesNotDropRoot(t *testing.T) {
	store := newCrontabTestStore(t)
	now := time.Now()
	rootPath := "/var/spool/cron/root"
	recentPath := "/var/spool/cron/zzz-customer"
	store.SetRaw("_crontab_root_hash", hashBytes([]byte("old root\n")))

	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			switch pattern {
			case "/var/spool/cron/*":
				return []string{rootPath, recentPath}, nil
			case "/etc/cron.d/*":
				return nil, nil
			default:
				return nil, nil
			}
		},
		stat: mtimesByPath(map[string]time.Time{
			rootPath:   now.Add(-24 * time.Hour),
			recentPath: now.Add(-1 * time.Minute),
		}),
		readFile: func(name string) ([]byte, error) {
			switch name {
			case rootPath:
				return []byte("new root\n"), nil
			case recentPath:
				return []byte("MAILTO=\"\"\n0 0 * * * /usr/bin/true\n"), nil
			default:
				return nil, os.ErrNotExist
			}
		},
	})

	cfg := &config.Config{}
	cfg.Thresholds.AccountScanMaxFiles = 1
	findings := CheckCrontabs(context.Background(), cfg, store)

	foundRootChange := false
	for _, finding := range findings {
		if finding.Check == "crontab_change" {
			foundRootChange = true
			break
		}
	}
	if !foundRootChange {
		t.Fatalf("root crontab change was hidden by account_scan_max_files=1: %+v", findings)
	}
}

func TestCheckCrontabsCronDIsNotAccountCapped(t *testing.T) {
	store := newCrontabTestStore(t)
	now := time.Now()
	oldPath := "/etc/cron.d/aaa-old"
	recentPath := "/etc/cron.d/zzz-recent"
	store.SetRaw("_crond:aaa-old", hashBytes([]byte("old job\n")))

	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			switch pattern {
			case "/var/spool/cron/*":
				return nil, nil
			case "/etc/cron.d/*":
				return []string{oldPath, recentPath}, nil
			default:
				return nil, nil
			}
		},
		stat: mtimesByPath(map[string]time.Time{
			oldPath:    now.Add(-24 * time.Hour),
			recentPath: now.Add(-1 * time.Minute),
		}),
		readFile: func(name string) ([]byte, error) {
			switch name {
			case oldPath:
				return []byte("changed job\n"), nil
			case recentPath:
				return []byte("new job\n"), nil
			default:
				return nil, os.ErrNotExist
			}
		},
	})

	cfg := &config.Config{}
	cfg.Thresholds.AccountScanMaxFiles = 1
	findings := CheckCrontabs(context.Background(), cfg, store)

	foundOldCronDChange := false
	for _, finding := range findings {
		if finding.Check == "crond_change" && finding.Message == "Cron.d file modified: "+oldPath {
			foundOldCronDChange = true
			break
		}
	}
	if !foundOldCronDChange {
		t.Fatalf("cron.d change was hidden by account_scan_max_files=1: %+v", findings)
	}
}

func TestCheckCrontabs_ContextCancelDuringRankingStopsBeforeCronD(t *testing.T) {
	store := newCrontabTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var globbed []string

	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			globbed = append(globbed, pattern)
			if pattern == "/var/spool/cron/*" {
				return []string{"/var/spool/cron/alice", "/var/spool/cron/bob"}, nil
			}
			return nil, nil
		},
		stat: func(name string) (os.FileInfo, error) {
			cancel()
			return statWithMtime{name: name, modTime: time.Now()}, nil
		},
		readFile: func(name string) ([]byte, error) {
			t.Fatalf("ReadFile(%q) called after context cancellation", name)
			return nil, os.ErrNotExist
		},
	})

	findings := CheckCrontabs(ctx, nil, store)

	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none", findings)
	}
	if !reflect.DeepEqual(globbed, []string{"/var/spool/cron/*"}) {
		t.Fatalf("globbed = %v, want only /var/spool/cron/*", globbed)
	}
}

func TestCheckCrontabs_ContextCancelAfterRootReadLeavesBaseline(t *testing.T) {
	store := newCrontabTestStore(t)
	store.SetRaw("_crontab_root_hash", "oldhash")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == "/var/spool/cron/*" {
				return []string{"/var/spool/cron/root"}, nil
			}
			return nil, nil
		},
		stat: mtimesByPath(map[string]time.Time{
			"/var/spool/cron/root": time.Now(),
		}),
		readFile: func(name string) ([]byte, error) {
			cancel()
			return []byte("* * * * * /usr/bin/new-job\n"), nil
		},
	})

	findings := CheckCrontabs(ctx, nil, store)

	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none after cancellation", findings)
	}
	got, ok := store.GetRaw("_crontab_root_hash")
	if !ok || got != "oldhash" {
		t.Fatalf("root baseline = %q, %v; want oldhash, true", got, ok)
	}
}

func TestCheckCrontabs_RootReadErrorLeavesBaseline(t *testing.T) {
	store := newCrontabTestStore(t)
	store.SetRaw("_crontab_root_hash", "oldhash")

	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == "/var/spool/cron/*" {
				return []string{"/var/spool/cron/root"}, nil
			}
			return nil, nil
		},
		stat: mtimesByPath(map[string]time.Time{
			"/var/spool/cron/root": time.Now(),
		}),
		readFile: func(name string) ([]byte, error) {
			return nil, os.ErrPermission
		},
	})

	findings := CheckCrontabs(context.Background(), nil, store)

	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none for unreadable root crontab", findings)
	}
	got, ok := store.GetRaw("_crontab_root_hash")
	if !ok || got != "oldhash" {
		t.Fatalf("root baseline = %q, %v; want oldhash, true", got, ok)
	}
}

func TestCheckCrontabs_CronDReadErrorLeavesBaseline(t *testing.T) {
	store := newCrontabTestStore(t)
	store.SetRaw("_crond:myjob", "oldhash")

	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			switch pattern {
			case "/var/spool/cron/*":
				return nil, nil
			case "/etc/cron.d/*":
				return []string{"/etc/cron.d/myjob"}, nil
			default:
				return nil, nil
			}
		},
		stat: mtimesByPath(map[string]time.Time{
			"/etc/cron.d/myjob": time.Now(),
		}),
		readFile: func(name string) ([]byte, error) {
			return nil, os.ErrPermission
		},
	})

	findings := CheckCrontabs(context.Background(), nil, store)

	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none for unreadable cron.d file", findings)
	}
	got, ok := store.GetRaw("_crond:myjob")
	if !ok || got != "oldhash" {
		t.Fatalf("cron.d baseline = %q, %v; want oldhash, true", got, ok)
	}
}
