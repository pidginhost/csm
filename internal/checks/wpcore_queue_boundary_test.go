package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func TestWPCoreQueueWithdrawalRetainsActiveCommands(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		name := "cancel"
		if deadline {
			name = "deadline"
		}
		t.Run(name, func(t *testing.T) {
			wpCoreQueueFixtures(t, 8)
			ctx, cancel := context.WithCancel(context.Background())
			if deadline {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
			}
			defer cancel()
			entered, release := make(chan struct{}, 5), make(chan struct{})
			finish := sync.OnceFunc(func() { close(release) })
			var calls atomic.Int32
			withMockCmd(t, &mockCmd{runContext: func(parent context.Context, name string, args ...string) ([]byte, error) {
				wpCoreQueuePath(t, name, args)
				calls.Add(1)
				entered <- struct{}{}
				<-release
				return nil, parent.Err()
			}})
			scan := startWPCoreQueueScan(t, ctx, finish)
			for range 5 {
				select {
				case <-entered:
				case <-time.After(5 * time.Second):
					t.Fatal("checksum workers did not enter")
				}
			}
			if deadline {
				if q := wpCoreQueueSnapshot(t, time.Now().Add(3*time.Second)); q.InFlight != 5 || q.Depth != 3 || q.Reason != "processing_lag" || q.DroppedTotal != 0 {
					t.Fatalf("short parent deadline not visible: %+v", q)
				}
				select {
				case <-ctx.Done():
				case <-time.After(5 * time.Second):
					t.Fatal("parent deadline did not expire")
				}
			} else {
				cancel()
			}
			if q := wpCoreQueueSnapshot(t, time.Now()); q.InFlight != 5 || q.Depth != 3 || q.DroppedTotal != 0 {
				t.Fatalf("cancellation released commands before they returned: %+v", q)
			}
			finish()
			if findings := scan.wait(t); len(findings) != 0 || calls.Load() != 5 || GlobalCMSCache().Size() != 0 {
				t.Fatalf("withdrawal started extra commands or cached failed verification: calls=%d findings=%+v cache=%d", calls.Load(), findings, GlobalCMSCache().Size())
			}
			var want uint64
			if deadline {
				want = 8
			}
			if q := wpCoreQueueSnapshot(t, time.Now()); q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != want {
				t.Fatalf("withdrawn installations: %+v", q)
			}
		})
	}
}

func TestWPCoreQueueOwnsPostCommandCacheWork(t *testing.T) {
	for _, phase := range []string{"file_read", "cache_write", "unreadable_file"} {
		for _, deadline := range []bool{false, true} {
			ending := "cancel"
			if deadline {
				ending = "deadline"
			}
			t.Run(phase+"/"+ending, func(t *testing.T) {
				roots, fs := wpCoreQueueFixtures(t, 1)
				path := filepath.Join(filepath.Dir(roots[0]), "wp-login.php")
				ctx, cancel := context.WithCancel(context.Background())
				if deadline {
					cancel()
					ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
				}
				defer cancel()
				entered, release := make(chan struct{}), make(chan struct{})
				cache := GlobalCMSCache()
				var finish func()
				if phase == "cache_write" {
					cache.mu.Lock()
					finish = sync.OnceFunc(func() { cache.mu.Unlock() })
					fs.stat = func(name string) (os.FileInfo, error) {
						if name == path {
							close(entered)
						}
						return os.Stat(name)
					}
				} else {
					finish = sync.OnceFunc(func() { close(release) })
					fs.open = func(name string) (*os.File, error) {
						if name == path {
							close(entered)
							<-release
							if phase == "unreadable_file" {
								return nil, os.ErrPermission
							}
						}
						return os.Open(name)
					}
				}
				var calls atomic.Int32
				withMockCmd(t, &mockCmd{runContext: func(_ context.Context, name string, args ...string) ([]byte, error) {
					wpCoreQueuePath(t, name, args)
					calls.Add(1)
					return []byte("Success: WordPress installation verifies against checksums.\n"), nil
				}})
				scan := startWPCoreQueueScan(t, ctx, finish)
				select {
				case <-entered:
				case <-time.After(5 * time.Second):
					t.Fatal("successful checksum did not reach cache work")
				}
				if q := wpCoreQueueSnapshot(t, time.Now().Add(time.Minute+time.Second)); q.Depth != 0 || q.InFlight != 1 || q.DroppedTotal != 0 || q.Reason != "processing_lag" {
					t.Fatalf("post-command work disappeared or lost progress deadline: %+v", q)
				}
				if deadline {
					select {
					case <-ctx.Done():
					case <-time.After(5 * time.Second):
						t.Fatal("parent deadline did not expire")
					}
				} else {
					cancel()
				}
				if q := wpCoreQueueSnapshot(t, time.Now()); q.InFlight != 1 || q.DroppedTotal != 0 {
					t.Fatalf("later cancellation discarded completed verification: %+v", q)
				}
				finish()
				if findings := scan.wait(t); len(findings) != 0 || calls.Load() != 1 {
					t.Fatalf("cache work changed checksum outcome: calls=%d findings=%+v", calls.Load(), findings)
				}
				wantCache := 1
				if phase == "unreadable_file" {
					wantCache = 0
				}
				if cache.Size() != wantCache {
					t.Fatalf("late cache outcome: got=%d want=%d", cache.Size(), wantCache)
				}
				if q := wpCoreQueueSnapshot(t, time.Now()); q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 0 || q.Status != "ok" {
					t.Fatalf("completed verification became a loss during cache work: %+v", q)
				}
			})
		}
	}
}

type wpCoreQueueMarkupFS struct {
	*mockOS
	readPrefix func(string, os.FileInfo, int64) ([]byte, error)
}

func (fs *wpCoreQueueMarkupFS) ReadRegularFilePrefix(path string, expected os.FileInfo, limit int64) ([]byte, error) {
	return fs.readPrefix(path, expected, limit)
}

func TestWPCoreQueueSnapshotAvoidsResultAndFileLocks(t *testing.T) {
	roots, fs := wpCoreQueueFixtures(t, 2)
	for _, root := range roots {
		path := filepath.Join(filepath.Dir(root), "wp-includes", "active.svg")
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("<svg><script>fixture()</script></svg>"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	fs.lstat = func(name string) (os.FileInfo, error) {
		if strings.HasSuffix(name, "active.svg") {
			return os.Stat(name)
		}
		return mockPathInfo(name, roots)
	}
	entered, release := make(chan struct{}, 2), make(chan struct{})
	finish := sync.OnceFunc(func() { close(release) })
	withMockOS(t, &wpCoreQueueMarkupFS{mockOS: fs, readPrefix: func(path string, expected os.FileInfo, limit int64) ([]byte, error) {
		if expected.Size() == 0 || limit != wpCoreMarkupPeekBytes {
			t.Errorf("markup prefix lost its inspected file or bound: size=%d limit=%d", expected.Size(), limit)
		}
		entered <- struct{}{}
		<-release
		return (realOS{}).ReadRegularFilePrefix(path, expected, limit)
	}})
	commands := make(chan struct{}, 2)
	withMockCmd(t, &mockCmd{runContext: func(_ context.Context, name string, args ...string) ([]byte, error) {
		wpCoreQueuePath(t, name, args)
		commands <- struct{}{}
		return []byte("Warning: File doesn't verify against checksum: wp-includes/active.svg\n"), os.ErrInvalid
	}})
	scan := startWPCoreQueueScan(t, context.Background(), finish)
	for range 2 {
		select {
		case <-commands:
		case <-time.After(5 * time.Second):
			t.Fatal("checksum command did not finish")
		}
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("result grading did not enter the file read")
	}
	if q := wpCoreQueueSnapshot(t, time.Now().Add(time.Minute+time.Second)); q.Depth != 0 || q.InFlight != 2 || q.Reason != "processing_lag" || q.DroppedTotal != 0 {
		t.Fatalf("blocked result collection did not retain both installations: %+v", q)
	}
	finish()
	findings := scan.wait(t)
	if len(findings) != 2 {
		t.Fatalf("result collection lost findings: %+v", findings)
	}
	seen := make(map[string]bool)
	for _, finding := range findings {
		if finding.Severity != alert.Critical || finding.Check != "wp_core_integrity" {
			t.Errorf("markup result changed: %+v", finding)
		}
		seen[finding.FilePath] = true
	}
	for _, root := range roots {
		if !seen[filepath.Join(filepath.Dir(root), "wp-includes", "active.svg")] {
			t.Error("installation lost its modified-file finding")
		}
	}
	if q := wpCoreQueueSnapshot(t, time.Now()); q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 0 {
		t.Fatalf("result collection did not settle: %+v", q)
	}
}
