package checks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/queuehealth"
)

func fileIndexQueueFixture(t *testing.T) (*config.Config, *mockOS) {
	t.Helper()
	previous := fileIndexQueues
	fileIndexQueues = newFileIndexQueue()
	t.Cleanup(func() { fileIndexQueues = previous })
	atomic.StoreInt32(&fileIndexScanCount, 0)
	setFileIndexShrinkSkips(t, 0)
	cfg := &config.Config{StatePath: t.TempDir()}
	files := phpDirEntries("c99.php")
	var unused int64
	fs := stateAwareFileIndexMock(cfg.StatePath, "/home/alice/public_html/wp-content/uploads", &files, &unused)
	fs.stat = func(name string) (os.FileInfo, error) {
		if strings.HasPrefix(name, cfg.StatePath) {
			return os.Stat(name)
		}
		return &fakeFileInfoMtime{name: filepath.Base(name), dir: true, mode: 0755, mtime: time.Unix(100, 0)}, nil
	}
	contentPath := filepath.Join(t.TempDir(), "content.php")
	if err := os.WriteFile(contentPath, []byte("<?php echo 'ready';"), 0600); err != nil {
		t.Fatal(err)
	}
	open := fs.open
	fs.open = func(name string) (*os.File, error) {
		if name == "/home/alice/public_html/wp-content/uploads/c99.php" {
			return os.Open(contentPath)
		}
		return open(name)
	}
	withMockOS(t, fs)
	return cfg, fs
}

func fileIndexQueueRows(t *testing.T, now time.Time) map[string]queuehealth.Status {
	t.Helper()
	done := make(chan map[string]queuehealth.Status, 1)
	go func() { done <- FileIndexQueueStatuses(now) }()
	select {
	case rows := <-done:
		return rows
	case <-time.After(time.Second):
		t.Fatal("file-index health waited on filesystem or gate")
		return nil
	}
}

func waitFileIndexQueue(t *testing.T, waiting, active int) map[string]queuehealth.Status {
	t.Helper()
	until := time.Now().Add(3 * time.Second)
	for {
		rows := fileIndexQueueRows(t, time.Now())
		if rows["waiting"].Depth == waiting && rows["active"].InFlight == active {
			return rows
		}
		if !time.Now().Before(until) {
			t.Fatalf("want waiting=%d active=%d, got %+v", waiting, active, rows)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestFileIndexQueueWaitingAndActiveBudgets(t *testing.T) {
	cfg, fs := fileIndexQueueFixture(t)
	readDir := fs.readDir
	entered, release := make(chan struct{}), make(chan struct{})
	finish := sync.OnceFunc(func() { close(release) })
	defer finish()
	var homeReads atomic.Int32
	fs.readDir = func(name string) ([]os.DirEntry, error) {
		if name == "/home" && homeReads.Add(1) == 1 {
			close(entered)
			<-release
		}
		return readDir(name)
	}
	done := make(chan []alert.Finding, 2)
	go func() { done <- CheckFileIndex(context.Background(), cfg, nil) }()
	joined := 0
	defer func() {
		finish()
		for joined < 2 {
			select {
			case <-done:
				joined++
			case <-time.After(3 * time.Second):
				t.Error("live scans did not join")
				return
			}
		}
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("live walk did not start")
	}
	go func() { done <- CheckFileIndex(context.Background(), cfg, nil) }()
	waitFileIndexQueue(t, 1, 1)
	rows := fileIndexQueueRows(t, time.Now().Add(61*time.Second))
	if rows["waiting"].Status != "ok" || rows["active"].Status != "ok" || rows["active"].Capacity != 1 || !rows["waiting"].CapacityUnavailable {
		t.Fatalf("valid long scan looked full or stalled: %+v", rows)
	}
	rows = fileIndexQueueRows(t, time.Now().Add(16*time.Minute))
	if rows["active"].Reason != "processing_lag" || rows["waiting"].Reason != "backlog_lag" {
		t.Fatalf("overdue live scan and waiting demand hidden: %+v", rows)
	}
	finish()
	for range 2 {
		select {
		case findings := <-done:
			joined++
			if len(findings) != 0 {
				t.Fatalf("initial baseline or unchanged scan emitted findings: %+v", findings)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("live scans did not finish")
		}
	}
	for _, name := range []string{"fileindex.current", "fileindex.previous"} {
		data, err := os.ReadFile(filepath.Join(cfg.StatePath, name))
		if err != nil || string(data) != "/home/alice/public_html/wp-content/uploads/c99.php\n" {
			t.Fatalf("wrong completed %s: %q error=%v", name, data, err)
		}
	}
	if homeReads.Load() != 2 {
		t.Fatalf("live scans did not execute exactly once each: %d", homeReads.Load())
	}
	rows = fileIndexQueueRows(t, time.Now())
	if rows["waiting"].Depth != 0 || rows["active"].InFlight != 0 || rows["waiting"].DroppedTotal != 0 || rows["active"].DroppedTotal != 0 {
		t.Fatalf("live scan ownership leaked or successful work counted lost: %+v", rows)
	}
}

func TestFileIndexQueueWaiterWithdrawal(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel", true: "deadline"}[deadline], func(t *testing.T) {
			cfg, fs := fileIndexQueueFixture(t)
			readDir := fs.readDir
			entered, release := make(chan struct{}), make(chan struct{})
			finish := sync.OnceFunc(func() { close(release) })
			defer finish()
			var homeReads atomic.Int32
			fs.readDir = func(name string) ([]os.DirEntry, error) {
				if name == "/home" && homeReads.Add(1) == 1 {
					close(entered)
					<-release
				}
				return readDir(name)
			}
			activeDone := make(chan []alert.Finding, 1)
			go func() { activeDone <- CheckFileIndex(context.Background(), cfg, nil) }()
			joined := false
			defer func() {
				finish()
				if !joined {
					select {
					case <-activeDone:
					case <-time.After(3 * time.Second):
						t.Error("active scan did not join")
					}
				}
			}()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("active scan did not enter")
			}
			ctx, cancel := context.WithCancel(context.Background())
			if deadline {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
			}
			defer cancel()
			done := make(chan []alert.Finding, 1)
			go func() { done <- CheckFileIndex(ctx, cfg, nil) }()
			waitFileIndexQueue(t, 1, 1)
			if deadline {
				if rows := fileIndexQueueRows(t, time.Now().Add(time.Second)); rows["waiting"].Reason != "backlog_lag" || rows["active"].Status != "ok" {
					t.Fatalf("waiter borrowed active deadline: %+v", rows)
				}
				<-ctx.Done()
			} else {
				cancel()
			}
			select {
			case findings := <-done:
				if len(findings) != 0 {
					t.Fatalf("withdrawn waiter produced findings: %+v", findings)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("waiter ignored withdrawal")
			}
			wantLoss := uint64(0)
			if deadline {
				wantLoss = 1
			}
			rows := fileIndexQueueRows(t, time.Now())
			if rows["waiting"].Depth != 0 || rows["waiting"].DroppedTotal != wantLoss || rows["active"].InFlight != 1 || rows["active"].DroppedTotal != 0 || homeReads.Load() != 1 {
				t.Fatalf("withdrawal changed actual scan: reads=%d rows=%+v", homeReads.Load(), rows)
			}
			finish()
			select {
			case findings := <-activeDone:
				joined = true
				if len(findings) != 0 {
					t.Fatalf("first scan emitted findings: %+v", findings)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("active scan did not finish")
			}
			rows = fileIndexQueueRows(t, time.Now().Add(time.Minute))
			if rows["waiting"].Status != "ok" || rows["waiting"].DroppedTotal != wantLoss || rows["active"].InFlight != 0 {
				t.Fatalf("recovery lost evidence or retained work: %+v", rows)
			}
		})
	}
}

func TestFileIndexQueueCanceledWalkRetainsActualOwner(t *testing.T) {
	for _, mode := range []string{"cancel", "deadline", "read_error_after_cancel"} {
		t.Run(mode, func(t *testing.T) {
			cfg, fs := fileIndexQueueFixture(t)
			readDir := fs.readDir
			entered, release := make(chan struct{}), make(chan struct{})
			finish := sync.OnceFunc(func() { close(release) })
			defer finish()
			fs.readDir = func(name string) ([]os.DirEntry, error) {
				if name == "/home" {
					close(entered)
					<-release
					if mode == "read_error_after_cancel" {
						return nil, os.ErrPermission
					}
				}
				return readDir(name)
			}
			ctx, cancel := context.WithCancel(context.Background())
			if mode == "deadline" {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
			}
			defer cancel()
			done := make(chan []alert.Finding, 1)
			go func() { done <- CheckFileIndex(ctx, cfg, nil) }()
			joined := false
			defer func() {
				finish()
				if !joined {
					select {
					case <-done:
					case <-time.After(3 * time.Second):
						t.Error("canceled scan did not join")
					}
				}
			}()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("scan did not start")
			}
			if mode == "deadline" {
				<-ctx.Done()
			} else {
				cancel()
			}
			rows := fileIndexQueueRows(t, time.Now())
			if rows["active"].InFlight != 1 || rows["active"].DroppedTotal != 0 {
				t.Fatalf("cancellation hid actual filesystem operation: %+v", rows)
			}
			if mode == "deadline" && rows["active"].Reason != "processing_lag" {
				t.Fatalf("actual work ignored expired parent: %+v", rows)
			}
			finish()
			select {
			case findings := <-done:
				joined = true
				if len(findings) != 0 {
					t.Fatalf("partial walk produced findings: %+v", findings)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("canceled scan did not finish")
			}
			wantLoss := uint64(0)
			if mode != "cancel" {
				wantLoss = 1
			}
			rows = fileIndexQueueRows(t, time.Now())
			if rows["active"].InFlight != 0 || rows["active"].DroppedTotal != wantLoss || atomic.LoadInt32(&fileIndexScanCount) != 0 {
				t.Fatalf("canceled walk failed settlement/reset: %+v", rows)
			}
			for _, name := range []string{"fileindex.current", "fileindex.previous", "dircache.json"} {
				if _, err := os.Stat(filepath.Join(cfg.StatePath, name)); !os.IsNotExist(err) {
					t.Fatalf("canceled scan wrote %s: %v", name, err)
				}
			}
		})
	}
}

func TestFileIndexQueueFailuresCountOnce(t *testing.T) {
	for _, failure := range []string{"walk", "cache_read", "cache_decode", "index_read", "index_scan", "cache_write", "cache_rename", "index_create", "index_rename", "copy_read", "copy_write"} {
		t.Run(failure, func(t *testing.T) {
			cfg, fs := fileIndexQueueFixture(t)
			previous := filepath.Join(cfg.StatePath, "fileindex.previous")
			if err := os.WriteFile(previous, nil, 0600); err != nil {
				t.Fatal(err)
			}
			readDir, readFile, open := fs.readDir, fs.readFile, fs.open
			switch failure {
			case "walk":
				fs.readDir = func(name string) ([]os.DirEntry, error) {
					if name == "/home/alice" {
						return nil, os.ErrPermission
					}
					return readDir(name)
				}
			case "cache_read":
				fs.readFile = func(name string) ([]byte, error) {
					if filepath.Base(name) == "dircache.json" {
						return nil, os.ErrPermission
					}
					return readFile(name)
				}
			case "cache_decode":
				if err := os.WriteFile(filepath.Join(cfg.StatePath, "dircache.json"), []byte("invalid"), 0600); err != nil {
					t.Fatal(err)
				}
			case "index_read":
				fs.open = func(name string) (*os.File, error) {
					if name == previous {
						return nil, os.ErrPermission
					}
					return open(name)
				}
			case "index_scan":
				fs.open = func(name string) (*os.File, error) {
					if name == previous {
						return os.Open(cfg.StatePath)
					}
					return open(name)
				}
			case "cache_write", "cache_rename", "index_create", "index_rename":
				target := map[string]string{"cache_write": "dircache.json.tmp", "cache_rename": "dircache.json", "index_create": "fileindex.current.tmp", "index_rename": "fileindex.current"}[failure]
				if err := os.Mkdir(filepath.Join(cfg.StatePath, target), 0700); err != nil {
					t.Fatal(err)
				}
				if failure == "cache_rename" {
					fs.readFile = func(name string) ([]byte, error) {
						if filepath.Base(name) == target {
							return nil, os.ErrNotExist
						}
						return readFile(name)
					}
				}
			case "copy_read":
				fs.readFile = func(name string) ([]byte, error) {
					if filepath.Base(name) == "fileindex.current" {
						return nil, errors.New("fixture copy read failure")
					}
					return readFile(name)
				}
			case "copy_write":
				fs.readFile = func(name string) ([]byte, error) {
					data, err := readFile(name)
					if filepath.Base(name) == "fileindex.current" {
						if renameErr := os.Rename(previous, previous+".saved"); renameErr != nil {
							t.Error(renameErr)
						}
						if mkdirErr := os.Mkdir(previous, 0700); mkdirErr != nil {
							t.Error(mkdirErr)
						}
					}
					return data, err
				}
			}
			findings := CheckFileIndex(context.Background(), cfg, nil)
			if len(findings) != 1 || findings[0].Check != "new_webshell_file" || findings[0].FilePath != "/home/alice/public_html/wp-content/uploads/c99.php" {
				t.Fatalf("failure discarded or changed actual finding: %+v", findings)
			}
			rows := fileIndexQueueRows(t, time.Now())
			if rows["waiting"].Depth != 0 || rows["active"].InFlight != 0 || rows["active"].DroppedTotal != 1 || rows["active"].RecentDrops != 1 || rows["active"].Status != "ok" {
				t.Fatalf("failed work not counted once: %+v", rows)
			}
			if failure == "walk" {
				data, err := os.ReadFile(previous)
				if err != nil || len(data) != 0 || atomic.LoadInt32(&fileIndexScanCount) != 0 {
					t.Fatalf("incomplete walk advanced baseline: %q %v", data, err)
				}
			}
			if failure == "cache_write" {
				if _, err := os.Stat(filepath.Join(cfg.StatePath, "dircache.json")); !os.IsNotExist(err) {
					t.Fatalf("failed cache write promoted its temporary directory: %v", err)
				}
			}
			if rows := fileIndexQueueRows(t, time.Now().Add(time.Minute)); rows["active"].Status != "ok" || rows["active"].DroppedTotal != 1 {
				t.Fatalf("recovery cleared evidence: %+v", rows)
			}
		})
	}
}

func TestFileIndexQueueLateBaselineCommitIsSuccessful(t *testing.T) {
	cfg, fs := fileIndexQueueFixture(t)
	readFile := fs.readFile
	entered, release := make(chan struct{}), make(chan struct{})
	finish := sync.OnceFunc(func() { close(release) })
	defer finish()
	fs.readFile = func(name string) ([]byte, error) {
		if filepath.Base(name) == "fileindex.current" {
			close(entered)
			<-release
		}
		return readFile(name)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	done := make(chan []alert.Finding, 1)
	go func() { done <- CheckFileIndex(ctx, cfg, nil) }()
	joined := false
	defer func() {
		finish()
		if !joined {
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("late commit did not join")
			}
		}
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("baseline copy did not start")
	}
	<-ctx.Done()
	rows := fileIndexQueueRows(t, time.Now())
	if rows["active"].InFlight != 1 || rows["active"].Status != "ok" || rows["active"].DroppedTotal != 0 {
		t.Fatalf("late baseline copy was hidden or failed: %+v", rows)
	}
	if rows := fileIndexQueueRows(t, time.Now().Add(61*time.Second)); rows["active"].Reason != "processing_lag" {
		t.Fatalf("baseline copy has no local stall budget: %+v", rows)
	}
	finish()
	select {
	case findings := <-done:
		joined = true
		if len(findings) != 0 {
			t.Fatalf("initial baseline emitted findings: %+v", findings)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("baseline did not finish")
	}
	data, err := os.ReadFile(filepath.Join(cfg.StatePath, "fileindex.previous"))
	if err != nil || string(data) != "/home/alice/public_html/wp-content/uploads/c99.php\n" {
		t.Fatalf("late baseline was not committed: %q %v", data, err)
	}
	if rows := fileIndexQueueRows(t, time.Now()); rows["active"].InFlight != 0 || rows["active"].DroppedTotal != 0 {
		t.Fatalf("completed late baseline counted lost: %+v", rows)
	}
}

func TestFileIndexQueueAbnormalWalkReleasesGate(t *testing.T) {
	cfg, fs := fileIndexQueueFixture(t)
	readDir := fs.readDir
	fs.readDir = func(name string) ([]os.DirEntry, error) {
		if name == "/home" {
			runtime.Goexit()
		}
		return readDir(name)
	}
	done := make(chan struct{})
	go func() { defer close(done); CheckFileIndex(context.Background(), cfg, nil) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("abnormal scan did not finish")
	}
	rows := fileIndexQueueRows(t, time.Now())
	if rows["active"].InFlight != 0 || rows["active"].DroppedTotal != 1 || len(fileIndexLiveScanGate) != 0 {
		t.Fatalf("abnormal scan leaked ownership: %+v", rows)
	}
	fs.readDir = readDir
	if findings := CheckFileIndex(context.Background(), cfg, nil); len(findings) != 0 {
		t.Fatalf("recovery scan emitted initial findings: %+v", findings)
	}
	if rows := fileIndexQueueRows(t, time.Now().Add(time.Minute)); rows["active"].Status != "ok" || rows["active"].DroppedTotal != 1 {
		t.Fatalf("recovery failed: %+v", rows)
	}
}

func TestFileIndexQueueRepeatedFailuresDegradeAndRecover(t *testing.T) {
	cfg, fs := fileIndexQueueFixture(t)
	readFile := fs.readFile
	fs.readFile = func(name string) ([]byte, error) {
		if filepath.Base(name) == "dircache.json" {
			return nil, os.ErrPermission
		}
		return readFile(name)
	}
	for range 3 {
		if findings := CheckFileIndex(context.Background(), cfg, nil); len(findings) != 0 {
			t.Fatalf("first or unchanged baseline emitted findings: %+v", findings)
		}
	}
	rows := fileIndexQueueRows(t, time.Now())
	if rows["active"].DroppedTotal != 3 || rows["active"].RecentDrops != 3 || rows["active"].Reason != "dropped_work" || rows["active"].InFlight != 0 {
		t.Fatalf("repeated failed scans stayed healthy: %+v", rows)
	}
	fs.readFile = readFile
	if findings := CheckFileIndex(context.Background(), cfg, nil); len(findings) != 0 {
		t.Fatalf("recovery changed findings: %+v", findings)
	}
	rows = fileIndexQueueRows(t, time.Now().Add(time.Minute))
	if rows["active"].Status != "ok" || rows["active"].RecentDrops != 0 || rows["active"].DroppedTotal != 3 {
		t.Fatalf("recovered scans lost failure evidence: %+v", rows)
	}
}

type fileIndexCleanupContext struct {
	context.Context
	armed   atomic.Bool
	entered chan struct{}
	release <-chan struct{}
}

func (c *fileIndexCleanupContext) Err() error {
	if c.armed.Load() {
		close(c.entered)
		<-c.release
	}
	return nil
}

func TestFileIndexQueueCleanupHasItsOwnBudget(t *testing.T) {
	cfg, fs := fileIndexQueueFixture(t)
	release := make(chan struct{})
	finish := sync.OnceFunc(func() { close(release) })
	defer finish()
	ctx := &fileIndexCleanupContext{Context: context.Background(), entered: make(chan struct{}), release: release}
	readDir, stat := fs.readDir, fs.stat
	fs.readDir = func(name string) ([]os.DirEntry, error) {
		if name == "/home/alice" {
			return nil, os.ErrPermission
		}
		return readDir(name)
	}
	fs.stat = func(name string) (os.FileInfo, error) {
		if name == "/home/alice/public_html/wp-content/uploads/c99.php" {
			ctx.armed.Store(true)
		}
		return stat(name)
	}
	done := make(chan []alert.Finding, 1)
	go func() { done <- CheckFileIndex(ctx, cfg, nil) }()
	joined := false
	defer func() {
		finish()
		if !joined {
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("scan cleanup did not join")
			}
		}
	}()
	select {
	case <-ctx.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("deferred scan cleanup did not enter")
	}
	rows := fileIndexQueueRows(t, time.Now().Add(61*time.Second))
	if rows["active"].InFlight != 1 || rows["active"].DroppedTotal != 1 || rows["active"].Reason != "processing_lag" {
		t.Errorf("cleanup borrowed the walk's longer deadline: %+v", rows)
	}
	finish()
	select {
	case findings := <-done:
		joined = true
		if len(findings) != 1 || findings[0].Check != "new_webshell_file" {
			t.Fatalf("cleanup discarded actual finding: %+v", findings)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("scan cleanup did not finish")
	}
	if rows := fileIndexQueueRows(t, time.Now()); rows["active"].InFlight != 0 || rows["active"].DroppedTotal != 1 {
		t.Fatalf("cleanup leaked owner or duplicated loss: %+v", rows)
	}
}

func TestFileIndexQueueAuditBypassesOccupiedLiveSlot(t *testing.T) {
	cfg, fs := fileIndexQueueFixture(t)
	readDir := fs.readDir
	entered, release := make(chan struct{}), make(chan struct{})
	finish := sync.OnceFunc(func() { close(release) })
	defer finish()
	var homeReads atomic.Int32
	fs.readDir = func(name string) ([]os.DirEntry, error) {
		if name == "/home" && homeReads.Add(1) == 1 {
			close(entered)
			<-release
		}
		return readDir(name)
	}
	done := make(chan []alert.Finding, 1)
	go func() { done <- CheckFileIndex(context.Background(), cfg, nil) }()
	joined := false
	defer func() {
		finish()
		if !joined {
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("live scan did not join")
			}
		}
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("live walk did not start")
	}
	auditDone := make(chan []alert.Finding, 1)
	auditCtx := ContextWithScanOptions(context.Background(), AccountScanOptions{ForceFileIndex: true})
	go func() { auditDone <- CheckFileIndex(auditCtx, cfg, nil) }()
	select {
	case findings := <-auditDone:
		if len(findings) != 1 || findings[0].Check != "new_webshell_file" {
			t.Fatalf("audit missed actual file: %+v", findings)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("audit waited behind live slot")
	}
	for _, name := range []string{"fileindex.current", "fileindex.previous", "dircache.json"} {
		if _, err := os.Stat(filepath.Join(cfg.StatePath, name)); !os.IsNotExist(err) {
			t.Fatalf("audit changed live state %s: %v", name, err)
		}
	}
	if rows := fileIndexQueueRows(t, time.Now()); rows["active"].InFlight != 1 || rows["waiting"].Depth != 0 || rows["active"].DroppedTotal != 0 {
		t.Fatalf("audit changed live ownership: %+v", rows)
	}
	finish()
	select {
	case findings := <-done:
		joined = true
		if len(findings) != 0 {
			t.Fatalf("first live baseline emitted findings: %+v", findings)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("live scan did not finish")
	}
}

type fileIndexAdmissionContext struct {
	context.Context
	entered chan struct{}
	release <-chan struct{}
}

func (c fileIndexAdmissionContext) Done() <-chan struct{} {
	close(c.entered)
	<-c.release
	return nil
}

func TestFileIndexQueueAdmissionBudgetStartsWhenSlotFrees(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg, fs := fileIndexQueueFixture(t)
		readDir := fs.readDir
		entered, release := make(chan struct{}), make(chan struct{})
		finish := sync.OnceFunc(func() { close(release) })
		defer finish()
		var homeReads atomic.Int32
		fs.readDir = func(name string) ([]os.DirEntry, error) {
			if name == "/home" && homeReads.Add(1) == 1 {
				close(entered)
				<-release
			}
			return readDir(name)
		}
		first := make(chan []alert.Finding, 1)
		go func() { first <- CheckFileIndex(context.Background(), cfg, nil) }()
		<-entered
		admissionRelease := make(chan struct{})
		finishAdmission := sync.OnceFunc(func() { close(admissionRelease) })
		defer finishAdmission()
		ctx := fileIndexAdmissionContext{Context: context.Background(), entered: make(chan struct{}), release: admissionRelease}
		second := make(chan []alert.Finding, 1)
		go func() { second <- CheckFileIndex(ctx, cfg, nil) }()
		<-ctx.entered
		time.Sleep(2 * time.Minute)
		finish()
		if findings := <-first; len(findings) != 0 {
			t.Fatalf("initial baseline emitted findings: %+v", findings)
		}
		synctest.Wait()
		rows := fileIndexQueueRows(t, time.Now())
		if rows["waiting"].Depth != 1 || rows["waiting"].Status != "ok" || rows["active"].InFlight != 0 {
			t.Errorf("time spent behind healthy scan caused immediate admission lag: %+v", rows)
		}
		time.Sleep(61 * time.Second)
		rows = fileIndexQueueRows(t, time.Now())
		if rows["waiting"].Reason != "backlog_lag" {
			t.Errorf("free slot admission stall hidden: %+v", rows)
		}
		finishAdmission()
		if findings := <-second; len(findings) != 0 {
			t.Fatalf("unchanged baseline emitted findings: %+v", findings)
		}
		rows = fileIndexQueueRows(t, time.Now())
		if rows["waiting"].Depth != 0 || rows["active"].InFlight != 0 || rows["waiting"].DroppedTotal != 0 || rows["active"].DroppedTotal != 0 {
			t.Fatalf("admission recovery leaked work: %+v", rows)
		}
	})
}

func TestFileIndexQueueUnreadableContentLoss(t *testing.T) {
	for _, tc := range []struct{ dir, check string }{
		{"uploads", "new_php_in_uploads"},
		{"languages", "new_php_in_sensitive_dir"},
		{"upgrade", "new_php_in_sensitive_dir"},
	} {
		t.Run(tc.dir, func(t *testing.T) {
			cfg, fs := fileIndexQueueFixture(t)
			previous := filepath.Join(cfg.StatePath, "fileindex.previous")
			if err := os.WriteFile(previous, nil, 0600); err != nil {
				t.Fatal(err)
			}
			uploads := "/home/alice/public_html/wp-content/" + tc.dir
			readDir, stat, open := fs.readDir, fs.stat, fs.open
			var cycle int
			var attempts int
			var currentPath string
			fs.readDir = func(name string) ([]os.DirEntry, error) {
				if name == uploads {
					return phpDirEntries(filepath.Base(currentPath)), nil
				}
				if name == "/home/alice/public_html/wp-content/uploads" {
					return nil, nil
				}
				return readDir(name)
			}
			fs.stat = func(name string) (os.FileInfo, error) {
				if name == uploads {
					return &fakeFileInfoMtime{name: "uploads", dir: true, mode: 0755, mtime: time.Unix(100+int64(cycle), 0)}, nil
				}
				return stat(name)
			}
			fs.open = func(name string) (*os.File, error) {
				if name == currentPath {
					attempts++
					return nil, os.ErrPermission
				}
				return open(name)
			}
			for cycle = 1; cycle <= 3; cycle++ {
				currentPath = filepath.Join(uploads, fmt.Sprintf("ordinary-loader-%d.php", cycle))
				findings := CheckFileIndex(context.Background(), cfg, nil)
				if len(findings) != 1 || findings[0].Check != tc.check || findings[0].Severity != alert.High || findings[0].FilePath != currentPath || !strings.Contains(findings[0].Message, "unreadable") {
					t.Fatalf("existing fail-closed verdict changed: %+v", findings)
				}
			}
			if attempts != 3 {
				t.Fatalf("actual content opens=%d, want 3", attempts)
			}
			rows := fileIndexQueueRows(t, time.Now())
			if rows["active"].InFlight != 0 || rows["active"].DroppedTotal != 3 || rows["active"].Reason != "dropped_work" {
				t.Errorf("failed content analysis stayed healthy: %+v", rows)
			}
		})
	}
}

type fileIndexQueueMetadataEntry struct {
	calls *atomic.Int32
	err   error
}

func (fileIndexQueueMetadataEntry) Name() string      { return "worker" }
func (fileIndexQueueMetadataEntry) IsDir() bool       { return false }
func (fileIndexQueueMetadataEntry) Type() os.FileMode { return 0 }
func (e fileIndexQueueMetadataEntry) Info() (os.FileInfo, error) {
	e.calls.Add(1)
	return nil, e.err
}

func TestFileIndexQueueExecutableMetadataFailureLoss(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		loss   uint64
		reason string
	}{
		{name: "permission", err: os.ErrPermission, loss: 3, reason: "dropped_work"},
		{name: "disappeared", err: os.ErrNotExist},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, fs := fileIndexQueueFixture(t)
			readDir, stat := fs.readDir, fs.stat
			var calls atomic.Int32
			var cycle int
			fs.readDir = func(name string) ([]os.DirEntry, error) {
				switch name {
				case "/home/alice/.config":
					return []os.DirEntry{fileIndexQueueMetadataEntry{calls: &calls, err: tc.err}}, nil
				case "/home/alice/public_html/wp-content/uploads":
					return nil, nil
				}
				return readDir(name)
			}
			fs.stat = func(name string) (os.FileInfo, error) {
				if name == "/home/alice/.config" {
					return &fakeFileInfoMtime{name: ".config", dir: true, mode: 0755, mtime: time.Unix(100+int64(cycle), 0)}, nil
				}
				return stat(name)
			}
			for cycle = 1; cycle <= 3; cycle++ {
				if findings := CheckFileIndex(context.Background(), cfg, nil); len(findings) != 0 {
					t.Fatalf("metadata failure created findings: %+v", findings)
				}
			}
			if calls.Load() != 3 {
				t.Fatalf("actual metadata calls=%d, want 3", calls.Load())
			}
			rows := fileIndexQueueRows(t, time.Now())
			if rows["active"].InFlight != 0 || rows["active"].DroppedTotal != tc.loss || rows["active"].Reason != tc.reason {
				t.Errorf("incomplete executable enumeration stayed healthy: %+v", rows)
			}
		})
	}
}

func TestFileIndexQueueContentOutcomeBeforeCommit(t *testing.T) {
	for _, tc := range []struct {
		name, body, check string
		unreadable        bool
		loss              uint64
	}{
		{name: "clean", body: "<?php echo 'ready';", check: "new_php_in_uploads_clean"},
		{name: "empty", check: "new_php_in_uploads_clean"},
		{name: "stub", body: "<?php // Silence is golden."},
		{name: "unreadable", unreadable: true, check: "new_php_in_uploads", loss: 1},
		{name: "c99", unreadable: true, check: "new_webshell_file", loss: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, fs := fileIndexQueueFixture(t)
			previous := filepath.Join(cfg.StatePath, "fileindex.previous")
			if err := os.WriteFile(previous, nil, 0600); err != nil {
				t.Fatal(err)
			}
			const uploads = "/home/alice/public_html/wp-content/uploads"
			path := filepath.Join(uploads, tc.name+".php")
			bodyPath := filepath.Join(t.TempDir(), "content.php")
			if err := os.WriteFile(bodyPath, []byte(tc.body), 0600); err != nil {
				t.Fatal(err)
			}
			readDir, open, readFile, stat := fs.readDir, fs.open, fs.readFile, fs.stat
			fs.readDir = func(name string) ([]os.DirEntry, error) {
				if name == uploads {
					return phpDirEntries(filepath.Base(path)), nil
				}
				return readDir(name)
			}
			fs.open = func(name string) (*os.File, error) {
				if name == path {
					if tc.unreadable {
						return nil, os.ErrPermission
					}
					return os.Open(bodyPath)
				}
				return open(name)
			}
			fs.stat = func(name string) (os.FileInfo, error) {
				if name == path {
					return os.Stat(bodyPath)
				}
				return stat(name)
			}
			commits := 0
			fs.readFile = func(name string) ([]byte, error) {
				if name == filepath.Join(cfg.StatePath, "fileindex.current") {
					commits++
					rows := fileIndexQueueRows(t, time.Now())
					if rows["active"].InFlight != 1 || rows["active"].DroppedTotal != tc.loss || rows["waiting"].Depth != 0 {
						t.Fatalf("content outcome missing before baseline commit: %+v", rows)
					}
				}
				return readFile(name)
			}
			findings := CheckFileIndex(context.Background(), cfg, nil)
			if tc.check == "" {
				if len(findings) != 0 {
					t.Fatalf("inert stub produced findings: %+v", findings)
				}
			} else if len(findings) != 1 || findings[0].Check != tc.check || findings[0].FilePath != path {
				t.Fatalf("content verdict changed: %+v", findings)
			}
			if commits != 1 {
				t.Fatalf("baseline copies=%d, want 1", commits)
			}
			data, err := os.ReadFile(previous)
			if err != nil || string(data) != path+"\n" {
				t.Fatalf("baseline=%q err=%v", data, err)
			}
			rows := fileIndexQueueRows(t, time.Now())
			if rows["active"].InFlight != 0 || rows["active"].DroppedTotal != tc.loss || rows["active"].RecentDrops != tc.loss || rows["active"].Status != "ok" || rows["waiting"].DroppedTotal != 0 {
				t.Fatalf("content outcome changed on completion: %+v", rows)
			}
		})
	}
}
