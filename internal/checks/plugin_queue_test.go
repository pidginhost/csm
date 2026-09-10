package checks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/queuehealth"
	"github.com/pidginhost/csm/internal/store"
)

func pluginQueueRoots(t *testing.T, count int) []string {
	t.Helper()
	paths := make([]string, count)
	for i := range paths {
		paths[i] = fmt.Sprintf("/home/alice/public_html/site%d/wp-config.php", i)
	}
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == "/home/*/public_html/wp-config.php" {
				return paths, nil
			}
			return nil, nil
		},
		lstat: func(name string) (os.FileInfo, error) { return mockPathInfo(name, paths) },
	})
	return paths
}

func pluginQueue(t *testing.T, now time.Time) queuehealth.Status {
	t.Helper()
	done := make(chan queuehealth.Status, 1)
	go func() { done <- PluginInventoryQueueStatus(now) }()
	select {
	case q := <-done:
		return q
	case <-time.After(time.Second):
		t.Fatal("plugin health waited for inventory or persistence")
		return queuehealth.Status{}
	}
}

func TestPluginQueueSaturatedBatchDrains(t *testing.T) {
	previous := pluginInventoryBatches
	pluginInventoryBatches = newScanBatchMonitor()
	defer func() { pluginInventoryBatches = previous }()
	db := setupPluginStore(t)
	roots := pluginQueueRoots(t, 8)
	entered, release := make(chan struct{}, 8), make(chan struct{})
	finish := sync.OnceFunc(func() { close(release) })
	defer finish()
	withMockCmd(t, &mockCmd{runContextStdout: func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if strings.Contains(strings.Join(args, " "), "plugin list") {
			entered <- struct{}{}
			<-release
			return []byte("[]"), nil
		}
		return []byte("https://example.test"), nil
	}})
	done := make(chan struct{})
	go func() { defer close(done); refreshPluginCache(context.Background(), db) }()
	defer func() {
		finish()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("refresh did not finish during cleanup")
		}
	}()
	for range 5 {
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			t.Fatal("five inventory workers did not start")
		}
	}
	q := pluginQueue(t, time.Now().Add(61*time.Second))
	if q.Depth != 3 || q.InFlight != 5 || q.DroppedTotal != 0 || q.Status != "ok" || !q.CapacityUnavailable {
		t.Fatalf("busy inventory pool: %+v", q)
	}
	finish()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("inventory did not drain")
	}
	if q := pluginQueue(t, time.Now()); q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 0 || q.Status != "ok" {
		t.Fatalf("drained inventory: %+v", q)
	}
	sites := db.AllSitePlugins()
	if len(sites) != 8 || db.GetPluginRefreshTime().IsZero() {
		t.Fatalf("successful inventory not persisted: sites=%d", len(sites))
	}
	for _, root := range roots {
		if _, ok := sites[filepath.Dir(root)]; !ok {
			t.Fatalf("site not persisted: %s", root)
		}
	}
}

func TestPluginQueueFailuresCountOnceAndRecover(t *testing.T) {
	previous := pluginInventoryBatches
	pluginInventoryBatches = newScanBatchMonitor()
	defer func() { pluginInventoryBatches = previous }()
	db := setupPluginStore(t)
	pluginQueueRoots(t, 3)
	withMockCmd(t, &mockCmd{runContextStdout: func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if !strings.Contains(strings.Join(args, " "), "plugin list") {
			return []byte("https://example.test"), nil
		}
		command := strings.Join(args, " ")
		switch {
		case strings.Contains(command, "/site0"):
			return nil, context.DeadlineExceeded
		case strings.Contains(command, "/site1"):
			return []byte("invalid JSON"), nil
		default:
			return nil, errors.New("fixture command failure")
		}
	}})
	log := captureStderr(t, func() { refreshPluginCache(context.Background(), db) })
	if !strings.Contains(log, "timeout=1 exec_fail=1 json_fail=1") {
		t.Fatalf("failure classes not exercised: %s", log)
	}
	if q := pluginQueue(t, time.Now()); q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 3 || q.RecentDrops != 3 || q.Reason != "dropped_work" {
		t.Fatalf("inventory failure accounting: %+v", q)
	}
	if len(db.AllSitePlugins()) != 0 || !db.GetPluginRefreshTime().IsZero() {
		t.Fatal("failed inventories were recorded as fresh")
	}
	if q := pluginQueue(t, time.Now().Add(time.Minute)); q.Status != "ok" || q.DroppedTotal != 3 || q.RecentDrops != 0 {
		t.Fatalf("inventory recovery lost evidence: %+v", q)
	}
}

func TestPluginQueueCanceledWorkersRemainOwned(t *testing.T) {
	testPluginQueueWithdrawal(t, false)
}

func TestPluginQueueDeadlineCountsUnfinishedSites(t *testing.T) {
	testPluginQueueWithdrawal(t, true)
}

func testPluginQueueWithdrawal(t *testing.T, deadline bool) {
	t.Helper()
	previous := pluginInventoryBatches
	pluginInventoryBatches = newScanBatchMonitor()
	defer func() { pluginInventoryBatches = previous }()
	db := setupPluginStore(t)
	pluginQueueRoots(t, 8)
	ctx, cancel := context.WithCancel(context.Background())
	if deadline {
		cancel()
		ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
	}
	defer cancel()
	entered, release := make(chan struct{}, 5), make(chan struct{})
	finish := sync.OnceFunc(func() { close(release) })
	defer finish()
	var calls atomic.Int32
	withMockCmd(t, &mockCmd{runContextStdout: func(ctx context.Context, _ string, args ...string) ([]byte, error) {
		if !strings.Contains(strings.Join(args, " "), "plugin list") {
			return []byte("https://example.test"), nil
		}
		calls.Add(1)
		entered <- struct{}{}
		<-release
		return nil, ctx.Err()
	}})
	done := make(chan struct{})
	go func() { defer close(done); refreshPluginCache(ctx, db) }()
	defer func() {
		finish()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("refresh did not finish during cleanup")
		}
	}()
	for range 5 {
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			t.Fatal("inventory workers did not start")
		}
	}
	if deadline {
		if q := pluginQueue(t, time.Now().Add(3*time.Second)); q.Depth != 3 || q.InFlight != 5 || q.Reason != "processing_lag" || q.DroppedTotal != 0 {
			t.Fatalf("short parent deadline not honored: %+v", q)
		}
		select {
		case <-ctx.Done():
		case <-time.After(3 * time.Second):
			t.Fatal("parent deadline did not expire")
		}
	} else {
		cancel()
	}
	// The original worker pool stops consuming only when its active calls return.
	if q := pluginQueue(t, time.Now()); q.Depth != 3 || q.InFlight != 5 || q.DroppedTotal != 0 {
		t.Fatalf("blocked canceled inventory disappeared: %+v", q)
	}
	finish()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("canceled inventory did not drain")
	}
	var want uint64
	if deadline {
		want = 8
	}
	if q := pluginQueue(t, time.Now()); q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != want {
		t.Fatalf("withdrawn inventory: %+v", q)
	}
	if calls.Load() != 5 || len(db.AllSitePlugins()) != 0 || !db.GetPluginRefreshTime().IsZero() {
		t.Fatal("withdrawal started extra jobs or persisted failed inventory")
	}
	if q := pluginQueue(t, time.Now().Add(time.Minute)); q.Status != "ok" || q.RecentDrops != 0 || q.DroppedTotal != want {
		t.Fatalf("withdrawal recovery lost evidence: %+v", q)
	}
}

func TestPluginQueueStoreAndCleanupFailureCountOnce(t *testing.T) {
	previous := pluginInventoryBatches
	pluginInventoryBatches = newScanBatchMonitor()
	defer func() { pluginInventoryBatches = previous }()
	db := setupPluginStore(t)
	pluginQueueRoots(t, 3)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	withMockCmd(t, &mockCmd{runContextStdout: func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if strings.Contains(strings.Join(args, " "), "plugin list") {
			return []byte("[]"), nil
		}
		return []byte("https://example.test"), nil
	}})
	log := captureStderr(t, func() { refreshPluginCache(context.Background(), db) })
	if strings.Count(log, "plugincheck: store failed") != 3 || strings.Count(log, "plugincheck: stale cache cleanup failed") != 3 {
		t.Fatalf("real write and cleanup failures not exercised: %s", log)
	}
	if q := pluginQueue(t, time.Now()); q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 3 || q.RecentDrops != 3 || q.Reason != "dropped_work" {
		t.Fatalf("store failures counted more than once per inventory: %+v", q)
	}
	reopened, err := store.Open(filepath.Dir(db.Path()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := reopened.Close(); err != nil {
			t.Error(err)
		}
	}()
	if len(reopened.AllSitePlugins()) != 0 || !reopened.GetPluginRefreshTime().IsZero() {
		t.Fatal("failed store recorded fresh inventory")
	}
}

type pluginRefreshWaitContext struct {
	context.Context
	entered chan struct{}
	once    sync.Once
}

func (c *pluginRefreshWaitContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.entered) })
	return c.Context.Done()
}

func TestPluginQueueSharedRefreshOwnedByCheckExecutions(t *testing.T) {
	previous, previousChecks := pluginInventoryBatches, checkExecutions
	pluginInventoryBatches, checkExecutions = newScanBatchMonitor(), newCheckExecutionMonitor()
	defer func() { pluginInventoryBatches, checkExecutions = previous, previousChecks }()
	db := setupPluginStore(t)
	pluginQueueRoots(t, 1)
	entered, release := make(chan struct{}), make(chan struct{})
	finish := sync.OnceFunc(func() { close(release) })
	defer finish()
	var inventories atomic.Int32
	withMockCmd(t, &mockCmd{runContextStdout: func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if strings.Contains(strings.Join(args, " "), "plugin list") {
			if inventories.Add(1) == 1 {
				close(entered)
			}
			<-release
			return []byte("[]"), nil
		}
		return []byte("https://example.test"), nil
	}})
	leaderCtx, stopLeader := context.WithTimeout(context.Background(), 5*time.Minute)
	defer stopLeader()
	leader := executeCheckAsync(leaderCtx, "outdated_plugins", func() []alert.Finding { return CheckOutdatedPlugins(leaderCtx, &config.Config{}, nil) })
	settle := func(e *checkExecution) {
		t.Helper()
		select {
		case result := <-e.done:
			e.received()
			e.finishCaller()
			if result.panicErr != "" || len(result.findings) != 0 {
				t.Errorf("shared refresh result changed: %+v", result)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("shared refresh check did not finish")
		}
	}
	// Join the leader even on an assertion failure before restoring global hooks.
	leaderSettled := false
	defer func() {
		finish()
		if !leaderSettled {
			settle(leader)
		}
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("leader did not start inventory")
	}
	waiterParent, stopWaiter := context.WithTimeout(context.Background(), 30*time.Second)
	defer stopWaiter()
	waiterCtx := &pluginRefreshWaitContext{Context: waiterParent, entered: make(chan struct{})}
	waiter := executeCheckAsync(waiterCtx, "vulnerable_plugins", func() []alert.Finding { return CheckVulnerablePlugins(waiterCtx, &config.Config{}, nil) })
	waiterSettled := false
	defer func() {
		stopWaiter()
		if !waiterSettled {
			settle(waiter)
		}
	}()
	select {
	case <-waiterCtx.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("second check did not wait on shared refresh")
	}
	if q := CheckExecutionQueueStatus(time.Now().Add(31 * time.Second)); q.Depth != 0 || q.InFlight != 2 || q.DroppedTotal != 0 || q.Reason != "processing_lag" {
		t.Fatalf("shared refresh wait not owned by check execution: %+v", q)
	}
	if q := pluginQueue(t, time.Now().Add(31*time.Second)); q.Depth != 0 || q.InFlight != 1 || q.DroppedTotal != 0 || q.Status != "ok" {
		t.Fatalf("shared waiter duplicated site work: %+v", q)
	}
	stopWaiter()
	settle(waiter)
	waiterSettled = true
	until := time.Now().Add(time.Second)
	for CheckExecutionQueueStatus(time.Now()).InFlight != 1 && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
	}
	if q := CheckExecutionQueueStatus(time.Now()); q.Depth != 0 || q.InFlight != 1 || q.DroppedTotal != 0 {
		t.Fatalf("waiter cancellation released leader or lost work: %+v", q)
	}
	if q := pluginQueue(t, time.Now()); q.InFlight != 1 || q.DroppedTotal != 0 {
		t.Fatalf("waiter cancellation released inventory: %+v", q)
	}
	finish()
	settle(leader)
	leaderSettled = true
	until = time.Now().Add(time.Second)
	for CheckExecutionQueueStatus(time.Now()).InFlight != 0 && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
	}
	if q := CheckExecutionQueueStatus(time.Now()); q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 0 {
		t.Fatalf("check ownership did not drain: %+v", q)
	}
	if q := pluginQueue(t, time.Now()); q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 0 {
		t.Fatalf("shared inventory did not drain: %+v", q)
	}
	if inventories.Load() != 1 || len(db.AllSitePlugins()) != 1 || db.GetPluginRefreshTime().IsZero() {
		t.Fatal("shared refresh duplicated inventory or lost successful result")
	}
}
