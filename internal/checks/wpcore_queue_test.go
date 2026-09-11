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
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/queuehealth"
)

func wpCoreQueueFixtures(t *testing.T, count int) ([]string, *mockOS) {
	t.Helper()
	previous := wpCoreBatches
	wpCoreBatches = newScanBatchMonitor()
	t.Cleanup(func() { wpCoreBatches = previous })
	GlobalCMSCache()
	previousCache := globalCache
	globalCache = &CMSHashCache{hashes: make(map[string]bool), sizes: make(map[int64]bool)}
	t.Cleanup(func() { globalCache = previousCache })
	home := filepath.Join(t.TempDir(), "home")
	withAccountHomeRoots(t, home)
	roots := make([]string, count)
	for i := range roots {
		roots[i] = filepath.Join(home, "alice", "public_html", fmt.Sprintf("site%d", i), "wp-config.php")
		if err := os.MkdirAll(filepath.Dir(roots[i]), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(roots[i], []byte("<?php // Queue test installation.\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		content := fmt.Sprintf("<?php echo 'queue fixture %d';\n", i)
		if err := os.WriteFile(filepath.Join(filepath.Dir(roots[i]), "wp-login.php"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	fs := &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == filepath.Join(home, "*", "public_html", "*", "wp-config.php") {
				return roots, nil
			}
			return nil, nil
		},
		lstat: func(name string) (os.FileInfo, error) { return mockPathInfo(name, roots) },
		open:  os.Open,
		stat:  os.Stat,
	}
	withMockOS(t, fs)
	return roots, fs
}

func wpCoreQueueSnapshot(t *testing.T, now time.Time) queuehealth.Status {
	t.Helper()
	result := make(chan queuehealth.Status, 1)
	go func() { result <- WPCoreQueueStatus(now) }()
	select {
	case q := <-result:
		return q
	case <-time.After(time.Second):
		t.Fatal("WordPress queue health waited for command, cache or result work")
		return queuehealth.Status{}
	}
}

func wpCoreQueuePath(t *testing.T, name string, args []string) string {
	t.Helper()
	if name != "wp" || len(args) != 4 || args[0] != "core" || args[1] != "verify-checksums" || !strings.HasPrefix(args[2], "--path=") || args[3] != "--allow-root" {
		t.Errorf("unexpected checksum command: %s %v", name, args)
		return ""
	}
	return strings.TrimPrefix(args[2], "--path=")
}

type wpCoreQueueScan struct {
	done     chan struct{}
	findings []alert.Finding
}

func startWPCoreQueueScan(t *testing.T, ctx context.Context, release func()) *wpCoreQueueScan {
	t.Helper()
	scan := &wpCoreQueueScan{done: make(chan struct{})}
	go func() {
		defer close(scan.done)
		scan.findings = CheckWPCore(ctx, &config.Config{}, nil)
	}()
	t.Cleanup(func() {
		release()
		select {
		case <-scan.done:
		case <-time.After(5 * time.Second):
			t.Error("WordPress scan did not join during cleanup")
		}
	})
	return scan
}

func (s *wpCoreQueueScan) wait(t *testing.T) []alert.Finding {
	t.Helper()
	select {
	case <-s.done:
		return s.findings
	case <-time.After(5 * time.Second):
		t.Fatal("WordPress scan did not finish")
		return nil
	}
}

type wpCoreQueueBatchKey struct{}

func TestWPCoreQueueConcurrentBatchesRemainIndependent(t *testing.T) {
	roots, _ := wpCoreQueueFixtures(t, 8)
	entered := [2]chan string{make(chan string, 8), make(chan string, 8)}
	release := [2]chan struct{}{make(chan struct{}), make(chan struct{})}
	finish := [2]func(){sync.OnceFunc(func() { close(release[0]) }), sync.OnceFunc(func() { close(release[1]) })}
	withMockCmd(t, &mockCmd{runContext: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		batch := ctx.Value(wpCoreQueueBatchKey{}).(int)
		entered[batch] <- wpCoreQueuePath(t, name, args)
		<-release[batch]
		return []byte("Success: WordPress installation verifies against checksums.\n"), nil
	}})
	var scans [2]*wpCoreQueueScan
	seen := [2]map[string]int{make(map[string]int), make(map[string]int)}
	for batch := range scans {
		scans[batch] = startWPCoreQueueScan(t, context.WithValue(context.Background(), wpCoreQueueBatchKey{}, batch), finish[batch])
		for range 5 {
			select {
			case path := <-entered[batch]:
				seen[batch][path]++
			case <-time.After(5 * time.Second):
				t.Fatal("five checksum workers did not enter")
			}
		}
	}
	q := wpCoreQueueSnapshot(t, time.Now().Add(61*time.Second))
	if q.Depth != 6 || q.InFlight != 10 || q.DroppedTotal != 0 || q.Status != "ok" || !q.CapacityUnavailable || q.DepthUnit != "installations" {
		t.Fatalf("finite concurrent batches: %+v", q)
	}
	if q := wpCoreQueueSnapshot(t, time.Now().Add(cmdTimeout+time.Second)); q.Depth != 6 || q.InFlight != 10 || q.Reason != "processing_lag" || q.DroppedTotal != 0 {
		t.Fatalf("command deadlines not visible: %+v", q)
	}
	for batch := range scans {
		finish[batch]()
		if findings := scans[batch].wait(t); len(findings) != 0 {
			t.Fatalf("verified sites produced findings: %+v", findings)
		}
		for range 3 {
			select {
			case path := <-entered[batch]:
				seen[batch][path]++
			default:
				t.Fatal("completed scan missed a waiting installation")
			}
		}
		if len(seen[batch]) != len(roots) {
			t.Fatalf("scan %d verified %d distinct sites, want %d", batch, len(seen[batch]), len(roots))
		}
		for _, root := range roots {
			if n := seen[batch][filepath.Dir(root)]; n != 1 {
				t.Errorf("scan %d verified installation %d times", batch, n)
			}
		}
		waiting, running := 0, 0
		if batch == 0 {
			waiting, running = 3, 5
		}
		if q := wpCoreQueueSnapshot(t, time.Now()); q.Depth != waiting || q.InFlight != running || q.DroppedTotal != 0 || q.Status != "ok" {
			t.Fatalf("scan %d completion changed other ownership: %+v", batch, q)
		}
	}
	if size := GlobalCMSCache().Size(); size != len(roots) {
		t.Fatalf("verified files cached = %d, want %d", size, len(roots))
	}
}

func TestWPCoreQueueDistinguishesFailuresFromIntegrityResults(t *testing.T) {
	roots, _ := wpCoreQueueFixtures(t, 8)
	var calls atomic.Int32
	withMockCmd(t, &mockCmd{runContext: func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls.Add(1)
		path := wpCoreQueuePath(t, name, args)
		switch filepath.Base(path) {
		case "site0":
			return []byte("Success: WordPress installation verifies against checksums.\n"), nil
		case "site1":
			return nil, errors.New("fixture command unavailable")
		case "site2":
			return []byte("Error: fixture checksum service unavailable\n"), errors.New("exit status 1")
		case "site3":
			return nil, context.DeadlineExceeded
		case "site4":
			return []byte("Warning: File doesn't verify against checksum: wp-includes/plugin.php\nWarning: File doesn't verify against checksum: wp-includes/version.php\nWarning: File should not exist: wp-includes/extra.php\n"), errors.New("exit status 1")
		case "site5":
			return []byte("Warning: File doesn't verify against checksum: readme.html\nWarning: File doesn't verify against checksum: license.txt\nWarning: File should not exist: error_log\n"), errors.New("exit status 1")
		case "site6":
			return []byte("Warning: File should not exist: wp-admin/extra.php\n"), errors.New("exit status 1")
		default:
			return nil, context.Canceled
		}
	}})
	findings := CheckWPCore(context.Background(), &config.Config{}, nil)
	if calls.Load() != 8 || len(findings) != 4 {
		t.Fatalf("checksum outcomes: calls=%d findings=%+v", calls.Load(), findings)
	}
	bySite := make(map[string]int)
	for _, finding := range findings {
		if finding.Check != "wp_core_integrity" {
			t.Errorf("unexpected finding: %+v", finding)
		}
		bySite[findingDetailPath(finding.Details)]++
	}
	if bySite[filepath.Dir(roots[4])] != 3 || bySite[filepath.Dir(roots[6])] != 1 || len(bySite) != 2 {
		t.Fatalf("integrity result collection changed: %+v", bySite)
	}
	if q := wpCoreQueueSnapshot(t, time.Now()); q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 4 || q.RecentDrops != 4 || q.Reason != "dropped_work" {
		t.Fatalf("failed installations counted incorrectly: %+v", q)
	}
	if q := wpCoreQueueSnapshot(t, time.Now().Add(time.Minute)); q.Status != "ok" || q.DroppedTotal != 4 || q.RecentDrops != 0 {
		t.Fatalf("recovery discarded failure history: %+v", q)
	}
	if cache := GlobalCMSCache(); cache.Size() != 1 || !cache.Contains(HashFile(filepath.Join(filepath.Dir(roots[0]), "wp-login.php"))) {
		t.Fatal("failed or mismatched installation entered verified cache")
	}
}

func TestWPCoreQueueWorkerExitAccountsForAbandonedSites(t *testing.T) {
	wpCoreQueueFixtures(t, 8)
	var calls atomic.Int32
	withMockCmd(t, &mockCmd{runContext: func(_ context.Context, name string, args ...string) ([]byte, error) {
		wpCoreQueuePath(t, name, args)
		calls.Add(1)
		runtime.Goexit()
		return nil, nil
	}})
	scan := startWPCoreQueueScan(t, context.Background(), func() {})
	if findings := scan.wait(t); len(findings) != 0 || calls.Load() != 5 {
		t.Fatalf("worker exit behavior changed: calls=%d findings=%+v", calls.Load(), findings)
	}
	if q := wpCoreQueueSnapshot(t, time.Now()); q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 8 || q.Reason != "dropped_work" {
		t.Fatalf("exited workers or buffered sites disappeared: %+v", q)
	}
	if GlobalCMSCache().Size() != 0 {
		t.Fatal("interrupted checks entered verified cache")
	}
}

func TestWPCoreQueueRefusedInstallationsAreNotLostWork(t *testing.T) {
	wpCoreQueueFixtures(t, 3)
	refused := refusedCommand(t)
	withMockCmd(t, &mockCmd{runContext: func(_ context.Context, name string, args ...string) ([]byte, error) {
		wpCoreQueuePath(t, name, args)
		return []byte("Error: This does not seem to be a WordPress installation.\n"), refused
	}})
	if findings := CheckWPCore(context.Background(), &config.Config{}, nil); len(findings) != 0 {
		t.Fatalf("a refused installation raised integrity findings: %+v", findings)
	}
	if q := wpCoreQueueSnapshot(t, time.Now()); q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 0 || q.Status != "ok" {
		t.Fatalf("installations wp-cli refused to check were counted as lost work: %+v", q)
	}
	if GlobalCMSCache().Size() != 0 {
		t.Fatal("a refused installation entered the verified cache")
	}
}
