package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/workerproc"
	"github.com/pidginhost/csm/internal/yara"
	"github.com/pidginhost/csm/internal/yaraworker"
)

func testYaraRulesDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rules.yar"), []byte("rule hit { condition: true }"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestInitYaraBackendWithoutEngineFailsClosed(t *testing.T) {
	var launches int
	stubYaraUnits(t, false, func(context.Context) (workerproc.Process, error) {
		launches++
		return nil, errors.New("unexpected worker launch")
	})
	allowParseWorkerCommand(t)
	d := yaraWorkerDaemon(t, &config.Config{})
	if err := d.initYaraBackend(); err != nil {
		t.Fatal(err)
	}
	b := yara.Active()
	if b == nil || d.yaraSup == nil || b != yara.Backend(d.yaraSup) {
		t.Fatal("missing engine left YARA inactive")
	}
	if m, err := yara.ScanBytesChecked(b, "test.php", []byte("test")); err == nil {
		t.Fatalf("missing engine allowed a clean scan: %+v", m)
	}
	if launches != 0 {
		t.Fatalf("missing engine launched %d workers", launches)
	}
	select {
	case f := <-d.alertCh:
		t.Fatalf("missing engine reported an unattempted compile: %s: %s", f.Check, f.Message)
	default:
	}
}

func TestInitYaraBackendExpiredBootFailsClosed(t *testing.T) {
	stubYaraUnits(t, true, nil)
	allowParseWorkerCommand(t)
	realBoot := yaraBootCompileTimeout
	yaraBootCompileTimeout = -time.Second
	t.Cleanup(func() { yaraBootCompileTimeout = realBoot })
	cfg := &config.Config{}
	cfg.Signatures.RulesDir = testYaraRulesDir(t)
	d := yaraWorkerDaemon(t, cfg)
	if err := d.initYaraBackend(); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("init = %v, want context.DeadlineExceeded", err)
	}
	if m, err := yara.ScanBytesChecked(yara.Active(), "test.php", []byte("test")); err == nil {
		t.Fatalf("expired boot compile allowed a clean scan: %+v", m)
	}
	if healthy, found := d.WatcherStatuses()[yaraWorkerWatcher]; !found || healthy {
		t.Fatalf("watcher healthy=%v found=%v, want recorded failure", healthy, found)
	}
	select {
	case f := <-d.alertCh:
		t.Fatalf("expired boot reported an unattempted compile: %s: %s", f.Check, f.Message)
	default:
	}
}

func TestInitYaraBackendUnknownBinaryFailsClosed(t *testing.T) {
	stubYaraUnits(t, true, nil)
	cfg := &config.Config{}
	cfg.Signatures.RulesDir = testYaraRulesDir(t)
	d := yaraWorkerDaemon(t, cfg)
	d.binaryPath = ""
	if err := d.initYaraBackend(); err == nil {
		t.Fatal("init succeeded without a worker binary")
	}
	b := yara.Active()
	if b == nil || d.yaraSup == nil || b != yara.Backend(d.yaraSup) {
		t.Fatal("unknown binary left YARA inactive")
	}
	if _, err := yara.ScanBytesChecked(b, "test.php", []byte("test")); err == nil {
		t.Fatal("unknown binary allowed a clean byte scan")
	}
}

func TestInitYaraBackendBrokenRulesReportsFailedWatcher(t *testing.T) {
	stubYaraUnits(t, true, nil)
	allowParseWorkerCommand(t)
	cfg := &config.Config{}
	cfg.Signatures.RulesDir = testYaraRulesDir(t)
	if err := os.Chmod(cfg.Signatures.RulesDir, 0o777); err != nil {
		t.Fatal(err)
	}
	d := yaraWorkerDaemon(t, cfg)
	_ = d.initYaraBackend()
	if _, err := yara.ScanBytesChecked(yara.Active(), "test.php", []byte("test")); err == nil {
		t.Fatal("untrusted rules allowed a clean scan")
	}
	if healthy, found := d.WatcherStatuses()[yaraWorkerWatcher]; !found || healthy {
		t.Fatalf("watcher healthy=%v found=%v, want recorded failure", healthy, found)
	}
}

func TestRetryYaraStartCancelsCompileOnShutdown(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	b, err := yaraworker.NewBackend(yaraworker.BackendConfig{
		RulesDir: testYaraRulesDir(t),
		ScanLaunch: func(context.Context) (workerproc.Process, error) {
			return nil, errors.New("unexpected scan launch")
		},
		CompileLaunch: func(ctx context.Context) (workerproc.Process, error) {
			close(entered)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-release:
				return nil, errors.New("test released launch")
			}
		},
		ScanTimeout: time.Minute, LoadTimeout: time.Minute, CompileTimeout: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	d := &Daemon{cfg: &config.Config{}, stopCh: make(chan struct{}), alertCh: make(chan alert.Finding, 8)}
	done := make(chan struct{})
	go func() { defer close(done); d.retryYaraStart(b, time.Second) }()
	t.Cleanup(func() {
		if !stopRequested(d.stopCh) {
			close(d.stopCh)
		}
		close(release)
		<-done
		_ = b.Stop()
	})
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("retry did not start compiling")
	}
	close(d.stopCh)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not cancel the compile retry")
	}
	select {
	case f := <-d.alertCh:
		t.Fatalf("shutdown emitted a finding: %s", f.Check)
	default:
	}
}

func TestReportYaraCompileStatusSilentDuringShutdown(t *testing.T) {
	d := newDaemonForYaraBackendTest(t)
	d.stopCh = make(chan struct{})
	close(d.stopCh)
	d.reportYaraCompileStatus("compile canceled")
	select {
	case f := <-d.alertCh:
		t.Fatalf("shutdown emitted a finding: %s", f.Check)
	default:
	}
}

func TestInitYaraBackendRetriesDescriptorPressure(t *testing.T) {
	launches := make(chan struct{}, 3)
	stubYaraUnits(t, true, func(context.Context) (workerproc.Process, error) {
		select {
		case launches <- struct{}{}:
		default:
		}
		return nil, syscall.EMFILE
	})
	allowParseWorkerCommand(t)
	cfg := &config.Config{}
	cfg.Signatures.RulesDir = testYaraRulesDir(t)
	d := yaraWorkerDaemon(t, cfg)
	if err := d.initYaraBackend(); err == nil {
		t.Error("descriptor pressure was treated as a permanent rule error")
	}
	deadline := time.After(5 * time.Second)
	for attempt := 0; attempt < 3; attempt++ {
		select {
		case <-launches:
		case <-deadline:
			t.Fatalf("only %d compile attempts; descriptor pressure stopped retries", attempt)
		}
	}
	if _, err := yara.ScanBytesChecked(yara.Active(), "test.php", []byte("test")); err == nil {
		t.Fatal("descriptor pressure allowed a clean scan")
	}
}
