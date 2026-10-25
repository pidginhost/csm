package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	emime "github.com/pidginhost/csm/internal/mime"
	"github.com/pidginhost/csm/internal/parseworker"
	"github.com/pidginhost/csm/internal/workerproc"
)

func TestParseWorkersLifecycleInstallsLazyLister(t *testing.T) {
	var stopped []string
	real := stopParseWorkerUnits
	stopParseWorkerUnits = func(_ context.Context, prefix string) error {
		stopped = append(stopped, prefix)
		return nil
	}
	t.Cleanup(func() { stopParseWorkerUnits = real })

	allowParseWorkerCommand(t)
	d := &Daemon{binaryPath: "/opt/csm/csm"}
	if err := d.initParseWorkers(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.stopParseWorkers)
	if len(stopped) != 1 || stopped[0] != "csm-parse-worker-" {
		t.Fatalf("leftover units stopped with %q", stopped)
	}
	if d.zipLister == nil {
		t.Fatal("zip lister was not installed")
	}
	if got := d.zipLister.Stats().Spawns; got != 0 {
		t.Fatalf("worker spawned during initialization: %d", got)
	}
	q, ok := d.QueueStatuses()["archive_list.requests"]
	if !ok || q.Status != "ok" || q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 0 {
		t.Fatalf("archive list queue was not published: found=%v status=%+v", ok, q)
	}

	lister := d.zipLister
	d.stopParseWorkers()
	if d.zipLister != nil {
		t.Fatal("zip lister survived shutdown")
	}
	if err := lister.ListZip(context.Background(), nil, 0, 0, nil); !errors.Is(err, workerproc.ErrStopped) {
		t.Fatalf("lister accepted work after shutdown: %v", err)
	}
}

func TestParseWorkersCleanupFailureWithPhishingDisabled(t *testing.T) {
	allowParseWorkerCommand(t)
	real := stopParseWorkerUnits
	calls := 0
	stopParseWorkerUnits = func(ctx context.Context, prefix string) error {
		calls++
		if prefix != "csm-parse-worker-" {
			t.Errorf("cleanup prefix = %q", prefix)
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 30*time.Second {
			t.Errorf("cleanup has no bounded deadline: %v, %v", deadline, ok)
		}
		return errors.New("systemd unavailable")
	}
	t.Cleanup(func() { stopParseWorkerUnits = real })

	d := &Daemon{
		binaryPath: "/opt/csm/csm",
		cfg:        &config.Config{DisabledChecks: []string{"phishing"}},
	}
	if err := d.initParseWorkers(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.stopParseWorkers)
	if calls != 1 {
		t.Fatalf("cleanup calls with phishing disabled = %d, want 1", calls)
	}
	if d.zipLister == nil {
		t.Fatal("cleanup failure prevented requested scans from getting a lister")
	}
	if got := d.zipLister.Stats(); got.Spawns != 0 || got.ConsecutiveFailures != 0 || got.BreakerOpen {
		t.Fatalf("cleanup failure affected worker health: %+v", got)
	}
}

func TestParseWorkersRejectMissingBinary(t *testing.T) {
	real := stopParseWorkerUnits
	stopParseWorkerUnits = func(context.Context, string) error { return nil }
	t.Cleanup(func() { stopParseWorkerUnits = real })
	d := &Daemon{}
	if err := d.initParseWorkers(); err == nil || d.zipLister != nil {
		t.Fatalf("empty daemon binary accepted: err=%v", err)
	}
}

// allowParseWorkerCommand accepts any command path, for tests whose binary
// path does not exist on the test host.
func allowParseWorkerCommand(t *testing.T) {
	t.Helper()
	real := checkParseWorkerCommand
	checkParseWorkerCommand = func(string) error { return nil }
	t.Cleanup(func() { checkParseWorkerCommand = real })
}

// A unit's dynamic user cannot run an owner-only binary. Without this check
// every launch would fail at exec, once per scan.
func TestParseWorkersRejectUnexecutableBinary(t *testing.T) {
	var stopped int
	real := stopParseWorkerUnits
	stopParseWorkerUnits = func(context.Context, string) error { stopped++; return nil }
	t.Cleanup(func() { stopParseWorkerUnits = real })
	path := filepath.Join(t.TempDir(), "csm")
	if err := os.WriteFile(path, []byte("x"), 0o700); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{binaryPath: path}
	err := d.initParseWorkers()
	if err == nil || !strings.Contains(err.Error(), "executable by others") || d.zipLister != nil {
		t.Fatalf("owner-only binary: err=%v lister=%v", err, d.zipLister != nil)
	}
	if stopped != 1 {
		t.Fatalf("leftover units not stopped first: %d", stopped)
	}
}

// One mail slot per spool scan goroutine, each started on first use.
func TestParseWorkersBuildMailExtractor(t *testing.T) {
	real := stopParseWorkerUnits
	stopParseWorkerUnits = func(context.Context, string) error { return nil }
	t.Cleanup(func() { stopParseWorkerUnits = real })
	allowParseWorkerCommand(t)
	cfg := &config.Config{}
	cfg.EmailAV.Enabled = true
	cfg.EmailAV.ScanConcurrency = 3
	d := &Daemon{binaryPath: "/opt/csm/csm", cfg: cfg}
	if err := d.initParseWorkers(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.stopParseWorkers)
	if d.mailExtractor == nil || d.mailExtractor.Size() != 3 {
		t.Fatalf("mail extractor = %v", d.mailExtractor)
	}
	q, ok := d.QueueStatuses()["email_extract.requests"]
	if !ok || q.Status != "ok" || q.Capacity != 3 || q.InFlight != 0 {
		t.Fatalf("mail extraction queue was not published: found=%v status=%+v", ok, q)
	}
	ex := d.mailExtractor
	d.stopParseWorkers()
	if d.mailExtractor != nil {
		t.Fatal("mail extractor survived shutdown")
	}
	if _, err := ex.Extract(context.Background(), 0, nil, nil, emime.DefaultLimits()); !errors.Is(err, workerproc.ErrStopped) {
		t.Fatalf("extractor accepted work after shutdown: %v", err)
	}
}

func TestParseWorkersNoMailExtractorWhenEmailAVOff(t *testing.T) {
	real := stopParseWorkerUnits
	stopParseWorkerUnits = func(context.Context, string) error { return nil }
	t.Cleanup(func() { stopParseWorkerUnits = real })
	allowParseWorkerCommand(t)
	d := &Daemon{binaryPath: "/opt/csm/csm", cfg: &config.Config{}}
	if err := d.initParseWorkers(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.stopParseWorkers)
	if d.mailExtractor != nil {
		t.Fatal("mail extractor built with email AV off")
	}
	if _, ok := d.QueueStatuses()["email_extract.requests"]; ok {
		t.Fatal("mail extraction queue published with email AV off")
	}
}

func isolationFindings(ch chan alert.Finding) []alert.Finding {
	var out []alert.Finding
	for {
		select {
		case f := <-ch:
			if f.Check == "email_av_isolation_unavailable" {
				out = append(out, f)
			}
		default:
			return out
		}
	}
}

// Parse workers that cannot run are a Critical condition: mail is handled as
// incomplete scans and phishing-kit zips go unchecked until it is fixed.
func TestParseWorkersIsolationUnavailableFinding(t *testing.T) {
	real := stopParseWorkerUnits
	stopParseWorkerUnits = func(context.Context, string) error { return nil }
	t.Cleanup(func() { stopParseWorkerUnits = real })

	path := filepath.Join(t.TempDir(), "csm")
	if err := os.WriteFile(path, []byte("x"), 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.EmailAV.Enabled = true
	d := &Daemon{binaryPath: path, cfg: cfg, alertCh: make(chan alert.Finding, 8)}
	if err := d.initParseWorkers(); err == nil {
		t.Fatal("owner-only binary accepted")
	}
	if d.zipLister != nil || d.mailExtractor != nil {
		t.Fatal("a pool was installed without a runnable binary")
	}
	if fs := isolationFindings(d.alertCh); len(fs) != 1 || fs[0].Severity != alert.Critical {
		t.Fatalf("isolation findings %+v, want one Critical", fs)
	}

	// The zip lister's failed starts raise it too, at most once an hour.
	allowParseWorkerCommand(t)
	realLaunch := parseWorkerLauncher
	parseWorkerLauncher = func(workerproc.UnitConfig) workerproc.Launcher {
		return func(context.Context) (workerproc.Process, error) { return nil, errors.New("systemd-run missing") }
	}
	t.Cleanup(func() { parseWorkerLauncher = realLaunch })
	d = &Daemon{binaryPath: "/opt/csm/csm", cfg: &config.Config{}, alertCh: make(chan alert.Finding, 8)}
	if err := d.initParseWorkers(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.stopParseWorkers)
	zip, err := os.Create(filepath.Join(t.TempDir(), "kit.zip"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = zip.Close() }()
	for range 2 {
		if err := d.zipLister.ListZip(context.Background(), zip, 0, 0, nil); !errors.Is(err, workerproc.ErrSpawn) {
			t.Fatalf("list with no worker = %v, want ErrSpawn", err)
		}
	}
	if fs := isolationFindings(d.alertCh); len(fs) != 1 || fs[0].Severity != alert.Critical {
		t.Fatalf("isolation findings %+v, want one Critical an hour", fs)
	}
}

// Resource pressure must report unavailable isolation without opening the
// worker breaker. Cancellation belongs to the caller and is not an outage.
func TestParseWorkersReportUncountedLaunchFailures(t *testing.T) {
	realStop, realLaunch := stopParseWorkerUnits, parseWorkerLauncher
	stopParseWorkerUnits = func(context.Context, string) error { return nil }
	t.Cleanup(func() { stopParseWorkerUnits, parseWorkerLauncher = realStop, realLaunch })
	allowParseWorkerCommand(t)
	for _, cause := range []error{syscall.EMFILE, syscall.ENFILE, context.Canceled} {
		t.Run(cause.Error(), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			parseWorkerLauncher = func(workerproc.UnitConfig) workerproc.Launcher {
				return func(context.Context) (workerproc.Process, error) {
					if errors.Is(cause, context.Canceled) {
						cancel()
					}
					return nil, cause
				}
			}
			d := &Daemon{binaryPath: "/opt/csm/csm", alertCh: make(chan alert.Finding, 1)}
			if err := d.initParseWorkers(); err != nil {
				t.Fatal(err)
			}
			defer d.stopParseWorkers()
			zip, err := os.Create(filepath.Join(t.TempDir(), "kit.zip"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = zip.Close() }()
			for range workerproc.ConsecutiveFailureLimit + 1 {
				err := d.zipLister.ListZip(ctx, zip, 0, 0, nil)
				if !errors.Is(err, cause) {
					t.Fatalf("listing error = %v, want %v", err, cause)
				}
			}
			if st := d.zipLister.Stats(); st.BreakerOpen || st.ConsecutiveFailures != 0 || len(st.Kills) != 0 {
				t.Fatalf("uncounted failure opened the breaker or changed kill counts: %+v", st)
			}
			fs := isolationFindings(d.alertCh)
			if errors.Is(cause, context.Canceled) {
				if len(fs) != 0 {
					t.Fatalf("cancellation reported an outage: %+v", fs)
				}
			} else if len(fs) != 1 || fs[0].Severity != alert.Critical {
				t.Fatalf("isolation findings %+v, want one Critical", fs)
			}
		})
	}
}

// Shutdown must keep the pool available to accepted spool work and watcher
// replacements until the daemon's tracked producers have all returned.
func TestStopParseWorkersWaitsForSpoolDrain(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		startErr := errors.New("test launcher reached")
		ex, err := parseworker.NewExtractor(parseworker.ExtractorConfig{Size: 1,
			Launch: func(int) workerproc.Launcher {
				return func(context.Context) (workerproc.Process, error) { return nil, startErr }
			}})
		if err != nil {
			t.Fatal(err)
		}
		d := &Daemon{mailExtractor: ex, stopCh: make(chan struct{})}
		close(d.stopCh) // shutdown signalled
		d.wg.Add(1)
		stopped := make(chan struct{})
		go func() { d.stopParseWorkers(); close(stopped) }()
		synctest.Wait()
		select {
		case <-stopped:
			t.Error("parse workers stopped before accepted spool work drained")
		default:
		}
		if d.spoolExtractor() != ex {
			t.Error("watcher replacement lost its extractor during shutdown")
		}
		f, err := os.CreateTemp(t.TempDir(), "spool")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = f.Close() }()
		if _, err := ex.Extract(context.Background(), 0, f, f, emime.DefaultLimits()); !errors.Is(err, workerproc.ErrSpawn) || !strings.Contains(err.Error(), startErr.Error()) {
			t.Errorf("accepted spool work could not reach its worker: %v", err)
		}
		d.wg.Done()
		<-stopped
		if d.spoolExtractor() != nil {
			t.Error("extractor retained after shutdown")
		}
		if _, err := ex.Extract(context.Background(), 0, f, f, emime.DefaultLimits()); !errors.Is(err, workerproc.ErrStopped) {
			t.Errorf("extractor accepted work after shutdown: %v", err)
		}
	})
}

// A panic unwinding Run runs the deferred stop before shutdown is signalled.
// Nothing has told the daemon's goroutines to stop, so waiting for them would
// hang the process instead of letting it crash and be restarted.
func TestStopParseWorkersDoesNotWaitBeforeShutdown(t *testing.T) {
	d := &Daemon{stopCh: make(chan struct{})}
	d.wg.Add(1)
	t.Cleanup(d.wg.Done)
	stopped := make(chan struct{})
	go func() { d.stopParseWorkers(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("parse worker stop waited for goroutines that were never told to stop")
	}
}

// Panic cleanup skips the producer drain, so a watcher replacement can still
// be reading the shared extractor while cleanup clears it.
func TestStopParseWorkersDuringWatcherRestart(t *testing.T) {
	ex, err := parseworker.NewExtractor(parseworker.ExtractorConfig{Size: 1,
		Launch: func(int) workerproc.Launcher {
			return func(context.Context) (workerproc.Process, error) {
				return nil, errors.New("unexpected worker launch")
			}
		}})
	if err != nil {
		t.Fatal(err)
	}
	d := &Daemon{mailExtractor: ex, stopCh: make(chan struct{})}
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		if got := d.spoolExtractor(); got != nil && got != ex {
			t.Errorf("replacement received an invalid extractor: %v", got)
		}
	}()
	d.stopParseWorkers()
	d.wg.Wait()
	if d.spoolExtractor() != nil {
		t.Fatal("extractor retained after cleanup")
	}
	if _, err := ex.Extract(context.Background(), 0, nil, nil, emime.DefaultLimits()); !errors.Is(err, workerproc.ErrStopped) {
		t.Fatalf("extractor accepted work after cleanup: %v", err)
	}
}

func TestInitParseWorkersUsesConfiguredMemoryLimit(t *testing.T) {
	realStop := stopParseWorkerUnits
	stopParseWorkerUnits = func(context.Context, string) error { return nil }
	t.Cleanup(func() { stopParseWorkerUnits = realStop })
	allowParseWorkerCommand(t)
	limits := map[string]uint64{}
	realLauncher := parseWorkerLauncher
	parseWorkerLauncher = func(cfg workerproc.UnitConfig) workerproc.Launcher {
		limits[cfg.Prefix] = cfg.MemoryLimit
		return realLauncher(cfg)
	}
	t.Cleanup(func() { parseWorkerLauncher = realLauncher })
	cfg := &config.Config{}
	cfg.EmailAV.Enabled = true
	cfg.EmailAV.ScanConcurrency = 2
	cfg.EmailAV.WorkerMemoryLimit = 256 << 20
	d := &Daemon{binaryPath: "/opt/csm/csm", cfg: cfg}
	if err := d.initParseWorkers(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.stopParseWorkers)
	want := map[string]uint64{
		"csm-parse-worker-zip0":  parseworker.DefaultMemoryLimit,
		"csm-parse-worker-mail0": 256 << 20,
		"csm-parse-worker-mail1": 256 << 20,
	}
	if len(limits) != len(want) {
		t.Fatalf("units configured = %v, want %v", limits, want)
	}
	for prefix, limit := range want {
		if limits[prefix] != limit {
			t.Errorf("%s memory limit = %d, want %d", prefix, limits[prefix], limit)
		}
	}
}
