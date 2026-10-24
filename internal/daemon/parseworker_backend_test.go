package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	emime "github.com/pidginhost/csm/internal/mime"
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
