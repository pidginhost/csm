package daemon

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
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
