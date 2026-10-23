package daemon

import (
	"context"
	"testing"
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

	d.stopParseWorkers()
	if d.zipLister != nil {
		t.Fatal("zip lister survived shutdown")
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
