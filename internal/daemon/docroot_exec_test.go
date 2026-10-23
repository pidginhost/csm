package daemon

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/queuehealth"
)

func newTestDocrootExecMonitor(t *testing.T, alertCh chan alert.Finding) *docrootExecMonitor {
	t.Helper()
	m := newDocrootExecMonitor(&config.Config{}, alertCh)
	m.roots.Store(checks.NewDocrootIndex([]string{"/home/alice/public_html"}))
	return m
}

func stubDocrootInspect(t *testing.T, fn func(pid int, filename, parentComm string, roots *checks.DocrootIndex) *alert.Finding) {
	t.Helper()
	old := inspectDocrootExec
	inspectDocrootExec = func(_ *config.Config, pid, _ int, filename, parentComm string, roots *checks.DocrootIndex) *alert.Finding {
		return fn(pid, filename, parentComm, roots)
	}
	t.Cleanup(func() { inspectDocrootExec = old })
}

// The exec event loop only filters: a start that cannot run a program from a
// document root never reaches the inspection queue.
func TestDocrootExecObserveFiltersWithoutIO(t *testing.T) {
	m := newTestDocrootExecMonitor(t, make(chan alert.Finding, 1))
	for _, ev := range []ExecEvent{
		{UID: 1001, PID: 10, Filename: "/usr/bin/php"},
		{UID: 1001, PID: 11, Filename: "/home/alice/bin/tool"},
		{UID: 1001, PID: 12, Filename: "/home/alice/public_html_old/x"},
		{UID: 0, PID: 13, Filename: "/home/alice/public_html/x"},
	} {
		m.observe(ev)
	}
	if depth := m.queue.Snapshot(time.Now()).Depth; depth != 0 {
		t.Fatalf("queued %d starts, want none", depth)
	}

	m.observe(ExecEvent{UID: 1001, PID: 20, Filename: "/home/alice/public_html/wp-content/uploads/x"})
	// A relative name is resolved through /proc on the worker.
	m.observe(ExecEvent{UID: 1001, PID: 21, Filename: "./x"})
	if depth := m.queue.Snapshot(time.Now()).Depth; depth != 2 {
		t.Fatalf("queued %d starts, want the docroot and the relative one", depth)
	}
}

// The inspection queue is published beside the exec reader's rows, so a
// start lost to a full queue degrades a health row instead of disappearing.
func TestDocrootExecQueuePublished(t *testing.T) {
	m := newTestDocrootExecMonitor(t, make(chan alert.Finding, 1))
	for i := 0; i < docrootExecQueueSize+3; i++ {
		m.observe(ExecEvent{UID: 1001, PID: uint32(100 + i), Filename: "/home/alice/public_html/x"})
	}
	d := &Daemon{}
	d.registerBackendQueues("bpf.execution", docrootQueueBackend{m})
	got, ok := d.QueueStatuses()["bpf.execution.docroot"]
	if !ok {
		t.Fatal("docroot inspection queue was not published")
	}
	if got.DroppedTotal != 3 || got.Status != "degraded" || got.Capacity != docrootExecQueueSize {
		t.Fatalf("queue status = %+v, want 3 dropped starts and a degraded row", got)
	}
}

// docrootQueueBackend stands in for the BPF exec backend, which merges the
// monitor's rows into its own.
type docrootQueueBackend struct{ m *docrootExecMonitor }

func (docrootQueueBackend) Mode() string        { return "bpf" }
func (docrootQueueBackend) EventCount() uint64  { return 0 }
func (docrootQueueBackend) Run(context.Context) {}
func (b docrootQueueBackend) QueueStatuses(now time.Time) map[string]queuehealth.Status {
	return b.m.queueStatuses(now)
}

func TestDocrootExecWorkerInspectsQueuedStarts(t *testing.T) {
	alertCh := make(chan alert.Finding, 1)
	m := newTestDocrootExecMonitor(t, alertCh)
	var gotPID atomic.Int64
	var gotParent atomic.Value
	stubDocrootInspect(t, func(pid int, filename, parentComm string, roots *checks.DocrootIndex) *alert.Finding {
		gotPID.Store(int64(pid))
		gotParent.Store(parentComm)
		if roots.Lookup(filename) == "" {
			t.Errorf("worker passed roots that do not cover %s", filename)
		}
		return &alert.Finding{Severity: alert.Critical, Check: "docroot_binary_exec", FilePath: filename}
	})

	stop := m.start(context.Background(), func(f *alert.Finding, ev ExecEvent) { f.Details = "attached " + ev.Comm })
	m.observe(ExecEvent{UID: 1001, PID: 4242, Comm: "x", ParentComm: "lsphp", Filename: "/home/alice/public_html/x"})
	select {
	case f := <-alertCh:
		if f.FilePath != "/home/alice/public_html/x" || f.Details != "attached x" {
			t.Fatalf("finding = %+v, want the inspected start with process context attached", f)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("queued start was not inspected")
	}
	stop()
	if gotPID.Load() != 4242 || gotParent.Load() != "lsphp" {
		t.Fatalf("inspected pid/parent = %d/%v", gotPID.Load(), gotParent.Load())
	}
}

// Stopping accounts for every start: each one was inspected or is counted as
// lost, and nothing is left waiting or running.
func TestDocrootExecStopAccountsForPendingStarts(t *testing.T) {
	m := newTestDocrootExecMonitor(t, make(chan alert.Finding, 8))
	var inspected atomic.Int64
	release := make(chan struct{})
	stubDocrootInspect(t, func(int, string, string, *checks.DocrootIndex) *alert.Finding {
		if inspected.Add(1) == 1 {
			<-release
		}
		return nil
	})
	stop := m.start(context.Background(), func(*alert.Finding, ExecEvent) {})
	const starts = 4
	for i := 0; i < starts; i++ {
		m.observe(ExecEvent{UID: 1001, PID: uint32(200 + i), Filename: "/home/alice/public_html/x"})
	}
	deadline := time.Now().Add(5 * time.Second)
	for inspected.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	stopped := make(chan struct{})
	go func() {
		stop()
		close(stopped)
	}()
	close(release)
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("stop did not return")
	}
	status := m.queue.Snapshot(time.Now())
	if status.Depth != 0 || status.InFlight != 0 {
		t.Fatalf("queue after stop = %+v, want nothing waiting or running", status)
	}
	if got := uint64(inspected.Load()) + status.DroppedTotal; got != starts {
		t.Fatalf("inspected %d + dropped %d = %d, want %d", inspected.Load(), status.DroppedTotal, got, starts)
	}
}
