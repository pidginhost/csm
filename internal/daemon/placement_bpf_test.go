//go:build linux && bpf

package daemon

import (
	"context"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/alert"
	bpfprog "github.com/pidginhost/csm/internal/daemon/placement_bpfprog"
	"github.com/pidginhost/csm/internal/queuehealth"
)

// fakePlacementSource stands in for the ring reader: a bounded queue that
// drops when full and closes when its context ends, like bpf.Reader.
type fakePlacementSource struct {
	q    *queuehealth.Channel[PlacementRawEvent]
	errs chan error
	done chan struct{}
}

func newFakePlacementSource(capacity int) *fakePlacementSource {
	return &fakePlacementSource{q: queuehealth.NewChannel[PlacementRawEvent](capacity, time.Minute), errs: make(chan error), done: make(chan struct{})}
}

func (f *fakePlacementSource) Start(ctx context.Context) func() {
	go func() {
		<-ctx.Done()
		f.q.Close()
		close(f.errs)
		close(f.done)
	}()
	return func() {
		<-f.done
		f.q.DiscardPending()
	}
}

func (f *fakePlacementSource) Events() <-chan queuehealth.Work[PlacementRawEvent] { return f.q.Items() }
func (f *fakePlacementSource) Errors() <-chan error                               { return f.errs }
func (f *fakePlacementSource) QueueStatuses(now time.Time) map[string]queuehealth.Status {
	return map[string]queuehealth.Status{"output": f.q.Snapshot(now)}
}

func startFakePlacementBackend(t *testing.T, capacity int, handle func(placementEvent)) (*placementBPF, *fakePlacementSource, chan alert.Finding) {
	t.Helper()
	alerts := make(chan alert.Finding, 16)
	src := newFakePlacementSource(capacity)
	p := &placementBPF{
		objs:       &bpfprog.PlacementObjects{},
		source:     src,
		fm:         placementTestMonitor(alerts),
		handle:     handle,
		mounts:     []mountEntry{{Dev: unix.Mkdev(259, 3), Root: "/", MountPoint: "/home"}},
		unresolved: queuehealth.New(0, time.Minute),
	}
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() { p.Run(ctx); close(stopped) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-stopped:
		case <-time.After(5 * time.Second):
			t.Error("Run did not return after cancel")
		}
	})
	return p, src, alerts
}

func placedRaw(name string) PlacementRawEvent {
	return PlacementRawEvent{Kind: 1, PID: 7, Dev: kernelDeviceID(unix.Mkdev(259, 3)), Ino: 11, Components: []string{name, "user"}}
}

// A rename flood must not grow goroutines or stall the ring reader: at most
// placementWorkers handlers run, the queue holds its capacity, and the rest
// is dropped and counted.
func TestPlacementWorkersAreBoundedAndOverflowIsCounted(t *testing.T) {
	entered := make(chan placementEvent, 64)
	gate := make(chan struct{})
	p, src, _ := startFakePlacementBackend(t, 2, func(ev placementEvent) {
		entered <- ev
		<-gate
	})
	defer close(gate)
	if !src.q.TrySend(placedRaw("first.php")) {
		t.Fatal("empty queue refused an event")
	}
	select {
	case ev := <-entered:
		want := placementEvent{Path: "/home/user/first.php", Dev: unix.Mkdev(259, 3), Ino: 11, PID: 7, Kind: placementRename}
		ev.At = time.Time{}
		if ev != want {
			t.Fatalf("handled %+v, want %+v", ev, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("event never reached a worker")
	}
	for range placementWorkers - 1 {
		src.q.TrySend(placedRaw("busy.php"))
		<-entered
	}
	// Every worker is blocked; two more fit the queue, the next is dropped.
	for i := range 3 {
		if sent := src.q.TrySend(placedRaw("queued.php")); sent != (i < 2) {
			t.Fatalf("send %d accepted=%v", i, sent)
		}
	}
	select {
	case ev := <-entered:
		t.Fatalf("a handler beyond the worker bound ran: %+v", ev)
	case <-time.After(100 * time.Millisecond):
	}
	if out := p.QueueStatuses(time.Now())["output"]; out.DroppedTotal != 1 || out.Depth != 2 || out.InFlight != placementWorkers {
		t.Fatalf("output queue status %+v, want 1 dropped, 2 waiting, %d running", out, placementWorkers)
	}
}

func TestPlacementWorkerSurvivesHandlerPanic(t *testing.T) {
	handled := make(chan string, 4)
	_, src, alerts := startFakePlacementBackend(t, 4, func(ev placementEvent) {
		if strings.HasSuffix(ev.Path, "boom.php") {
			panic("crafted placement")
		}
		handled <- ev.Path
	})
	src.q.TrySend(placedRaw("boom.php"))
	src.q.TrySend(placedRaw("after.php"))
	select {
	case path := <-handled:
		if path != "/home/user/after.php" {
			t.Fatalf("handled %s", path)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("placement after a panic was never handled")
	}
	deadline := time.After(5 * time.Second)
	for {
		select {
		case f := <-alerts:
			if f.Check == "realtime_scanner_panic" && f.FilePath == "/home/user/boom.php" {
				return
			}
		case <-deadline:
			t.Fatal("panic was not reported")
		}
	}
}

func TestUnresolvedPlacementIsCountedAndNotHandled(t *testing.T) {
	handled := make(chan placementEvent, 1)
	p, src, alerts := startFakePlacementBackend(t, 4, func(ev placementEvent) { handled <- ev })
	raw := placedRaw("deep.php")
	raw.Truncated = true
	src.q.TrySend(raw)
	deadline := time.After(5 * time.Second)
	for p.QueueStatuses(time.Now())["unresolved"].DroppedTotal != 1 {
		select {
		case <-deadline:
			t.Fatalf("unresolved placement not counted: %+v", p.QueueStatuses(time.Now()))
		case <-time.After(10 * time.Millisecond):
		}
	}
	select {
	case ev := <-handled:
		t.Fatalf("truncated placement handled as %+v", ev)
	default:
	}
	if found := unresolvedPlacementFindings(t, alerts); len(found) != 1 {
		t.Fatalf("unresolved findings %+v, want one", found)
	}
}

// A worker may reach an event long after the ring delivered it. The event
// keeps the time it was read, which restore detection compares with the
// placing process's start time.
func TestPlacementKeepsTheRingReadTime(t *testing.T) {
	handled := make(chan placementEvent, 1)
	_, src, _ := startFakePlacementBackend(t, 4, func(ev placementEvent) { handled <- ev })
	raw := placedRaw("late.php")
	raw.At = time.Now().Add(-time.Hour)
	src.q.TrySend(raw)
	select {
	case ev := <-handled:
		if !ev.At.Equal(raw.At) {
			t.Fatalf("handled at %v, want the read time %v", ev.At, raw.At)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("event never reached a worker")
	}
}
