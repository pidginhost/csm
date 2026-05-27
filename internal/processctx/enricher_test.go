package processctx

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeReader implements the same Read shape as ProcReader without touching
// /proc. allows test control over latency and result.
type fakeReader struct {
	delay time.Duration
	calls atomic.Int64
	uid   int
	comm  string
}

type procReaderFunc func(pid int) (processEntry, error)

func (f procReaderFunc) Read(pid int) (processEntry, error) { return f(pid) }

func (f *fakeReader) Read(pid int) (processEntry, error) {
	f.calls.Add(1)
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	uid := f.uid
	if uid == 0 {
		uid = 1000 + pid%100
	}
	comm := f.comm
	if comm == "" {
		comm = "fake"
	}
	return processEntry{PID: pid, Comm: comm, UID: uid, UIDKnown: true, ProcRead: true}, nil
}

type fakeResolver struct{}

func (fakeResolver) Resolve(uid int) (string, string) {
	return "alice", "alice"
}

func TestEnricherEnqueueAndDrain(t *testing.T) {
	c := newTestCache(64, 0)
	r := &fakeReader{}
	e := NewEnricher(c, r, EnricherConfig{Workers: 2, QueueCap: 8})
	e.Start()
	defer e.Stop()

	for pid := 1; pid <= 4; pid++ {
		if !e.Enqueue(EnrichRequest{PID: pid}) {
			t.Fatalf("Enqueue(%d) reported full unexpectedly", pid)
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if c.Len() == 4 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if c.Len() != 4 {
		t.Fatalf("expected 4 cached entries, got %d", c.Len())
	}
	if got := r.calls.Load(); got != 4 {
		t.Errorf("Read called: want 4, got %d", got)
	}
}

func TestEnricherDropsWhenFull(t *testing.T) {
	c := newTestCache(64, 0)
	r := &fakeReader{delay: 50 * time.Millisecond}
	e := NewEnricher(c, r, EnricherConfig{Workers: 1, QueueCap: 2})
	e.Start()
	defer e.Stop()

	for pid := 1; pid <= 50; pid++ {
		if !e.Enqueue(EnrichRequest{PID: pid}) {
			t.Fatalf("Enqueue(%d) failed; drop-oldest should keep producers nonblocking", pid)
		}
	}
	if got := e.Stats().Drops; got == 0 {
		t.Errorf("Stats().Drops: want >0, got %d", got)
	}
}

func TestEnricherRejectsStalePIDReuse(t *testing.T) {
	c := newTestCache(8, 0)
	e := NewEnricher(c, &fakeReader{uid: 2000, comm: "other"}, EnricherConfig{Workers: 1, QueueCap: 4})
	e.Start()
	defer e.Stop()

	if !e.Enqueue(EnrichRequest{PID: 1234, UID: 1001, Comm: "ncat"}) {
		t.Fatal("enqueue failed")
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if e.Stats().Stale > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, ok := c.Get(1234); ok {
		t.Fatal("stale PID reuse must not be cached")
	}
	if e.Stats().Stale == 0 {
		t.Fatalf("expected stale counter to move; stats=%+v", e.Stats())
	}
}

func TestEnricherRejectsMissingUIDWhenRequestHasRootUID(t *testing.T) {
	c := newTestCache(8, 0)
	reader := procReaderFunc(func(pid int) (processEntry, error) {
		return processEntry{PID: pid, Comm: "bash", ProcRead: true}, nil
	})
	e := NewEnricher(c, reader, EnricherConfig{Workers: 1, QueueCap: 4})
	e.Start()
	defer e.Stop()

	if !e.Enqueue(EnrichRequest{PID: 1234, UID: 0, UIDKnown: true, Comm: "bash"}) {
		t.Fatal("enqueue failed")
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if e.Stats().Stale > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, ok := c.Get(1234); ok {
		t.Fatal("entry without confirmed UID must not be cached as root")
	}
	if e.Stats().Stale == 0 {
		t.Fatalf("expected stale counter to move; stats=%+v", e.Stats())
	}
}

func TestEnricherAcceptsConfirmedRootUID(t *testing.T) {
	c := newTestCache(8, 0)
	reader := procReaderFunc(func(pid int) (processEntry, error) {
		return processEntry{PID: pid, UID: 0, UIDKnown: true, Comm: "bash", ProcRead: true}, nil
	})
	e := NewEnricher(c, reader, EnricherConfig{Workers: 1, QueueCap: 4})
	e.Start()
	defer e.Stop()

	if !e.Enqueue(EnrichRequest{PID: 1234, UID: 0, UIDKnown: true, Comm: "bash"}) {
		t.Fatal("enqueue failed")
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if pc := c.Materialize(1234); pc != nil {
			if pc.UID != 0 {
				t.Fatalf("Process UID: want 0, got %+v", pc)
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("confirmed root entry was not cached; stats=%+v", e.Stats())
}

func TestEnricherPopulatesUserAndAccount(t *testing.T) {
	c := newTestCache(8, 0)
	e := NewEnricher(c, &fakeReader{uid: 1001, comm: "ncat"}, EnricherConfig{
		Workers:  1,
		QueueCap: 4,
		Resolver: fakeResolver{},
	})
	e.Start()
	defer e.Stop()

	if !e.Enqueue(EnrichRequest{PID: 1234, UID: 1001, Comm: "ncat"}) {
		t.Fatal("enqueue failed")
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if pc := c.Materialize(1234); pc != nil && pc.User == "alice" && pc.Account == "alice" {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("user/account never populated; entry=%+v", c.Materialize(1234))
}

func TestEnricherStopIsIdempotent(t *testing.T) {
	c := newTestCache(8, 0)
	e := NewEnricher(c, &fakeReader{}, EnricherConfig{Workers: 1, QueueCap: 4})
	e.Start()
	e.Start()
	e.Stop()
	e.Stop() // must not panic or block
}

func TestEnricherEnqueueAfterStopReturnsFalse(t *testing.T) {
	c := newTestCache(8, 0)
	e := NewEnricher(c, &fakeReader{}, EnricherConfig{Workers: 1, QueueCap: 4})
	e.Start()
	e.Stop()
	if e.Enqueue(EnrichRequest{PID: 1}) {
		t.Fatal("enqueue after stop should return false")
	}
}

func TestEnricherEnqueueStopRaceNoPanic(t *testing.T) {
	c := newTestCache(64, 0)
	e := NewEnricher(c, &fakeReader{delay: time.Millisecond}, EnricherConfig{Workers: 1, QueueCap: 4})
	e.Start()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for pid := 1; pid <= 1000; pid++ {
			e.Enqueue(EnrichRequest{PID: pid})
		}
	}()
	e.Stop()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("enqueue goroutine did not exit after Stop")
	}
}

func TestEnricherDoesNotBlockProducer(t *testing.T) {
	c := newTestCache(64, 0)
	r := &fakeReader{delay: time.Second}
	e := NewEnricher(c, r, EnricherConfig{Workers: 1, QueueCap: 1})
	e.Start()
	defer e.Stop()

	var wg sync.WaitGroup
	wg.Add(1)
	start := time.Now()
	go func() {
		defer wg.Done()
		for pid := 1; pid <= 100; pid++ {
			e.Enqueue(EnrichRequest{PID: pid})
		}
	}()
	wg.Wait()
	if took := time.Since(start); took > 200*time.Millisecond {
		t.Errorf("producer was blocked; took %v", took)
	}
}

// TestEnricherRejectsPIDReuseByStartTime: when the detector supplies
// an event start time and /proc reports a different start time for the
// same PID, the enricher must drop the finding instead of caching the
// new process under the old detector's event.
func TestEnricherRejectsPIDReuseByStartTime(t *testing.T) {
	c := newTestCache(8, 0)
	detected := time.Unix(1700000000, 0)
	reused := detected.Add(time.Hour)
	reader := procReaderFunc(func(pid int) (processEntry, error) {
		return processEntry{
			PID: pid, Comm: "ncat", UID: 1001, UIDKnown: true,
			ProcRead: true, StartedAt: reused,
		}, nil
	})
	e := NewEnricher(c, reader, EnricherConfig{Workers: 1, QueueCap: 4})
	e.Start()
	defer e.Stop()

	if !e.Enqueue(EnrichRequest{
		PID: 1234, UID: 1001, UIDKnown: true, Comm: "ncat", StartedAt: detected,
	}) {
		t.Fatal("enqueue failed")
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if e.Stats().Stale > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, ok := c.Get(1234); ok {
		t.Fatal("PID-reuse mismatch must not be cached")
	}
	if e.Stats().Stale == 0 {
		t.Fatalf("expected stale counter to move; stats=%+v", e.Stats())
	}
}

// TestEnricherAcceptsMatchingStartTime: when /proc reports a start
// time inside the tolerance window, caching proceeds normally.
func TestEnricherAcceptsMatchingStartTime(t *testing.T) {
	c := newTestCache(8, 0)
	detected := time.Unix(1700000000, 0)
	matching := detected.Add(200 * time.Millisecond)
	reader := procReaderFunc(func(pid int) (processEntry, error) {
		return processEntry{
			PID: pid, Comm: "ncat", UID: 1001, UIDKnown: true,
			ProcRead: true, StartedAt: matching,
		}, nil
	})
	e := NewEnricher(c, reader, EnricherConfig{Workers: 1, QueueCap: 4})
	e.Start()
	defer e.Stop()

	if !e.Enqueue(EnrichRequest{
		PID: 1234, UID: 1001, UIDKnown: true, Comm: "ncat", StartedAt: detected,
	}) {
		t.Fatal("enqueue failed")
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if _, ok := c.Get(1234); ok {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, ok := c.Get(1234); !ok {
		t.Fatalf("matching start time should be cached; stats=%+v", e.Stats())
	}
}
