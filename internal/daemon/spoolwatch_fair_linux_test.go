//go:build linux

package daemon

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/metrics"
	emime "github.com/pidginhost/csm/internal/mime"
)

// buildSourceSpool writes a message whose -H names a remote sending host.
func buildSourceSpool(t *testing.T, dir, msgID, host string) {
	t.Helper()
	buildMinimalEximSpool(t, dir, msgID)
	path := filepath.Join(dir, msgID+"-H")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data = []byte(strings.Replace(string(data), "-local\n", "-host_address "+host+".25\n", 1))
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// gateExtractor blocks every extraction until released and records which
// messages were extracting at the same time.
type gateExtractor struct {
	size    int
	arrived chan string
	release chan struct{}

	mu        sync.Mutex
	active    int
	maxActive int
	order     []string
}

func newGateExtractor(size int) *gateExtractor {
	return &gateExtractor{size: size, arrived: make(chan string, 128), release: make(chan struct{}, 128)}
}

func (e *gateExtractor) Size() int { return e.size }

func (e *gateExtractor) Extract(ctx context.Context, _ int, header, _ *os.File, _ emime.Limits) (*emime.ExtractionResult, error) {
	msgID := strings.TrimSuffix(filepath.Base(header.Name()), "-H")
	e.mu.Lock()
	e.active++
	e.maxActive = max(e.maxActive, e.active)
	e.order = append(e.order, msgID)
	e.mu.Unlock()
	e.arrived <- msgID
	select {
	case <-e.release:
	case <-ctx.Done():
	}
	e.mu.Lock()
	e.active--
	e.mu.Unlock()
	return &emime.ExtractionResult{}, nil
}

func (e *gateExtractor) snapshot() (maxActive int, order []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.maxActive, append([]string(nil), e.order...)
}

// gateWatcher runs the scan goroutines over a gate extractor and stops them
// when the test ends.
func gateWatcher(t *testing.T, failMode string, ex *gateExtractor) (*SpoolWatcher, chan alert.Finding) {
	t.Helper()
	sw, _ := extractWatcher(failMode, ex)
	ch := make(chan alert.Finding, 256)
	sw.alertCh = ch
	sw.scanCh = make(chan spoolEvent, 64)
	sw.initQueueHealth()
	sw.startScanWorkers()
	t.Cleanup(func() {
		close(ex.release)
		close(sw.scanCh)
		sw.wg.Wait()
	})
	return sw, ch
}

func freshSourceWaits(t *testing.T) *metrics.CounterVec {
	t.Helper()
	orig := spoolSourceWaitsTotal
	spoolSourceWaitsTotal = metrics.NewCounterVec("test_spool_source_waits_total", "", []string{"outcome"})
	t.Cleanup(func() { spoolSourceWaitsTotal = orig })
	return spoolSourceWaitsTotal
}

func enqueue(t *testing.T, sw *SpoolWatcher, dir, msgID string) spoolEvent {
	t.Helper()
	evt := bodyEvent(t, dir, msgID)
	evt.queueTicket = sw.scannerHealth.Begin(time.Now())
	sw.scanCh <- evt
	return evt
}

func waitArrival(t *testing.T, ex *gateExtractor, want string) {
	t.Helper()
	select {
	case got := <-ex.arrived:
		if got != want {
			t.Fatalf("extracting %s, want %s", got, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("%s never reached extraction", want)
	}
}

func waitCounter(t *testing.T, c *metrics.Counter, want float64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for c.Value() < want {
		if time.Now().After(deadline) {
			t.Fatalf("counter = %v, want %v", c.Value(), want)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestSourceGateSlotLimits(t *testing.T) {
	for _, tc := range []struct{ slots, want int }{
		{1, 1}, {2, 1}, {3, 1}, {4, 2}, {5, 2}, {8, 4},
	} {
		t.Run(fmt.Sprintf("slots=%d", tc.slots), func(t *testing.T) {
			var g sourceGate
			g.setLimit(tc.slots)
			for i := range tc.want {
				if run, overflow := g.enter("sender", spoolEvent{}); !run || overflow {
					t.Fatalf("scan %d: run=%v overflow=%v, want admitted", i, run, overflow)
				}
			}
			if run, overflow := g.enter("sender", spoolEvent{path: "waiting"}); run || overflow {
				t.Fatalf("extra scan: run=%v overflow=%v, want parked", run, overflow)
			}
			if next, more := g.leave("sender"); !more || next.path != "waiting" {
				t.Fatalf("handoff = %+v, %v, want parked event", next, more)
			}
			for remaining := tc.want - 1; remaining >= 0; remaining-- {
				if _, more := g.leave("sender"); more {
					t.Fatal("handoff returned the parked event twice")
				}
				if remaining > 0 {
					if scans := g.busy["sender"]; scans == nil || scans.running != remaining {
						t.Fatalf("source = %+v, want %d running scans", scans, remaining)
					}
				} else if len(g.busy) != 0 {
					t.Fatalf("finished source retained: %+v", g.busy)
				}
			}
		})
	}
}

// Below the overflow limit, one sender uses at most half the slots. Its
// further messages wait their turn in arrival order.
func TestSourceGateLimitsOneSource(t *testing.T) {
	captureResponses(t)
	waits := freshSourceWaits(t)
	ex := newGateExtractor(4)
	sw, _ := gateWatcher(t, "open", ex)
	dir := t.TempDir()
	ids := []string{"1aBcDe-SRC000-XX", "1aBcDe-SRC001-XX", "1aBcDe-SRC002-XX", "1aBcDe-SRC003-XX"}
	for _, id := range ids {
		buildSourceSpool(t, dir, id, "192.0.2.10")
	}
	for i, id := range ids {
		enqueue(t, sw, dir, id)
		if i < 2 {
			waitArrival(t, ex, id)
		} else {
			waitCounter(t, waits.With("waited"), float64(i-1))
		}
	}
	for _, id := range ids[2:] {
		ex.release <- struct{}{}
		waitArrival(t, ex, id)
	}
	ex.release <- struct{}{}
	ex.release <- struct{}{}
	maxActive, order := ex.snapshot()
	if maxActive != 2 {
		t.Fatalf("%d messages from one source extracted at once on 4 slots, want 2", maxActive)
	}
	if strings.Join(order, ",") != strings.Join(ids, ",") {
		t.Fatalf("scan order %v, want arrival order %v", order, ids)
	}
}

func TestSourceGateOtherSourceNotBlocked(t *testing.T) {
	captureResponses(t)
	ex := newGateExtractor(4)
	sw, _ := gateWatcher(t, "open", ex)
	dir := t.TempDir()
	buildSourceSpool(t, dir, "1aBcDe-SRCA00-XX", "192.0.2.10")
	buildSourceSpool(t, dir, "1aBcDe-SRCB00-XX", "198.51.100.7")
	enqueue(t, sw, dir, "1aBcDe-SRCA00-XX")
	waitArrival(t, ex, "1aBcDe-SRCA00-XX")
	enqueue(t, sw, dir, "1aBcDe-SRCB00-XX")
	waitArrival(t, ex, "1aBcDe-SRCB00-XX")
}

// A sender past its wait limit is still scanned: one sender key can stand
// for a whole gateway, localhost or Exim's own bounces, so answering without
// a scan would let a slow message open the door for everyone behind it.
func TestSourceGateOverflowStillScans(t *testing.T) {
	responses := captureResponses(t)
	waits := freshSourceWaits(t)
	ex := newGateExtractor(4)
	sw, findings := gateWatcher(t, "tempfail", ex)
	dir := t.TempDir()
	id := func(i int) string { return fmt.Sprintf("1aBcDe-FL%04d-XX", i) }
	const total = 2 + maxSourceWaiting + 2
	var events []spoolEvent
	for i := range total {
		buildSourceSpool(t, dir, id(i), "192.0.2.10")
	}
	for i := range total {
		events = append(events, enqueue(t, sw, dir, id(i)))
		switch {
		case i < 2:
			waitArrival(t, ex, id(i))
		case i < 2+maxSourceWaiting:
			waitCounter(t, waits.With("waited"), float64(i-1))
		}
	}
	waitCounter(t, waits.With("overflow"), 2)
	overflow := map[string]bool{}
	for range 2 {
		select {
		case got := <-ex.arrived:
			overflow[got] = true
		case <-time.After(5 * time.Second):
			t.Fatal("overflowing messages were not scanned")
		}
	}
	if !overflow[id(total-2)] || !overflow[id(total-1)] {
		t.Fatalf("scanned %v, want the two overflowing messages", overflow)
	}
	if got := responses(); len(got) != 0 {
		t.Fatalf("responses = %+v, want no message answered before its scan", got)
	}
	fs := takeFindings(findings)
	if n := len(findingsFor(fs, "email_av_hold_bypass")); n != 0 {
		t.Fatalf("hold bypass findings = %d, want 0", n)
	}
	backlog := findingsFor(fs, "email_av_source_backlog")
	if len(backlog) != 1 || !strings.Contains(backlog[0].Message, `"ip:192.0.2.10"`) || backlog[0].Severity != alert.Warning {
		t.Fatalf("source backlog findings = %+v, want one Warning naming the source", backlog)
	}
	for range total {
		ex.release <- struct{}{}
	}
	close(sw.stopCh)
	sw.wg.Wait()
	got := waitForResponses(t, responses, total, 10*time.Second)
	if len(got) != total {
		t.Fatalf("responses = %d, want all %d messages scanned and answered", len(got), total)
	}
	for _, r := range got {
		if r.response != FAN_ALLOW {
			t.Fatalf("clean message answered %d, want allowed after its scan", r.response)
		}
	}
	if _, order := ex.snapshot(); len(order) != total {
		t.Fatalf("extractions = %d, want %d", len(order), total)
	}
	for _, evt := range events {
		count := 0
		for _, r := range got {
			if int(r.fd) == evt.fd {
				count++
			}
		}
		if count != 1 {
			t.Errorf("fd %d received %d responses, want one", evt.fd, count)
		}
		assertFDClosed(t, evt.fd, "scanned source event")
	}
	if len(sw.sources.busy) != 0 {
		t.Fatalf("finished scans retained sources: %+v", sw.sources.busy)
	}
	if q := sw.scannerHealth.Snapshot(time.Now()); q.Depth != 0 || q.InFlight != 0 {
		t.Fatalf("finished scans retained queue work: %+v", q)
	}
}

// Completing an overflow scan must not release an admitted scan's claim or
// take any parked work, even if the overflow handler panics.
func TestSourceGateOverflowPreservesClaims(t *testing.T) {
	for _, panics := range []bool{false, true} {
		t.Run(fmt.Sprintf("panic=%v", panics), func(t *testing.T) {
			responses := captureResponses(t)
			sw, _ := extractWatcher("open", &recordingExtractor{size: 4})
			sw.sources.setLimit(4)
			const src = "ip:192.0.2.10"
			for range 2 {
				sw.sources.enter(src, spoolEvent{fd: -1})
			}
			for i := range maxSourceWaiting {
				sw.sources.enter(src, spoolEvent{fd: -1, path: fmt.Sprintf("waiting-%d", i)})
			}
			original := spoolEventHandler
			t.Cleanup(func() { spoolEventHandler = original })
			calls := 0
			spoolEventHandler = func(_ *SpoolWatcher, evt spoolEvent) {
				calls++
				if evt.slot != 2 || evt.source != src {
					t.Errorf("overflow slot=%d source=%q, want slot 2 and %q", evt.slot, evt.source, src)
				}
				if panics {
					panic("overflow scan failed")
				}
			}
			dir := t.TempDir()
			buildSourceSpool(t, dir, "1aBcDe-CLAIMS-XX", "192.0.2.10")
			evt := bodyEvent(t, dir, "1aBcDe-CLAIMS-XX")
			sw.handleFair(2, evt)
			if calls != 1 {
				t.Fatalf("handler calls=%d, want only the overflow scan", calls)
			}
			if got := responses(); len(got) != 1 || int(got[0].fd) != evt.fd || got[0].response != FAN_ALLOW {
				t.Fatalf("responses=%+v, want one allow for overflow", got)
			}
			assertFDClosed(t, evt.fd, "completed overflow event")
			scans := sw.sources.busy[src]
			if scans == nil || scans.running != 2 || len(scans.waiting) != maxSourceWaiting {
				t.Fatalf("source after overflow=%+v, want two claims and all waiters", scans)
			}
			for i, queued := range scans.waiting {
				if queued.path != fmt.Sprintf("waiting-%d", i) {
					t.Fatalf("waiter %d=%q, want its original position", i, queued.path)
				}
			}
		})
	}
}

// A message parked behind its sender keeps its hold. When the hold runs out
// it follows fail_mode, does not count toward the bypass, and is still
// scanned once its turn comes.
func TestSourceGateWaitExpiryNotCounted(t *testing.T) {
	responses := captureResponses(t)
	shortHoldBudget(t, time.Minute)
	orig := spoolHoldExpiredTotal
	spoolHoldExpiredTotal = metrics.NewCounterVec("test_spool_hold_expired_total", "", []string{"stage"})
	t.Cleanup(func() { spoolHoldExpiredTotal = orig })
	waits := freshSourceWaits(t)
	ex := newGateExtractor(4)
	sw, findings := gateWatcher(t, "tempfail", ex)
	sw.permissionMode = true
	dir := t.TempDir()
	ids := []string{"1aBcDe-WX0000-XX", "1aBcDe-WX0001-XX", "1aBcDe-WX0002-XX", "1aBcDe-WX0003-XX"}
	var events []spoolEvent
	for _, id := range ids {
		buildSourceSpool(t, dir, id, "192.0.2.10")
	}
	for i, id := range ids {
		evt := bodyEvent(t, dir, id)
		evt.queueTicket = sw.scannerHealth.Begin(time.Now())
		evt.guard = sw.newHoldGuard(int32(evt.fd), true) // #nosec G115 -- test fd fits in int32.
		events = append(events, evt)
		sw.scanCh <- evt
		if i < 2 {
			waitArrival(t, ex, id)
		} else {
			waitCounter(t, waits.With("waited"), float64(i-1))
		}
	}
	// Expire only after each event reached its intended stage. Wall-clock
	// timers could fire in the admission queue on a loaded test runner.
	for _, evt := range events {
		evt.guard.expire()
	}
	got := waitForResponses(t, responses, 4, 5*time.Second)
	if len(got) != 4 {
		t.Fatalf("responses = %d, want every expired hold answered", len(got))
	}
	for _, r := range got {
		if r.response != FAN_DENY {
			t.Fatalf("expired hold answered %d, want tempfail deferral", r.response)
		}
	}
	if v := spoolHoldExpiredTotal.With("waiting").Value(); v != 2 {
		t.Fatalf("waiting expiries = %v, want 2", v)
	}
	if sw.holds.bypassing(time.Now()) || len(findingsFor(takeFindings(findings), "email_av_hold_bypass")) != 0 {
		t.Fatal("expiries behind a busy source started the bypass")
	}
	for _, id := range ids[2:] {
		ex.release <- struct{}{}
		waitArrival(t, ex, id)
	}
	ex.release <- struct{}{}
	ex.release <- struct{}{}
	close(sw.stopCh)
	sw.wg.Wait()
	if len(responses()) != 4 {
		t.Fatal("a late scan wrote a second verdict")
	}
	for _, evt := range events {
		assertFDClosed(t, evt.fd, "expired source event")
	}
}

func TestSourceGateDrainsOnStop(t *testing.T) {
	for _, shutdown := range []bool{true, false} {
		t.Run(fmt.Sprintf("daemon_stop=%v", shutdown), func(t *testing.T) {
			responses := captureResponses(t)
			shortHoldBudget(t, time.Minute)
			waits := freshSourceWaits(t)
			dir := t.TempDir()
			ex := newGateExtractor(4)
			sw, _ := gateWatcher(t, "tempfail", ex)
			sw.permissionMode = true
			daemonStop := make(chan struct{})
			sw.daemonStop = daemonStop
			var events []spoolEvent
			for i := range 6 {
				id := fmt.Sprintf("1aBcDe-ST%04d-XX", i)
				buildSourceSpool(t, dir, id, "192.0.2.10")
				evt := bodyEvent(t, dir, id)
				evt.queueTicket = sw.scannerHealth.Begin(time.Now())
				evt.guard = sw.newHoldGuard(int32(evt.fd), true) // #nosec G115 -- test fd fits in int32.
				events = append(events, evt)
				sw.scanCh <- evt
				if i < 2 {
					waitArrival(t, ex, id)
				} else {
					waitCounter(t, waits.With("waited"), float64(i-1))
				}
			}
			if shutdown {
				close(daemonStop)
			}
			close(sw.stopCh)
			// Shutdown skips parked extractions; a restart must finish them
			// before the replacement watcher can reuse the worker slots.
			ex.release <- struct{}{}
			ex.release <- struct{}{}
			if !shutdown {
				for range len(events) - 2 {
					ex.release <- struct{}{}
				}
			}
			done := make(chan struct{})
			go func() { sw.wg.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("scan goroutines did not return after stop")
			}
			got := responses()
			if len(got) != len(events) {
				t.Fatalf("responses = %+v, want one per event", got)
			}
			for _, evt := range events {
				n := 0
				for _, r := range got {
					if int(r.fd) == evt.fd && r.response == FAN_ALLOW {
						n++
					}
				}
				if n != 1 {
					t.Errorf("fd %d got %d allow responses, want 1", evt.fd, n)
				}
				assertFDClosed(t, evt.fd, "event drained on stop")
			}
			wantScans := len(events)
			if shutdown {
				wantScans = 2
			}
			if maxActive, order := ex.snapshot(); maxActive != 2 || len(order) != wantScans {
				t.Fatalf("extractions = %v (max active %d), want %d scans, at most 2 at once", order, maxActive, wantScans)
			}
			if len(sw.sources.busy) != 0 {
				t.Fatal("stopped watcher retained parked source events")
			}
			if q := sw.scannerHealth.Snapshot(time.Now()); q.Depth != 0 || q.InFlight != 0 {
				t.Fatalf("stopped watcher retained queue work: %+v", q)
			}
		})
	}
}

func TestSourceGateSkipsUnreadableHeader(t *testing.T) {
	cases := []struct {
		name string
		make func(t *testing.T, header string)
	}{
		{"missing", func(t *testing.T, header string) {
			if err := os.Remove(header); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlink", func(t *testing.T, header string) {
			if err := os.Rename(header, header+".real"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(header+".real", header); err != nil {
				t.Fatal(err)
			}
		}},
		{"fifo", func(t *testing.T, header string) {
			if err := os.Remove(header); err != nil {
				t.Fatal(err)
			}
			if err := unix.Mkfifo(header, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			responses := captureResponses(t)
			waits := freshSourceWaits(t)
			dir := t.TempDir()
			msgID := "1aBcDe-UNREAD-XX"
			buildSourceSpool(t, dir, msgID, "192.0.2.10")
			tc.make(t, filepath.Join(dir, msgID+"-H"))
			ex := &recordingExtractor{size: 1}
			sw, ch := extractWatcher("tempfail", ex)
			evt := bodyEvent(t, dir, msgID)
			if src := sw.spoolSource(evt); src != "" {
				t.Fatalf("source = %q, want none for an unreadable -H", src)
			}
			sw.scanCh = make(chan spoolEvent, 1)
			sw.initQueueHealth()
			evt.queueTicket = sw.scannerHealth.Begin(time.Now())
			sw.scanCh <- evt
			close(sw.scanCh)
			sw.wg.Add(1)
			sw.scanWorker(0)
			got := responses()
			fs := takeFindings(ch)
			if tc.name == "missing" {
				if len(got) != 1 || got[0].response != FAN_ALLOW || len(fs) != 0 {
					t.Fatalf("missing -H: responses %+v findings %+v, want a silent allow", got, fs)
				}
			} else if len(got) != 1 || got[0].response != FAN_DENY || len(findingsFor(fs, "email_av_parse_error")) != 1 {
				t.Fatalf("responses %+v findings %+v, want today's parse error under tempfail", got, fs)
			}
			if waits.With("waited").Value() != 0 || waits.With("overflow").Value() != 0 {
				t.Fatal("event with no source went through the gate")
			}
			assertFDClosed(t, evt.fd, "ungated event")
		})
	}
}

func TestSourceGatePanicFreesSource(t *testing.T) {
	responses := captureResponses(t)
	waits := freshSourceWaits(t)
	orig := spoolEventHandler
	t.Cleanup(func() { spoolEventHandler = orig })
	started := make(chan string, 4)
	release := make(chan struct{})
	spoolEventHandler = func(_ *SpoolWatcher, evt spoolEvent) {
		started <- filepath.Base(evt.path)
		if strings.Contains(evt.path, "PANIC") {
			<-release
			panic("scan failed")
		}
	}
	sw, _ := extractWatcher("open", &recordingExtractor{size: 1})
	sw.alertCh = make(chan alert.Finding, 16)
	sw.scanCh = make(chan spoolEvent, 4)
	sw.initQueueHealth()
	sw.wg.Add(1)
	go sw.scanWorker(0)
	sw.wg.Add(1)
	go sw.scanWorker(1)
	dir := t.TempDir()
	buildSourceSpool(t, dir, "1aBcDe-PANIC0-XX", "192.0.2.10")
	buildSourceSpool(t, dir, "1aBcDe-AFTER0-XX", "192.0.2.10")
	first := enqueue(t, sw, dir, "1aBcDe-PANIC0-XX")
	if got := <-started; got != "1aBcDe-PANIC0-XX-D" {
		t.Fatalf("first handled %s", got)
	}
	next := enqueue(t, sw, dir, "1aBcDe-AFTER0-XX")
	waitCounter(t, waits.With("waited"), 1)
	close(release)
	select {
	case got := <-started:
		if got != "1aBcDe-AFTER0-XX-D" {
			t.Fatalf("after the panic handled %s", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a panic left the source busy")
	}
	close(sw.scanCh)
	sw.wg.Wait()
	got := responses()
	if len(got) != 2 || int(got[0].fd) != first.fd || int(got[1].fd) != next.fd {
		t.Fatalf("responses = %+v, want one for the panicking event and one for its waiter", got)
	}
	assertFDClosed(t, first.fd, "panicking event")
	assertFDClosed(t, next.fd, "event parked behind panic")
	if len(sw.sources.busy) != 0 {
		t.Fatal("panic left source events parked")
	}
}

// Source parsing reads attacker-influenced bytes before the handler's panic
// guard. A parser bug must not crash the daemon on every redelivery.
func TestSourceGateSurvivesSourceParserPanic(t *testing.T) {
	responses := captureResponses(t)
	orig := readSpoolSource
	readSpoolSource = func(io.Reader) (string, error) { panic("parser bug") }
	t.Cleanup(func() { readSpoolSource = orig })
	ex := &recordingExtractor{size: 1}
	sw, _ := extractWatcher("open", ex)
	sw.scanCh = make(chan spoolEvent, 1)
	sw.initQueueHealth()
	dir := t.TempDir()
	buildSourceSpool(t, dir, "1aBcDe-PNCSRC-XX", "192.0.2.10")
	evt := enqueue(t, sw, dir, "1aBcDe-PNCSRC-XX")
	close(sw.scanCh)
	sw.wg.Add(1)
	sw.scanWorker(0)
	if got := responses(); len(got) != 1 || got[0].response != FAN_ALLOW {
		t.Fatalf("responses = %+v, want the message handled", got)
	}
	if n := len(ex.recorded()); n != 1 {
		t.Fatalf("extractor calls = %d, want the message still scanned", n)
	}
	assertFDClosed(t, evt.fd, "event after a source parser panic")
}
