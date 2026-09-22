package daemon

import (
	"net"
	"runtime"
	"sync"
	"testing"
	"time"
)

// Profiles accumulate for the process lifetime. Count events at our workload's
// stack, not distinct stacks or unrelated background goroutine samples.
func contentionSamples(profile func([]runtime.BlockProfileRecord) (int, bool), function string) int64 {
	var records []runtime.BlockProfileRecord
	for {
		n, ok := profile(records)
		if !ok {
			records = make([]runtime.BlockProfileRecord, n+16)
			continue
		}
		var count int64
		for _, record := range records[:n] {
			frames := runtime.CallersFrames(record.Stack())
			for {
				frame, more := frames.Next()
				if frame.Function == "github.com/pidginhost/csm/internal/daemon."+function {
					count += record.Count
					break
				}
				if !more {
					break
				}
			}
		}
		return count
	}
}

func contendedMutexSamples(t *testing.T) int64 {
	t.Helper()
	var mu sync.Mutex
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 2000; i++ {
				mu.Lock()
				// Force waiters even with GOMAXPROCS=1; a short critical
				// section alone need not contend at all.
				runtime.Gosched()
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return contentionSamples(runtime.MutexProfile, "contendedMutexSamples.func1")
}

func blockedChannelSamples(t *testing.T) int64 {
	t.Helper()
	started := make(chan struct{})
	ready := make(chan struct{})
	done := make(chan struct{})
	go func() {
		close(started)
		<-ready
		close(done)
	}()
	<-started
	time.Sleep(20 * time.Millisecond)
	close(ready)
	<-done
	return contentionSamples(runtime.BlockProfile, "blockedChannelSamples.func1")
}

func newTestPprofDaemon(t *testing.T) *Daemon {
	t.Helper()
	d := &Daemon{stopCh: make(chan struct{})}
	t.Cleanup(func() {
		select {
		case <-d.stopCh:
		default:
			close(d.stopCh)
		}
		waitForPprofWorkers(t, d)
	})
	return d
}

func waitForPprofWorkers(t *testing.T, d *Daemon) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("pprof workers did not stop")
	}
}

func startTestPprofListener(t *testing.T) *Daemon {
	t.Helper()
	withPprofListen(t, func(string, string) (net.Listener, error) {
		return newBlockingPprofListener("127.0.0.1:6060"), nil
	})
	d := newTestPprofDaemon(t)
	if !d.startPprofListener("127.0.0.1:6060") {
		t.Fatal("pprof listener did not start on a loopback address")
	}
	return d
}

func TestPprofListenerRecordsMutexContention(t *testing.T) {
	before := contendedMutexSamples(t)
	startTestPprofListener(t)

	if got := contendedMutexSamples(t); got <= before {
		t.Fatalf("mutex profile recorded %d samples after %d, want the listener to enable sampling", got, before)
	}
}

func TestPprofListenerRecordsBlockingEvents(t *testing.T) {
	before := blockedChannelSamples(t)
	startTestPprofListener(t)

	if got := blockedChannelSamples(t); got <= before {
		t.Fatalf("block profile recorded %d samples after %d, want the listener to enable sampling", got, before)
	}
}

func TestPprofShutdownStopsContentionSampling(t *testing.T) {
	d := startTestPprofListener(t)
	// Warm the same stack while enabled so the shutdown assertion detects
	// new events at an existing stack, too.
	blockedChannelSamples(t)
	close(d.stopCh)
	waitForPprofWorkers(t, d)
	assertContentionSamplingOff(t)
}

func assertContentionSamplingOff(t *testing.T) {
	t.Helper()
	if got := runtime.SetMutexProfileFraction(-1); got != 0 {
		t.Cleanup(func() { runtime.SetMutexProfileFraction(0) })
		t.Fatalf("mutex sampling still at fraction %d after shutdown", got)
	}
	t.Cleanup(func() { runtime.SetBlockProfileRate(0) })
	before := blockedChannelSamples(t)
	if got := blockedChannelSamples(t); got != before {
		t.Fatalf("block profile still recorded samples after shutdown: %d then %d", before, got)
	}
}

func TestPprofRefusedListenerLeavesSamplingOff(t *testing.T) {
	d := newTestPprofDaemon(t)
	t.Cleanup(func() {
		runtime.SetMutexProfileFraction(0)
		runtime.SetBlockProfileRate(0)
	})

	if d.startPprofListener("0.0.0.0:6060") {
		t.Fatal("pprof listener accepted a non-loopback bind")
	}

	assertContentionSamplingOff(t)
}

func TestPprofBindFailureLeavesSamplingOff(t *testing.T) {
	withPprofListen(t, func(string, string) (net.Listener, error) {
		return nil, errTestPprofListen
	})
	d := newTestPprofDaemon(t)
	if d.startPprofListener("127.0.0.1:6060") {
		t.Fatal("pprof listener started after bind failure")
	}
	waitForPprofWorkers(t, d)
	assertContentionSamplingOff(t)
}

func TestPprofSecondBindFailureDoesNotRetainSampling(t *testing.T) {
	d := startTestPprofListener(t)
	withPprofListen(t, func(string, string) (net.Listener, error) {
		return nil, errTestPprofListen
	})
	if d.startPprofListener("127.0.0.1:6060") {
		t.Fatal("second pprof listener started after bind failure")
	}
	before := blockedChannelSamples(t)
	if got := blockedChannelSamples(t); got <= before {
		t.Fatal("failed second bind disabled the active listener's sampling")
	}
	close(d.stopCh)
	waitForPprofWorkers(t, d)
	assertContentionSamplingOff(t)
}

func TestPprofServeFailureStopsContentionSampling(t *testing.T) {
	ln := newBlockingPprofListener("127.0.0.1:6060")
	_ = ln.Close() // Accept fails immediately, without a daemon stop signal.
	withPprofListen(t, func(string, string) (net.Listener, error) { return ln, nil })
	d := newTestPprofDaemon(t)
	if !d.startPprofListener("127.0.0.1:6060") {
		t.Fatal("pprof listener did not start")
	}
	waitForPprofWorkers(t, d)
	assertContentionSamplingOff(t)
}

func TestPprofOverlappingListenersKeepSampling(t *testing.T) {
	for _, stop := range []string{"shutdown", "serve-failure"} {
		t.Run(stop, func(t *testing.T) {
			ln := newBlockingPprofListener("127.0.0.1:6060")
			withPprofListen(t, func(string, string) (net.Listener, error) { return ln, nil })
			first := newTestPprofDaemon(t)
			if !first.startPprofListener("127.0.0.1:6060") {
				t.Fatal("first pprof listener did not start")
			}
			second := startTestPprofListener(t)
			if stop == "serve-failure" {
				_ = ln.Close()
			} else {
				close(first.stopCh)
			}
			waitForPprofWorkers(t, first)
			beforeMutex := contendedMutexSamples(t)
			if got := contendedMutexSamples(t); got <= beforeMutex {
				t.Error("first listener stopping disabled the second listener's mutex sampling")
			}
			beforeBlock := blockedChannelSamples(t)
			if got := blockedChannelSamples(t); got <= beforeBlock {
				t.Error("first listener stopping disabled the second listener's block sampling")
			}
			close(second.stopCh)
			waitForPprofWorkers(t, second)
			assertContentionSamplingOff(t)
		})
	}
}

func TestPprofConcurrentListenerLifetimes(t *testing.T) {
	withPprofListen(t, func(string, string) (net.Listener, error) {
		return newBlockingPprofListener("127.0.0.1:6060"), nil
	})
	// Two successful starts on each daemon must each release exactly one
	// reference, including when both shutdown workers run concurrently.
	var daemons []*Daemon
	var starters sync.WaitGroup
	for i := 0; i < 8; i++ {
		d := newTestPprofDaemon(t)
		daemons = append(daemons, d)
		for j := 0; j < 2; j++ {
			starters.Add(1)
			go func() {
				defer starters.Done()
				if !d.startPprofListener("127.0.0.1:6060") {
					t.Error("pprof listener did not start")
				}
			}()
		}
	}
	starters.Wait()
	before := blockedChannelSamples(t)
	if got := blockedChannelSamples(t); got <= before {
		t.Error("active listeners did not record blocking samples")
	}
	for _, d := range daemons {
		close(d.stopCh)
	}
	for _, d := range daemons {
		waitForPprofWorkers(t, d)
	}
	assertContentionSamplingOff(t)
}
