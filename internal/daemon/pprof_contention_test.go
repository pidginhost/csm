package daemon

import (
	"runtime"
	"runtime/pprof"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

// The pprof listener served mutex and block profiles that were always empty:
// the Go runtime samples neither until its rates are set, and nothing set
// them. An operator asked for a contention profile during a CPU incident and
// got a file with no samples, which reads like "no contention".

// contendedMutexSamples produces enough real contention that the runtime's
// one-in-a-hundred sampling is certain to record some of it, then reports how
// many samples the mutex profile holds.
func contendedMutexSamples(t *testing.T) int {
	t.Helper()
	var mu sync.Mutex
	var wg sync.WaitGroup
	shared := 0
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 2000; i++ {
				mu.Lock()
				shared++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return pprof.Lookup("mutex").Count()
}

func blockedChannelSamples(t *testing.T) int {
	t.Helper()
	ready := make(chan struct{})
	done := make(chan struct{})
	go func() {
		<-ready
		close(done)
	}()
	time.Sleep(20 * time.Millisecond)
	close(ready)
	<-done
	return pprof.Lookup("block").Count()
}

func startTestPprofListener(t *testing.T) *Daemon {
	t.Helper()
	cfg := &config.Config{}
	d := New(cfg, nil, nil, "")
	if !d.startPprofListener("127.0.0.1:0") {
		t.Fatal("pprof listener did not start on a loopback address")
	}
	t.Cleanup(func() {
		close(d.stopCh)
		d.wg.Wait()
	})
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
	cfg := &config.Config{}
	d := New(cfg, nil, nil, "")
	if !d.startPprofListener("127.0.0.1:0") {
		t.Fatal("pprof listener did not start on a loopback address")
	}
	close(d.stopCh)
	d.wg.Wait()

	if got := runtime.SetMutexProfileFraction(-1); got != 0 {
		runtime.SetMutexProfileFraction(0)
		t.Fatalf("mutex sampling still at fraction %d after shutdown", got)
	}
	before := blockedChannelSamples(t)
	if got := blockedChannelSamples(t); got != before {
		t.Fatalf("block profile still recorded samples after shutdown: %d then %d", before, got)
	}
}

func TestPprofRefusedListenerLeavesSamplingOff(t *testing.T) {
	cfg := &config.Config{}
	d := New(cfg, nil, nil, "")
	t.Cleanup(func() {
		runtime.SetMutexProfileFraction(0)
		runtime.SetBlockProfileRate(0)
	})

	if d.startPprofListener("0.0.0.0:6060") {
		t.Fatal("pprof listener accepted a non-loopback bind")
	}

	if got := runtime.SetMutexProfileFraction(-1); got != 0 {
		t.Fatalf("a refused listener enabled mutex sampling (fraction %d)", got)
	}
}
