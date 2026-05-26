package checks

import (
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// TestAutoBlockIPs_ConcurrentSetIPBlockerIsRaceSafe asserts that the
// global IP blocker pointer can be swapped (SIGHUP rewire) while a
// scan is running through AutoBlockIPs. Without atomic semantics the
// -race detector trips because reads and writes of fwBlocker happen
// from different goroutines without synchronization. The holder is
// updated atomically and AutoBlockIPs picks up one consistent
// reference per call.
func TestAutoBlockIPs_ConcurrentSetIPBlockerIsRaceSafe(t *testing.T) {
	cfg := newAutoBlockTestConfig(t)
	old := getIPBlocker()
	t.Cleanup(func() { SetIPBlocker(old) })

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				SetIPBlocker(&recordingIPBlocker{})
				SetIPBlocker(&outcomeIPBlocker{outcome: "live"})
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			_ = AutoBlockIPs(cfg, []alert.Finding{{
				Check: "wp_login_bruteforce", Message: "WP brute from 192.0.2.99", Timestamp: time.Now(),
			}})
		}
	}()
	time.AfterFunc(200*time.Millisecond, func() { close(stop) })
	wg.Wait()
}
