package incident

import (
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// TestCorrelator_ConcurrentOnFindingAndSetStatusRaceSafe runs many
// OnFinding calls in parallel with SetStatus calls on overlapping
// incident IDs to expose mutex / map-mutation races. Failure mode
// the test guards against: a SetStatus that mutates incident state
// while OnFinding is mid-merge, leading to stale-pointer writes or
// map corruption. Run with -race.
func TestCorrelator_ConcurrentOnFindingAndSetStatusRaceSafe(t *testing.T) {
	c := NewCorrelator(CorrelatorConfig{})

	// Seed a handful of incidents so SetStatus has live targets.
	var seeded []string
	for i := 0; i < 10; i++ {
		id, _, err := c.OnFinding(alert.Finding{
			Check:    "wp_login_bruteforce",
			Mailbox:  "user" + strconv.Itoa(i) + "@example.com",
			Severity: alert.Critical,
			SourceIP: "198.51.100.1",
		})
		if err != nil {
			t.Fatalf("seed: %v", err)
		}
		seeded = append(seeded, id)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	var onCalls, setCalls int64

	// Many OnFinding writers, hammering the same actor keys.
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_, _, _ = c.OnFinding(alert.Finding{
						Check:    "wp_login_bruteforce",
						Mailbox:  "user" + strconv.Itoa(worker%5) + "@example.com",
						Severity: alert.Critical,
					})
					atomic.AddInt64(&onCalls, 1)
				}
			}
		}(w)
	}

	// SetStatus walkers cycling through seeded ids.
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			i := 0
			for {
				select {
				case <-stop:
					return
				default:
					_ = c.SetStatus(seeded[i%len(seeded)], StatusContained, "stress")
					_ = c.SetStatus(seeded[i%len(seeded)], StatusOpen, "stress")
					i++
					atomic.AddInt64(&setCalls, 1)
				}
			}
		}()
	}

	time.AfterFunc(200*time.Millisecond, func() { close(stop) })
	wg.Wait()
	if atomic.LoadInt64(&onCalls) == 0 || atomic.LoadInt64(&setCalls) == 0 {
		t.Fatalf("stress test made no progress: on=%d set=%d", onCalls, setCalls)
	}
	if got := c.OpenCount(); got < 0 {
		t.Fatalf("OpenCount returned nonsense after stress: %d", got)
	}
}
