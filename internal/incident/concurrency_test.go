package incident

import (
	"runtime"
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
	var persistCalls int64
	c := NewCorrelator(CorrelatorConfig{
		Persist: func(Incident) {
			atomic.AddInt64(&persistCalls, 1)
			runtime.Gosched()
		},
	})

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
	atomic.StoreInt64(&persistCalls, 0)

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
	if atomic.LoadInt64(&persistCalls) == 0 {
		t.Fatal("stress test never exercised Persist unlock path")
	}
	if got := c.OpenCount(); got < 0 {
		t.Fatalf("OpenCount returned nonsense after stress: %d", got)
	}
}

func TestCorrelator_ConcurrentCloseSkipsStaleAutoBlock(t *testing.T) {
	var c *Correlator
	var cap blockCapture
	blockPersist := make(chan struct{})
	persistEntered := make(chan struct{})
	releasePersist := make(chan struct{})
	var blockOnce sync.Once
	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() {
			close(releasePersist)
		})
	}
	c = NewCorrelator(CorrelatorConfig{
		Persist: func(Incident) {
			select {
			case <-blockPersist:
				blockOnce.Do(func() {
					close(persistEntered)
					<-releasePersist
				})
			default:
			}
		},
		AutoBlock: IncidentAutoBlockConfig{
			Enabled:         true,
			BlockAtSeverity: "critical",
			Kinds:           map[Kind]bool{KindMailboxTakeover: true},
		},
		OnIncidentBlock: cap.recordOK,
	})

	now := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return now }
	id, _, err := c.OnFinding(alert.Finding{
		Check:     "email_compromised_account",
		Severity:  alert.High,
		Mailbox:   "victim@example.com",
		SourceIP:  "192.0.2.60",
		Timestamp: now,
	})
	if err != nil {
		t.Fatalf("seed OnFinding: %v", err)
	}

	close(blockPersist)
	mergeDone := make(chan error, 1)
	c.now = func() time.Time { return now.Add(time.Minute) }
	go func() {
		_, _, err := c.OnFinding(alert.Finding{
			Check:     "email_compromised_account",
			Severity:  alert.Critical,
			Mailbox:   "victim@example.com",
			SourceIP:  "192.0.2.60",
			Timestamp: now.Add(time.Minute),
		})
		mergeDone <- err
	}()

	<-persistEntered
	statusDone := make(chan error, 1)
	go func() {
		statusDone <- c.SetStatus(id, StatusResolved, "operator")
	}()
	defer release()
	waitForIncidentStatus(t, c, id, StatusResolved)
	release()
	if err := <-statusDone; err != nil {
		t.Fatalf("SetStatus: %v", err)
	}
	if err := <-mergeDone; err != nil {
		t.Fatalf("merge OnFinding: %v", err)
	}
	if got := cap.len(); got != 0 {
		t.Fatalf("OnIncidentBlock fired %d times after concurrent resolve; want 0", got)
	}
	inc, ok := c.Get(id)
	if !ok {
		t.Fatal("incident disappeared")
	}
	if hasIncidentAction(inc.Actions, "incident_block_requested") {
		t.Fatal("resolved incident recorded incident_block_requested")
	}
}

func waitForIncidentStatus(t *testing.T, c *Correlator, id string, status Status) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		inc, ok := c.Get(id)
		if ok && inc.Status == status {
			return
		}
		select {
		case <-deadline:
			if !ok {
				t.Fatalf("incident %s not found while waiting for %s", id, status)
			}
			t.Fatalf("incident %s status = %s, want %s", id, inc.Status, status)
		case <-ticker.C:
		}
	}
}
