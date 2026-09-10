package checks

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

type retryCleanupBlocker struct {
	retryQueueBlocker
	cover func() bool
}

func (b retryCleanupBlocker) CloudflareCovers(string) bool { return b.cover() }

// A retry owns the real callback through its deferred cleanup. Abnormal
// work survives if its old record remains; an acknowledged block stays done.
func TestAutoBlockRetryAbnormalOwnership(t *testing.T) {
	for _, origin := range []string{"restored", "fresh"} {
		for _, phase := range []string{"block", "bookkeeping"} {
			for _, mode := range []string{"panic", "goexit"} {
				t.Run(origin+"/"+phase+"/"+mode, func(t *testing.T) {
					cfg := autoBlockQueueFixture(t, func() error { return nil })
					const ip = "192.0.2.91"
					var findings []alert.Finding
					if origin == "restored" {
						if err := writeBlockState(cfg.StatePath, &blockState{Pending: []pendingIP{{Check: "wp_login_bruteforce", Severity: alert.Critical, IP: ip, Reason: "retry", QueuedAt: time.Now()}}}); err != nil {
							t.Fatal(err)
						}
					} else {
						findings = []alert.Finding{retryFinding(ip)}
					}
					cleanup, release := make(chan struct{}), make(chan struct{})
					var once sync.Once
					unblock := func() { once.Do(func() { close(release) }) }
					var attempted atomic.Bool
					interrupt := func() {
						if !attempted.CompareAndSwap(false, true) {
							return
						}
						defer func() { close(cleanup); <-release }()
						if mode == "panic" {
							panic("retry cleanup fixture")
						}
						runtime.Goexit()
					}
					SetIPBlocker(retryCleanupBlocker{
						retryQueueBlocker: retryQueueBlocker{block: func(string) error {
							if phase == "block" {
								interrupt()
							}
							return nil
						}},
						cover: func() bool {
							if phase == "bookkeeping" {
								interrupt()
							}
							return false
						},
					})
					exited := make(chan any, 1)
					joined := false
					defer func() {
						unblock()
						if !joined {
							select {
							case <-exited:
							case <-time.After(3 * time.Second):
								t.Error("interrupted retry did not join")
							}
						}
					}()
					var returned atomic.Bool
					go func() { defer func() { exited <- recover() }(); AutoBlockIPs(cfg, findings); returned.Store(true) }()
					select {
					case <-cleanup:
					case <-time.After(3 * time.Second):
						t.Fatal("real cleanup not reached")
					}
					pending, candidates := retryQueueRows(t, time.Now())
					wantPending := 0
					if origin == "restored" {
						wantPending = 1
					}
					if pending.InFlight != wantPending || candidates.InFlight != 1 || pending.DroppedTotal != 0 || candidates.DroppedTotal != 0 {
						t.Fatalf("premature cleanup release: pending=%+v candidates=%+v", pending, candidates)
					}
					latePending, lateCandidates := retryQueueRows(t, time.Now().Add(61*time.Second))
					if lateCandidates.Reason != "processing_lag" || (origin == "restored" && latePending.Reason != "processing_lag") {
						t.Fatalf("cleanup stall missing: pending=%+v candidates=%+v", latePending, lateCandidates)
					}
					later := make(chan error, 1)
					laterJoined := false
					defer func() {
						unblock()
						if !laterJoined {
							select {
							case <-later:
							case <-time.After(3 * time.Second):
								t.Error("later state caller did not join")
							}
						}
					}()
					go func() { later <- autoBlockQueueCall(cfg, "direct", nil) }()
					waitAutoBlockQueue(t, 1, 1)
					unblock()
					select {
					case recovered := <-exited:
						joined = true
						if mode == "panic" && recovered != "retry cleanup fixture" {
							t.Fatalf("panic changed: %v", recovered)
						}
						if mode == "goexit" && recovered != nil {
							t.Fatalf("Goexit changed: %v", recovered)
						}
					case <-time.After(3 * time.Second):
						t.Fatal("interrupted retry stayed blocked")
					}
					select {
					case err := <-later:
						laterJoined = true
						if err != nil {
							t.Fatal(err)
						}
					case <-time.After(3 * time.Second):
						t.Fatal("state gate stayed blocked")
					}
					if returned.Load() {
						t.Fatal("abnormal exit became normal return")
					}
					pending, candidates = retryQueueRows(t, time.Now())
					wantLoss := uint64(0)
					if origin == "fresh" && phase == "block" {
						wantLoss = 1
					}
					if pending.Depth != wantPending || pending.InFlight != 0 || pending.DroppedTotal != 0 || candidates.Depth != 0 || candidates.InFlight != 0 || candidates.DroppedTotal != wantLoss {
						t.Fatalf("survival or completed outcome lost: pending=%+v candidates=%+v", pending, candidates)
					}
					if origin == "restored" && phase == "block" && (pending.Status != "degraded" || pending.Reason != "retry_failed") {
						t.Fatalf("abnormal retained attempt failure hidden: %+v", pending)
					}
					SetIPBlocker(retryQueueBlocker{block: func(string) error { return nil }})
					AutoBlockIPs(cfg, nil)
					pending, candidates = retryQueueRows(t, time.Now())
					if pending.Depth != 0 || pending.Status != "ok" || pending.DroppedTotal != 0 || candidates.DroppedTotal != wantLoss {
						t.Fatalf("retry failed to recover: pending=%+v candidates=%+v", pending, candidates)
					}
				})
			}
		}
	}
}
