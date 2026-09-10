package checks

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/queuehealth"
	"github.com/pidginhost/csm/internal/store"
)

type admissionBlocker struct{ call func() error }

func (b admissionBlocker) BlockIP(string, string, time.Duration) error { return b.call() }
func (admissionBlocker) UnblockIP(string) error                        { return nil }
func (admissionBlocker) IsBlocked(string) bool                         { return false }

func autoBlockQueueFixture(t *testing.T, call func() error) *config.Config {
	t.Helper()
	previous := autoBlockQueues
	autoBlockQueues = newAutoBlockQueue()
	t.Cleanup(func() { autoBlockQueues = previous })
	previousStore := store.Global()
	store.SetGlobal(nil)
	t.Cleanup(func() { store.SetGlobal(previousStore) })
	applyBlockTestSetup(t, admissionBlocker{call: call})
	return pendingTestConfig(t)
}

func autoBlockQueueCall(cfg *config.Config, route string, callback func() error) error {
	switch route {
	case "scan":
		AutoBlockIPs(cfg, []alert.Finding{{Check: "wp_login_bruteforce", SourceIP: "192.0.2.10", Message: "queue regression", Severity: alert.Critical}})
		return nil
	case "direct":
		_, err := ApplyBlock(cfg, ApplyBlockRequest{IP: "192.0.2.11", Reason: "queue regression", TTL: time.Hour, Source: BlockSourceCentral})
		return err
	case "flush":
		_, err := FlushAutoBlockState(cfg.StatePath, callback)
		return err
	default:
		panic("unknown test route")
	}
}

func waitAutoBlockQueue(t *testing.T, waiting, active int) map[string]queuehealth.Status {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		rows := AutoBlockQueueStatuses(time.Now())
		if rows["waiting"].Depth == waiting && rows["active"].InFlight == active {
			return rows
		}
		if time.Now().After(deadline) {
			t.Fatalf("queue waiting/active wanted %d/%d: %+v", waiting, active, rows)
		}
		time.Sleep(time.Millisecond)
	}
}

func assertAutoBlockQueueDrained(t *testing.T, losses uint64) {
	t.Helper()
	rows := AutoBlockQueueStatuses(time.Now())
	// These are state-call owners; retry records have independent loss policy.
	for _, name := range []string{"waiting", "active"} {
		row, exists := rows[name]
		if !exists {
			t.Fatalf("state-call queue missing: %s", name)
		}
		want := uint64(0)
		if name == "active" {
			want = losses
		}
		if row.Depth != 0 || row.InFlight != 0 || row.DroppedTotal != want {
			t.Errorf("%s not drained with expected losses %d: %+v", name, want, row)
		}
	}
}

func TestAutoBlockQueueAllStateCallersAreVisible(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	var first sync.Once
	var calls, active atomic.Int32
	var overlapped atomic.Bool
	call := func() error {
		running := active.Add(1)
		defer active.Add(-1)
		if running != 1 {
			overlapped.Store(true)
		}
		calls.Add(1)
		first.Do(func() { close(entered); <-release })
		return nil
	}
	cfg := autoBlockQueueFixture(t, call)
	blockStateMu.Lock()
	locked := true
	done := make(chan error, 3)
	remaining := 3
	defer func() {
		if locked {
			blockStateMu.Unlock()
		}
		unblock()
		for remaining > 0 {
			select {
			case <-done:
				remaining--
			case <-time.After(3 * time.Second):
				t.Error("state caller did not join during cleanup")
				return
			}
		}
	}()
	for _, route := range []string{"scan", "direct", "flush"} {
		go func() { done <- autoBlockQueueCall(cfg, route, call) }()
	}
	rows := waitAutoBlockQueue(t, 3, 0)
	if !rows["waiting"].CapacityUnavailable || rows["active"].Capacity != 1 || calls.Load() != 0 {
		t.Fatalf("incorrect admission capacity or early execution: %+v calls=%d", rows, calls.Load())
	}
	late := AutoBlockQueueStatuses(time.Now().Add(61 * time.Second))
	if late["waiting"].Status != "degraded" || late["waiting"].Reason != "backlog_lag" {
		t.Fatalf("free state slot admission stall missing: %+v", late)
	}
	blockStateMu.Unlock()
	locked = false
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("no state caller entered")
	}
	waitAutoBlockQueue(t, 2, 1)
	late = AutoBlockQueueStatuses(time.Now().Add(61 * time.Second))
	if late["active"].Reason != "processing_lag" || late["waiting"].Reason != "backlog_lag" {
		t.Fatalf("blocked state callback hidden: %+v", late)
	}
	if blockStateMu.TryLock() {
		blockStateMu.Unlock()
		t.Fatal("state callback lost the actual mutex")
	}
	unblock()
	for range 3 {
		select {
		case err := <-done:
			remaining--
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("caller failed to drain")
		}
	}
	if calls.Load() != 3 || overlapped.Load() {
		t.Fatalf("state calls=%d overlap=%v, want 3/false", calls.Load(), overlapped.Load())
	}
	assertAutoBlockQueueDrained(t, 0)
}

func TestAutoBlockQueueRetainsAbnormalCleanupAndReleasesWaiters(t *testing.T) {
	for _, route := range []string{"scan", "direct", "flush"} {
		for _, mode := range []string{"panic", "goexit"} {
			t.Run(route+"/"+mode, func(t *testing.T) {
				cleanup, release := make(chan struct{}), make(chan struct{})
				var releaseOnce sync.Once
				unblock := func() { releaseOnce.Do(func() { close(release) }) }
				defer unblock()
				var calls atomic.Int32
				callback := func() error {
					if calls.Add(1) == 1 {
						defer func() { close(cleanup); <-release }()
						if mode == "panic" {
							panic("held block callback")
						}
						runtime.Goexit()
					}
					return nil
				}
				cfg := autoBlockQueueFixture(t, callback)
				exited := make(chan any, 1)
				var returned atomic.Bool
				exitedJoined := false
				defer func() {
					unblock()
					if !exitedJoined {
						select {
						case <-exited:
						case <-time.After(3 * time.Second):
							t.Error("abnormal caller did not join")
						}
					}
				}()
				go func() {
					defer func() { exited <- recover() }()
					_ = autoBlockQueueCall(cfg, route, callback)
					returned.Store(true)
				}()
				select {
				case <-cleanup:
				case <-time.After(3 * time.Second):
					t.Fatal("callback cleanup not reached")
				}
				later := make(chan error, 1)
				laterJoined := false
				defer func() {
					unblock()
					if !laterJoined {
						select {
						case <-later:
						case <-time.After(3 * time.Second):
							t.Error("later caller did not join")
						}
					}
				}()
				go func() { later <- autoBlockQueueCall(cfg, "direct", callback) }()
				rows := waitAutoBlockQueue(t, 1, 1)
				if rows["active"].DroppedTotal != 0 || calls.Load() != 1 {
					t.Fatalf("premature release/loss: %+v calls=%d", rows, calls.Load())
				}
				late := AutoBlockQueueStatuses(time.Now().Add(61 * time.Second))
				if late["active"].Reason != "processing_lag" || late["waiting"].Reason != "backlog_lag" {
					t.Fatalf("cleanup stall missing: %+v", late)
				}
				unblock()
				select {
				case recovered := <-exited:
					exitedJoined = true
					if mode == "panic" && recovered != "held block callback" {
						t.Fatalf("panic changed: %v", recovered)
					}
					if mode == "goexit" && recovered != nil {
						t.Fatalf("Goexit changed: %v", recovered)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("abnormal caller did not finish cleanup")
				}
				select {
				case err := <-later:
					laterJoined = true
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("later writer stayed blocked")
				}
				if returned.Load() || calls.Load() != 2 {
					t.Fatalf("abnormal return=%v calls=%d", returned.Load(), calls.Load())
				}
				assertAutoBlockQueueDrained(t, 1)
			})
		}
	}
}

func TestAutoBlockQueueExplicitFailuresAndProtectedRefusal(t *testing.T) {
	failure := errors.New("synthetic engine failure")
	cfg := autoBlockQueueFixture(t, func() error { return failure })
	for range 3 {
		if err := autoBlockQueueCall(cfg, "direct", nil); !errors.Is(err, failure) {
			t.Fatalf("lost returned engine error: %v", err)
		}
	}
	rows := AutoBlockQueueStatuses(time.Now())
	if rows["active"].RecentDrops != 3 || rows["active"].Reason != "dropped_work" {
		t.Fatalf("failed state operations hidden: %+v", rows)
	}
	failure = firewall.ErrIPProtected
	if err := autoBlockQueueCall(cfg, "direct", nil); !errors.Is(err, failure) {
		t.Fatalf("protected refusal changed: %v", err)
	}
	assertAutoBlockQueueDrained(t, 3)
	recovered := AutoBlockQueueStatuses(time.Now().Add(2 * time.Minute))["active"]
	if recovered.Status != "ok" || recovered.DroppedTotal != 3 {
		t.Fatalf("loss recovery discarded evidence: %+v", recovered)
	}
}

func TestAutoBlockQueueTracksFlushError(t *testing.T) {
	cfg := autoBlockQueueFixture(t, func() error { return nil })
	failure := errors.New("synthetic flush failure")
	if err := autoBlockQueueCall(cfg, "flush", func() error { return failure }); !errors.Is(err, failure) {
		t.Fatalf("flush error changed: %v", err)
	}
	assertAutoBlockQueueDrained(t, 1)
}

func TestAutoBlockQueueLongBatchKeepsProgress(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		cfg := autoBlockQueueFixture(t, func() error { calls.Add(1); time.Sleep(30 * time.Second); return nil })
		findings := make([]alert.Finding, 5)
		for i := range findings {
			findings[i] = alert.Finding{Check: "wp_login_bruteforce", SourceIP: fmt.Sprintf("192.0.2.%d", 20+i), Message: "queue progress"}
		}
		done := make(chan []alert.Finding, 1)
		joined := false
		defer func() {
			if !joined {
				<-done
			}
		}()
		go func() { done <- AutoBlockIPs(cfg, findings) }()
		time.Sleep(65 * time.Second)
		active := AutoBlockQueueStatuses(time.Now())["active"]
		if active.InFlight != 1 || active.Status != "ok" || active.ProcessingSeconds != 5 {
			t.Fatalf("advancing long batch reported stalled: %+v", active)
		}
		results := <-done
		joined = true
		if calls.Load() != 5 || len(results) != 5 {
			t.Fatalf("batch calls=%d results=%d, want 5/5", calls.Load(), len(results))
		}
		assertAutoBlockQueueDrained(t, 0)
	})
}

func TestAutoBlockQueueBypassesDisabledAndMissingEngine(t *testing.T) {
	cfg := autoBlockQueueFixture(t, func() error { t.Error("unexpected engine call"); return nil })
	cfg.AutoResponse.Enabled = false
	AutoBlockIPs(cfg, []alert.Finding{{Check: "wp_login_bruteforce", SourceIP: "192.0.2.30"}})
	SetIPBlocker(nil)
	if err := autoBlockQueueCall(cfg, "direct", nil); !errors.Is(err, ErrNoIPBlocker) {
		t.Fatalf("missing engine refusal changed: %v", err)
	}
	assertAutoBlockQueueDrained(t, 0)
}

type slowAdmissionSubnets struct {
	admissionBlocker
	calls atomic.Int32
}

func (b *slowAdmissionSubnets) BlockedSubnets() []firewall.SubnetEntry {
	entries := make([]firewall.SubnetEntry, 5)
	for i := range entries {
		entries[i] = firewall.SubnetEntry{CIDR: fmt.Sprintf("203.0.113.%d/28", i*16), Source: firewall.SourceAutoResponse}
	}
	return entries
}
func (b *slowAdmissionSubnets) UnblockSubnet(string) error {
	b.calls.Add(1)
	time.Sleep(30 * time.Second)
	return nil
}

func TestAutoBlockQueueLongPruneKeepsProgress(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := autoBlockQueueFixture(t, func() error { t.Error("unexpected IP block"); return nil })
		cfg.Firewall = cfgWithExempt(t, "203.0.113.0/24").Firewall
		blocker := &slowAdmissionSubnets{admissionBlocker: admissionBlocker{call: func() error { return nil }}}
		SetIPBlocker(blocker)
		done := make(chan []alert.Finding, 1)
		joined := false
		defer func() {
			if !joined {
				<-done
			}
		}()
		go func() { done <- AutoBlockIPs(cfg, nil) }()
		time.Sleep(65 * time.Second)
		active := AutoBlockQueueStatuses(time.Now())["active"]
		if active.InFlight != 1 || active.Status != "ok" || active.ProcessingSeconds != 5 {
			t.Fatalf("advancing subnet cleanup reported stalled: %+v", active)
		}
		findings := <-done
		joined = true
		if len(findings) != 0 {
			t.Fatalf("prune created block findings: %+v", findings)
		}
		if blocker.calls.Load() != 5 {
			t.Fatalf("prune calls=%d, want5", blocker.calls.Load())
		}
		assertAutoBlockQueueDrained(t, 0)
	})
}
