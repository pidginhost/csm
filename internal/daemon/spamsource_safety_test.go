package daemon

import (
	"fmt"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/store"
)

func TestSpamSourceEvictionKeepsCheckOwnership(t *testing.T) {
	tr := newSpamSourceTracker(1)
	ip := netip.MustParseAddr("198.51.100.7")
	tr.observe(ip, true, false, spamSourceBase)
	old := spamSourceBase.Add(time.Hour)
	if !tr.observe(ip, true, false, old) {
		t.Fatal("second occasion did not start a check")
	}
	tr.observe(netip.MustParseAddr("198.51.100.8"), true, false, old)
	tr.observe(ip, true, false, old.Add(time.Minute))
	now := old.Add(2 * time.Hour)
	if tr.observe(ip, true, false, now) {
		t.Fatal("eviction allowed a second check before the first finished")
	}
	if tr.finish(ip, old, func() bool { t.Fatal("stale check emitted for a replacement entry"); return true }) {
		t.Fatal("stale check succeeded")
	}
	if !tr.observe(ip, true, false, now) {
		t.Fatal("replacement entry could not start its own check")
	}
	if !tr.finish(ip, now, func() bool { return true }) {
		t.Fatal("replacement entry could not emit")
	}
}

func TestSpamSourceFullAlertQueueDoesNotThrottle(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		useSpamStore(t)
		cfg := spamSourceConfig(t)
		d := startSpamDaemon(t, cfg, &spamDNS{})
		for range cap(d.alertCh) {
			d.alertCh <- alert.Finding{Check: "test_queue_filler"}
		}
		base := time.Now()
		const ip = "198.51.100.7"
		eximAt(d, cfg, rejectMarker(ip), base)
		eximAt(d, cfg, rejectMarker(ip), base.Add(time.Hour))
		synctest.Wait()
		tr := d.spamSources.Load().tracker
		if !tr.snapshot()[ip].LastFinding.IsZero() {
			t.Fatal("a full alert queue started the throttle")
		}
		if got := spamFindings(d); len(got) != cap(d.alertCh) {
			t.Fatalf("drained %d findings, want the %d fillers", len(got), cap(d.alertCh))
		}
		retry := base.Add(time.Hour + time.Minute)
		eximAt(d, cfg, rejectMarker(ip), retry)
		wantSpamFinding(t, spamFindings(d), ip, retry)
		if !tr.snapshot()[ip].LastFinding.Equal(retry) {
			t.Fatal("successful enqueue did not start the throttle")
		}
	})
}

func TestSpamSourceFinalSaveIncludesLateProducer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		db := useSpamStore(t)
		cfg := spamSourceConfig(t)
		d := startSpamDaemon(t, cfg, &spamDNS{})
		close(d.stopCh)
		if !wgIdle(d) {
			t.Fatal("runner did not stop with the daemon")
		}
		// A log producer can finish a line after the runner exits. Run joins
		// those producers before stopAbuseReporting performs the final save.
		at := time.Now()
		const ip = "198.51.100.7"
		eximAt(d, cfg, scanMarker("enforce", "on", 20, "none", spamMsgA, ip), at)
		d.stopAbuseReporting()
		got, err := db.LoadSpamSources()
		if err != nil || len(got) != 1 || !got[ip].LastClean.Equal(at) {
			t.Fatalf("final state = %+v, %v; want the late clean observation", got, err)
		}
	})
}

func TestSpamSourceConcurrentStartup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		useSpamStore(t)
		cfg := spamSourceConfig(t)
		reportEveryAddress(t)
		prev := alert.ReportHook
		t.Cleanup(func() { alert.SetReportHook(prev) })
		d := New(cfg, nil, nil, "")
		d.spamSourceDNS = &spamDNS{}
		base := time.Now()
		stop := make(chan struct{})
		var producers, ready sync.WaitGroup
		for i := range 8 {
			producers.Add(1)
			ready.Add(1)
			go func() {
				defer producers.Done()
				scan := scanOf(rejectMarker(fmt.Sprintf("198.51.100.%d", i+1)))
				d.recordSpamSource(scan, base, cfg)
				ready.Done()
				for {
					select {
					case <-stop:
						return
					default:
						d.recordSpamSource(scan, base, cfg)
						runtime.Gosched()
					}
				}
			}()
		}
		ready.Wait()
		loop := d.startAbuseReporting()
		close(stop)
		producers.Wait()
		if loop == nil {
			t.Fatal("reporting did not start")
		}
		go loop()
		t.Cleanup(d.stopAbuseReporting)
		for i := range 8 {
			ip := fmt.Sprintf("198.51.100.%d", i+1)
			d.recordSpamSource(scanOf(rejectMarker(ip)), base, cfg)
			d.recordSpamSource(scanOf(rejectMarker(ip)), base.Add(time.Hour), cfg)
		}
		got := spamFindings(d)
		if len(got) != 8 {
			t.Fatalf("got %d findings, want one per sender", len(got))
		}
		seen := make(map[string]bool)
		for _, f := range got {
			if seen[f.SourceIP] {
				t.Fatalf("duplicate finding for %s", f.SourceIP)
			}
			seen[f.SourceIP] = true
			wantSpamFinding(t, []alert.Finding{f}, f.SourceIP, base.Add(time.Hour))
		}
		for i := range 8 {
			if !seen[fmt.Sprintf("198.51.100.%d", i+1)] {
				t.Fatalf("missing sender %d", i+1)
			}
		}
	})
}

func TestSpamSourceLoadEnforcesBoundAndEvictionPolicy(t *testing.T) {
	for _, cleanCount := range []int{18, 19, 21} {
		t.Run(fmt.Sprint(cleanCount), func(t *testing.T) {
			tr := newSpamSourceTracker(20)
			state := make(map[string]store.SpamSource)
			for i := range 21 {
				src := store.SpamSource{Seen: spamSourceBase.Add(time.Duration(i) * time.Minute)}
				if i < cleanCount {
					src.LastClean = src.Seen
				}
				state[fmt.Sprintf("198.51.100.%d", i+1)] = src
			}
			tr.load(state, spamSourceBase.Add(time.Hour))
			got := tr.snapshot()
			if len(got) != 20 {
				t.Fatalf("loaded %d entries, want 20", len(got))
			}
			victim := "198.51.100.1"
			if cleanCount == 18 {
				victim = "198.51.100.19"
			}
			if _, ok := got[victim]; ok {
				t.Errorf("retained eviction candidate %s", victim)
			}
			for ip, want := range state {
				if ip != victim && (!got[ip].Seen.Equal(want.Seen) || !got[ip].LastClean.Equal(want.LastClean)) {
					t.Errorf("changed retained state for %s", ip)
				}
			}
		})
	}
}
