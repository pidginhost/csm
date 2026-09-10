package incident

import (
	"errors"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/queuehealth"
)

func TestIncidentPersistBulkExitReleasesLaterWriters(t *testing.T) {
	for _, operation := range []string{"bulk", "stale", "age", "cap", "flush"} {
		for _, exit := range []string{"goexit", "panic"} {
			t.Run(operation+"/"+exit, func(t *testing.T) {
				c := NewCorrelator(CorrelatorConfig{Persist: func(Incident) error { return nil }})
				base := time.Unix(1700000000, 0)
				c.now = func() time.Time { return base }
				seeds := 3
				if operation == "cap" {
					seeds = 4
				}
				for i := range seeds {
					f := alert.Finding{Check: "wp_login_bruteforce", TenantID: "account" + strconv.Itoa(i), Severity: alert.High, Timestamp: base}
					id, created, err := c.OnFinding(f)
					if err != nil || !created || id == "" {
						t.Fatalf("seed %d: id=%q created=%v err=%v", i, id, created, err)
					}
					if operation == "flush" {
						if _, created, err := c.OnFinding(f); err != nil || created {
							t.Fatalf("deferred seed created=%v err=%v", created, err)
						}
					}
				}
				var calls atomic.Int32
				cleanup, release := make(chan struct{}), make(chan struct{})
				finish := sync.OnceFunc(func() { close(release) })
				defer finish()
				c.cfg.Persist = func(Incident) error {
					if calls.Add(1) == 1 {
						defer func() { close(cleanup); <-release }()
						if exit == "panic" {
							panic("synthetic incident writer panic")
						}
						runtime.Goexit()
					}
					return nil
				}
				type result struct {
					recovered any
					returned  bool
				}
				bulkDone := make(chan result, 1)
				go func() {
					out := result{}
					defer func() { out.recovered = recover(); bulkDone <- out }()
					switch operation {
					case "bulk":
						_, _ = c.BulkSetStatus(BulkStatusFilter{FromStatuses: []Status{StatusOpen}, To: StatusResolved, OlderThan: time.Second, Limit: 3, Now: base.Add(time.Minute)})
					case "stale":
						c.CloseStaleLimited(base.Add(time.Minute), map[Kind]time.Duration{KindWebAccountCompromise: time.Second}, false, 3)
					case "age":
						c.CloseStaleByAge(base.Add(time.Minute), time.Second, 3)
					case "cap":
						c.EnforceActiveCap(base.Add(time.Minute), 1, 3)
					case "flush":
						c.FlushPendingPersists()
					}
					out.returned = true
				}()
				waitForTestSignal(t, cleanup, "bulk callback did not enter abnormal cleanup")
				rows := incidentQueueRows(t, c, time.Now())
				if rows["persist.waiting"].Depth != 2 || rows["persist.active"].InFlight != 1 || rows["persist.active"].DroppedTotal != 0 || rows["persist.deferred"].Depth != 0 {
					t.Fatalf("reserved bulk/cleanup owners: %+v", rows)
				}
				wantResolved := 3
				if operation == "flush" {
					wantResolved = 0
				}
				if got := countStatus(c.Snapshot(), StatusResolved); got != wantResolved {
					t.Fatalf("reserved transitions=%d, want%d", got, wantResolved)
				}
				later := make(chan error, 1)
				go func() {
					_, _, err := c.OnFinding(alert.Finding{Check: "wp_login_bruteforce", TenantID: "later", Severity: alert.High, Timestamp: base})
					later <- err
				}()
				waitForTestCondition(t, func() bool { return incidentQueueRows(t, c, time.Now())["persist.waiting"].Depth == 3 }, "later writer never queued behind bulk")
				rows = incidentQueueRows(t, c, time.Now().Add(61*time.Second))
				if rows["persist.active"].Reason != "processing_lag" || rows["persist.waiting"].Reason != "backlog_lag" || calls.Load() != 1 {
					t.Fatalf("held cleanup was bypassed: calls=%d rows=%+v", calls.Load(), rows)
				}
				finish()
				select {
				case out := <-bulkDone:
					if out.returned {
						t.Fatal("abnormal exit was swallowed")
					}
					if exit == "panic" && out.recovered != "synthetic incident writer panic" {
						t.Fatalf("panic changed: %v", out.recovered)
					}
					if exit == "goexit" && out.recovered != nil {
						t.Fatalf("Goexit became panic: %v", out.recovered)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("bulk cleanup did not finish")
				}
				select {
				case err := <-later:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("abandoned bulk writes stranded the later writer")
				}
				if calls.Load() != 2 {
					t.Fatalf("callback calls=%d, want interrupted write plus later write", calls.Load())
				}
				rows = incidentQueueRows(t, c, time.Now())
				if rows["persist.waiting"].Depth != 0 || rows["persist.waiting"].DroppedTotal != 2 || rows["persist.active"].InFlight != 0 || rows["persist.active"].DroppedTotal != 1 || rows["persist.deferred"].Depth != 0 {
					t.Fatalf("bulk abandonment settlement: %+v", rows)
				}
			})
		}
	}
}

func incidentQueueRows(t *testing.T, c *Correlator, now time.Time) map[string]queuehealth.Status {
	t.Helper()
	done := make(chan map[string]queuehealth.Status, 1)
	go func() { done <- c.QueueStatuses(now) }()
	select {
	case rows := <-done:
		return rows
	case <-time.After(time.Second):
		t.Fatal("incident health waited on state or persistence")
		return nil
	}
}

func TestIncidentPersistQueueOrderedWriters(t *testing.T) {
	c := NewCorrelator(CorrelatorConfig{})
	id, created, err := c.OnFinding(alert.Finding{Check: "wp_login_bruteforce", TenantID: "alice", Severity: alert.High})
	if err != nil || !created || id == "" {
		t.Fatalf("seed id=%q created=%v err=%v", id, created, err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	finish := sync.OnceFunc(func() { close(release) })
	defer finish()
	var writes []Incident
	c.cfg.Persist = func(snap Incident) error {
		if len(writes) == 0 {
			close(entered)
			<-release
		}
		if _, ok := c.Get(snap.ID); !ok {
			t.Error("callback could not read incident")
		}
		writes = append(writes, snap)
		return nil
	}
	done := make(chan error, 2)
	go func() { done <- c.SetStatus(id, StatusContained, "first") }()
	waitForTestSignal(t, entered, "first writer never started")
	go func() { done <- c.SetStatus(id, StatusResolved, "second") }()
	joined := 0
	defer func() {
		finish()
		for joined < 2 {
			select {
			case <-done:
				joined++
			case <-time.After(2 * time.Second):
				t.Error("incident writers did not join")
				return
			}
		}
	}()
	waitForTestCondition(t, func() bool {
		rows := incidentQueueRows(t, c, time.Now())
		return rows["persist.waiting"].Depth == 1 && rows["persist.active"].InFlight == 1
	}, "queued writer was not published")
	func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		rows := incidentQueueRows(t, c, time.Now())
		if rows["persist.waiting"].Status != "ok" || !rows["persist.waiting"].CapacityUnavailable || rows["persist.active"].Capacity != 1 || rows["persist.active"].Status != "ok" {
			t.Fatalf("valid writer pressure: %+v", rows)
		}
		rows = incidentQueueRows(t, c, time.Now().Add(61*time.Second))
		if rows["persist.waiting"].Reason != "backlog_lag" || rows["persist.active"].Reason != "processing_lag" {
			t.Fatalf("stalled writers hidden: %+v", rows)
		}
	}()
	finish()
	for range 2 {
		select {
		case err := <-done:
			joined++
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("ordered writer did not finish")
		}
	}
	if len(writes) != 2 || writes[0].Status != StatusContained || writes[1].Status != StatusResolved || len(writes[0].Actions) != 1 || len(writes[1].Actions) != 2 {
		t.Fatalf("immutable mutation order changed: %+v", writes)
	}
	for name, q := range incidentQueueRows(t, c, time.Now()) {
		if q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 0 || q.Status != "ok" {
			t.Errorf("%s did not drain: %+v", name, q)
		}
	}
}

func TestIncidentPersistQueueDeferredBookkeeping(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var writes []Incident
		c := NewCorrelator(CorrelatorConfig{Persist: func(snap Incident) error { writes = append(writes, snap); return nil }})
		f := alert.Finding{Check: "wp_login_bruteforce", TenantID: "alice", Severity: alert.High, Timestamp: time.Now()}
		id, created, err := c.OnFinding(f)
		if err != nil || !created || id == "" {
			t.Fatalf("seed id=%q created=%v err=%v", id, created, err)
		}
		time.Sleep(time.Second)
		for i := range 2 {
			f.Message = "merge" + strconv.Itoa(i)
			if got, created, err := c.OnFinding(f); err != nil || created || got != id {
				t.Fatalf("merge id=%q created=%v err=%v", got, created, err)
			}
			time.Sleep(time.Second)
		}
		rows := incidentQueueRows(t, c, time.Now())
		q := rows["persist.deferred"]
		if len(writes) != 1 || q.Depth != 1 || q.LagSeconds != 2 || q.LagBasis != "deferred_checkpoint" {
			t.Fatalf("coalesced dirty state: writes=%d rows=%+v", len(writes), rows)
		}
		if future := incidentQueueRows(t, c, time.Now().Add(time.Hour))["persist.deferred"]; future.Status != "ok" || future.DroppedTotal != 0 || future.Depth != 1 {
			t.Fatalf("quiet bookkeeping falsely stalled: %+v", future)
		}
		if flushed := c.FlushPendingPersists(); flushed != 1 {
			t.Fatalf("flushed=%d, want 1", flushed)
		}
		if len(writes) != 2 || len(writes[1].Findings) != 3 || len(writes[1].Timeline) != 3 || writes[1].Timeline[2].Message != "merge1" {
			t.Fatalf("flush lost coalesced state: %+v", writes)
		}
		if flushed := c.FlushPendingPersists(); flushed != 0 {
			t.Fatalf("second flush=%d, want 0", flushed)
		}
		for name, q := range incidentQueueRows(t, c, time.Now()) {
			if q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 0 {
				t.Errorf("%s retained completed work: %+v", name, q)
			}
		}
	})
}

func TestIncidentPersistQueueFailuresAndNoStore(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(strconv.FormatBool(enabled), func(t *testing.T) {
			var calls int
			cfg := CorrelatorConfig{}
			if enabled {
				cfg.Persist = func(Incident) error { calls++; return errors.New("synthetic store failure") }
			}
			c := NewCorrelator(cfg)
			for i := range 3 {
				id, created, err := c.OnFinding(alert.Finding{Check: "wp_login_bruteforce", TenantID: "account" + strconv.Itoa(i), Severity: alert.High})
				if err != nil || !created || id == "" {
					t.Fatalf("in-memory transition changed: id=%q created=%v err=%v", id, created, err)
				}
			}
			rows := incidentQueueRows(t, c, time.Now())
			wantLoss := uint64(0)
			if enabled {
				wantLoss = 3
			}
			if calls != int(wantLoss) || rows["persist.active"].DroppedTotal != wantLoss || rows["persist.active"].InFlight != 0 || rows["persist.waiting"].DroppedTotal != 0 {
				t.Fatalf("actual failures: calls=%d rows=%+v", calls, rows)
			}
			if enabled && rows["persist.active"].Reason != "dropped_work" {
				t.Fatalf("repeated write failure stayed healthy: %+v", rows)
			}
			future := incidentQueueRows(t, c, time.Now().Add(2*time.Minute))["persist.active"]
			if future.Status != "ok" || future.RecentDrops != 0 || future.DroppedTotal != wantLoss {
				t.Fatalf("loss recovery changed totals: %+v", future)
			}
		})
	}
}

func TestIncidentPersistQueueSupersedesOnlyEarlierBookkeeping(t *testing.T) {
	c := NewCorrelator(CorrelatorConfig{})
	base := time.Now()
	c.now = func() time.Time { return base }
	entered, release := make(chan struct{}), make(chan struct{})
	finish := sync.OnceFunc(func() { close(release) })
	defer finish()
	var writes []Incident
	c.cfg.Persist = func(snap Incident) error {
		if len(writes) == 0 {
			close(entered)
			<-release
		}
		writes = append(writes, snap)
		return nil
	}
	f := alert.Finding{Check: "wp_login_bruteforce", TenantID: "alice", Severity: alert.High, Timestamp: base}
	done := make(chan error, 2)
	go func() { _, _, err := c.OnFinding(f); done <- err }()
	waitForTestSignal(t, entered, "initial write did not start")
	joined := 0
	defer func() {
		finish()
		for joined < 2 {
			select {
			case <-done:
				joined++
			case <-time.After(2 * time.Second):
				t.Error("writers did not join")
				return
			}
		}
	}()
	if _, created, err := c.OnFinding(f); err != nil || created {
		t.Fatalf("bookkeeping merge created=%v err=%v", created, err)
	}
	rows := incidentQueueRows(t, c, time.Now())
	if rows["persist.deferred"].Depth != 1 || rows["persist.active"].InFlight != 1 {
		t.Fatalf("new bookkeeping missing beside active older snapshot: %+v", rows)
	}
	critical := f
	critical.Severity = alert.Critical
	go func() { _, _, err := c.OnFinding(critical); done <- err }()
	waitForTestCondition(t, func() bool { return incidentQueueRows(t, c, time.Now())["persist.waiting"].Depth == 1 }, "transition did not queue")
	rows = incidentQueueRows(t, c, time.Now())
	if rows["persist.deferred"].Depth != 0 || rows["persist.active"].InFlight != 1 {
		t.Fatalf("transition did not transfer deferred work: %+v", rows)
	}
	if _, created, err := c.OnFinding(critical); err != nil || created {
		t.Fatalf("later merge created=%v err=%v", created, err)
	}
	finish()
	for range 2 {
		select {
		case err := <-done:
			joined++
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("writes did not finish")
		}
	}
	if len(writes) != 2 || len(writes[0].Timeline) != 1 || len(writes[1].Timeline) != 3 {
		t.Fatalf("queued snapshots changed after reservation: %+v", writes)
	}
	rows = incidentQueueRows(t, c, time.Now())
	if rows["persist.deferred"].Depth != 1 || rows["persist.waiting"].Depth != 0 || rows["persist.active"].InFlight != 0 {
		t.Fatalf("finishing older snapshots erased newer bookkeeping: %+v", rows)
	}
	if flushed := c.FlushPendingPersists(); flushed != 1 || len(writes) != 3 || len(writes[2].Timeline) != 4 {
		t.Fatalf("latest bookkeeping lost: flushed=%d writes=%+v", flushed, writes)
	}
	for name, q := range incidentQueueRows(t, c, time.Now()) {
		if q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 0 {
			t.Errorf("%s failed to drain: %+v", name, q)
		}
	}
}

func TestIncidentPersistQueueMemoryOnlyHasNoDeferredWrites(t *testing.T) {
	c := NewCorrelator(CorrelatorConfig{})
	f := alert.Finding{Check: "wp_login_bruteforce", TenantID: "alice", Severity: alert.High}
	for i := range 3 {
		id, created, err := c.OnFinding(f)
		if id == "" || err != nil || created != (i == 0) {
			t.Fatalf("memory transition %d: id=%q created=%v err=%v", i, id, created, err)
		}
	}
	if flushed := c.FlushPendingPersists(); flushed != 0 {
		t.Fatalf("memory-only flush=%d", flushed)
	}
	for name, q := range incidentQueueRows(t, c, time.Now().Add(time.Hour)) {
		if q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 0 || q.Status != "ok" {
			t.Errorf("%s invented durable work: %+v", name, q)
		}
	}
}

func TestIncidentPersistQueueRestoreDiscardsReplacedBookkeeping(t *testing.T) {
	var writes []Incident
	c := NewCorrelator(CorrelatorConfig{Persist: func(snap Incident) error { writes = append(writes, snap); return nil }})
	f := alert.Finding{Check: "wp_login_bruteforce", TenantID: "alice", Severity: alert.High}
	id, created, err := c.OnFinding(f)
	if id == "" || !created || err != nil {
		t.Fatalf("seed id=%q created=%v err=%v", id, created, err)
	}
	if _, created, err := c.OnFinding(f); created || err != nil {
		t.Fatalf("merge created=%v err=%v", created, err)
	}
	if q := incidentQueueRows(t, c, time.Now())["persist.deferred"]; q.Depth != 1 {
		t.Fatalf("dirty state missing: %+v", q)
	}
	c.Restore(writes[:1])
	if flushed := c.FlushPendingPersists(); flushed != 0 || len(writes) != 1 {
		t.Fatalf("restore retained superseded bookkeeping: flushed=%d writes=%d", flushed, len(writes))
	}
	if got, ok := c.Get(id); !ok || len(got.Timeline) != 1 {
		t.Fatalf("restored state differs: ok=%v incident=%+v", ok, got)
	}
	for name, q := range incidentQueueRows(t, c, time.Now()) {
		if q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 0 {
			t.Errorf("%s restore queue: %+v", name, q)
		}
	}
	if _, created, err := c.OnFinding(f); created || err != nil {
		t.Fatalf("post-restore merge created=%v err=%v", created, err)
	}
	if len(writes) != 2 || len(writes[1].Timeline) != 2 {
		t.Fatalf("post-restore persistence did not resume: %+v", writes)
	}
}

func TestIncidentPersistQueueProgressDuringLongBatch(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := NewCorrelator(CorrelatorConfig{})
		base := time.Now()
		for i := range 5 {
			id, created, err := c.OnFinding(alert.Finding{Check: "wp_login_bruteforce", TenantID: "account" + strconv.Itoa(i), Severity: alert.High})
			if id == "" || !created || err != nil {
				t.Fatalf("seed%d id=%q created=%v err=%v", i, id, created, err)
			}
		}
		entered := make(chan struct{})
		calls := 0
		c.cfg.Persist = func(Incident) error {
			calls++
			if calls == 1 {
				close(entered)
			}
			time.Sleep(30 * time.Second)
			return nil
		}
		done := make(chan BulkStatusResult, 1)
		go func() {
			result, err := c.BulkSetStatus(BulkStatusFilter{FromStatuses: []Status{StatusOpen}, To: StatusResolved, OlderThan: time.Second, Limit: 5, Now: base.Add(time.Hour)})
			if err != nil {
				t.Error(err)
			}
			done <- result
		}()
		<-entered
		time.Sleep(65 * time.Second)
		rows := incidentQueueRows(t, c, time.Now())
		if rows["persist.waiting"].Depth != 2 || rows["persist.waiting"].LagSeconds != 65 || rows["persist.waiting"].Status != "ok" || rows["persist.active"].InFlight != 1 || rows["persist.active"].ProcessingSeconds != 5 || rows["persist.active"].Status != "ok" {
			t.Fatalf("progressing long batch falsely stalled: %+v", rows)
		}
		result := <-done
		if result.Updated != 5 || calls != 5 {
			t.Fatalf("batch completion: updated=%d callbacks=%d", result.Updated, calls)
		}
		for name, q := range incidentQueueRows(t, c, time.Now()) {
			if q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 0 || q.Status != "ok" {
				t.Errorf("%s did not drain: %+v", name, q)
			}
		}
	})
}
