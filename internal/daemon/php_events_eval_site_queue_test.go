package daemon

import (
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/queuehealth"
)

func evalSiteQueueStatus(t *testing.T) queuehealth.Status {
	t.Helper()
	status, ok := (&Daemon{}).QueueStatuses()["php_shield.eval_sites"]
	if !ok {
		t.Fatal("eval-site ownership work is missing from daemon queue health")
	}
	if !status.Advisory || !status.CapacityUnavailable {
		t.Fatalf("optional grading work claims a protection failure or a bounded result backlog: %+v", status)
	}
	return status
}

func TestPHPShieldEvalSiteQueuePublished(t *testing.T) {
	toolkitTree(t)
	tree := phpShieldEvalSiteLstat
	synctest.Test(t, func(t *testing.T) {
		before := evalSiteQueueStatus(t)
		phpShieldEvalSiteLstat = func(name string) (os.FileInfo, error) {
			if got := evalSiteQueueStatus(t); got.Depth != 0 || got.InFlight != 1 {
				t.Errorf("running ownership walk is not published: %+v", got)
			}
			return tree(name)
		}
		defer func() { phpShieldEvalSiteLstat = tree }()
		for _, tc := range []struct {
			file string
			want alert.Severity
		}{
			{toolkitEvalCommand, alert.Warning},
			{"/usr/local/lib/missing.php", alert.High},
		} {
			f := parsePHPShieldLine(evalFatalLine(evalSite(tc.file, "44")))
			if f == nil || f.Severity != tc.want {
				t.Fatalf("ownership result changed: finding=%+v want=%v", f, tc.want)
			}
			synctest.Wait()
			got := evalSiteQueueStatus(t)
			if got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != before.DroppedTotal {
				t.Fatalf("completed proof leaked work or counted a negative result as loss: %+v", got)
			}
		}
	})
}

func TestPHPShieldEvalSiteQueueRetainsTimedOutLookup(t *testing.T) {
	toolkitTree(t)
	tree := phpShieldEvalSiteLstat
	synctest.Test(t, func(t *testing.T) {
		before := evalSiteQueueStatus(t)
		release := make(chan struct{})
		unblock := sync.OnceFunc(func() { close(release) })
		var calls atomic.Int32
		phpShieldEvalSiteLstat = func(name string) (os.FileInfo, error) {
			calls.Add(1)
			<-release
			return tree(name)
		}
		defer func() {
			unblock()
			synctest.Wait()
			phpShieldEvalSiteLstat = tree
		}()
		line := evalFatalLine(evalSite(toolkitEvalCommand, "44"))
		if f := parsePHPShieldLine(line); f == nil || f.Severity != alert.High {
			t.Fatalf("timed-out ownership proof lowered the grade: %+v", f)
		}
		got := evalSiteQueueStatus(t)
		if got.Depth != 0 || got.InFlight != 1 || got.DroppedTotal != before.DroppedTotal+1 || got.Reason != "processing_lag" || got.ProcessingSeconds < phpShieldEvalSiteTimeout.Seconds() {
			t.Fatalf("caller timeout hid its running syscall or loss: %+v", got)
		}
		start := time.Now()
		for range 3 {
			if f := parsePHPShieldLine(line); f == nil || f.Severity != alert.High {
				t.Fatalf("refused proof lowered the grade: %+v", f)
			}
		}
		got = evalSiteQueueStatus(t)
		if calls.Load() != 1 || !time.Now().Equal(start) || got.InFlight != 1 || got.DroppedTotal != before.DroppedTotal+4 {
			t.Fatalf("saturation delayed events, created more walks or lost refusals: calls=%d status=%+v", calls.Load(), got)
		}
		unblock()
		synctest.Wait()
		time.Sleep(time.Minute)
		got = evalSiteQueueStatus(t)
		if got.Depth != 0 || got.InFlight != 0 || got.Status != "ok" || got.DroppedTotal != before.DroppedTotal+4 {
			t.Fatalf("late completion lost prior evidence or left work running: %+v", got)
		}
		if f := parsePHPShieldLine(line); f == nil || f.Severity != alert.Warning {
			t.Fatalf("recovered lookup did not resume proof: %+v", f)
		}
		synctest.Wait()
		if got := evalSiteQueueStatus(t); got.InFlight != 0 || got.DroppedTotal != before.DroppedTotal+4 {
			t.Fatalf("successful recovery changed loss evidence: %+v", got)
		}
	})
}

func TestPHPShieldEvalSiteQueueRetainsUndeliveredResult(t *testing.T) {
	toolkitTree(t)
	synctest.Test(t, func(t *testing.T) {
		before := evalSiteQueueStatus(t)
		work := acquirePHPShieldEvalSiteWork()
		if work == nil {
			t.Fatal("idle eval-site owner refused a lookup")
		}
		defer work.release()
		result := make(chan bool, 1)
		work.run(toolkitEvalCommand, result)
		time.Sleep(time.Second)
		got := evalSiteQueueStatus(t)
		if got.Depth != 0 || got.InFlight != 1 || got.ProcessingSeconds != 1 || got.Reason != "processing_lag" || len(phpShieldEvalSiteProbe) != 0 {
			t.Fatalf("completed walk hid its undelivered result or held admission: %+v", got)
		}
		if f := parsePHPShieldLine(evalFatalLine(evalSite(toolkitEvalCommand, "44"))); f == nil || f.Severity != alert.Warning {
			t.Fatalf("completed walk's caller delayed a later event: %+v", f)
		}
		synctest.Wait()
		if got := evalSiteQueueStatus(t); got.InFlight != 1 || got.DroppedTotal != before.DroppedTotal {
			t.Fatalf("later work discarded or changed the outstanding result: %+v", got)
		}
		if !<-result {
			t.Fatal("buffered ownership proof changed")
		}
		// The deferred caller release must settle exactly this result.
	})
	if got := evalSiteQueueStatus(t); got.Depth != 0 || got.InFlight != 0 {
		t.Fatalf("consumed result leaked ownership: %+v", got)
	}
}

func TestPHPShieldEvalSiteQueueAbnormalWalkSettlesOnce(t *testing.T) {
	toolkitTree(t)
	tree := phpShieldEvalSiteLstat
	synctest.Test(t, func(t *testing.T) {
		before := evalSiteQueueStatus(t)
		phpShieldEvalSiteLstat = func(string) (os.FileInfo, error) {
			runtime.Goexit()
			return nil, nil
		}
		defer func() { phpShieldEvalSiteLstat = tree }()
		line := evalFatalLine(evalSite(toolkitEvalCommand, "44"))
		if f := parsePHPShieldLine(line); f == nil || f.Severity != alert.High {
			t.Fatalf("abandoned walk changed the fail-closed grade: %+v", f)
		}
		synctest.Wait()
		got := evalSiteQueueStatus(t)
		if got.Depth != 0 || got.InFlight != 0 || got.DroppedTotal != before.DroppedTotal+1 || len(phpShieldEvalSiteProbe) != 0 {
			t.Fatalf("walk exit leaked a slot or counted caller timeout twice: %+v", got)
		}
		phpShieldEvalSiteLstat = tree
		if f := parsePHPShieldLine(line); f == nil || f.Severity != alert.Warning {
			t.Fatalf("abandoned walk blocked the next proof: %+v", f)
		}
	})
}
