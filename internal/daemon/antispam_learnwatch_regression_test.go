//go:build linux

package daemon

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/antispam/learn"
	"github.com/pidginhost/csm/internal/antispam/reconcile"
	"github.com/pidginhost/csm/internal/store"
)

type gateCheckingEngine struct {
	*fakeEngine
	beforeSet func()
}

func (e *gateCheckingEngine) SetGate(g antispam.LearningGate) {
	e.beforeSet()
	e.fakeEngine.SetGate(g)
}

func TestWatcherGateWaitsForEngine(t *testing.T) {
	watchers := withFakeWatchers(t)
	newLearningDaemon(t)
	e := &gateCheckingEngine{fakeEngine: &fakeEngine{}}
	r := &learnerRunner{engine: e}
	r.watcher = newRunnerWatcher(store.Global(), r)
	w := (*watchers)[0]
	e.beforeSet = func() {
		if w.cfg.CanDiscover() || w.cfg.CanSubmit() {
			t.Error("watcher can read before the engine has applied its gate")
		}
	}
	open := antispam.LearningGate{Install: true, Publish: true}
	r.setGate(open)
	if !w.cfg.CanDiscover() || !w.cfg.CanSubmit() {
		t.Fatal("watcher did not resume after the engine opened")
	}
	r.setGate(antispam.LearningGate{})
	if w.cfg.CanDiscover() || w.cfg.CanSubmit() {
		t.Fatal("watcher did not suspend with the engine")
	}
}

func TestWatcherPausesBeforeHostReconcile(t *testing.T) {
	withFakeEngines(t)
	watchers := withFakeWatchers(t)
	d := newLearningDaemon(t)
	open := antispam.LearningGate{Install: true, Publish: true}
	d.syncLearner(learnedOutcome(open, testTarget))
	w := (*watchers)[0]
	d.pauseLearner()
	d.syncLearner(reconcile.Outcome{Retry: reconcile.BusyRetry})
	if w.cfg.CanDiscover() || w.cfg.CanSubmit() {
		t.Fatal("a paused learner left the watcher reading")
	}
	d.syncLearner(learnedOutcome(open, testTarget))
	if !w.cfg.CanDiscover() || !w.cfg.CanSubmit() {
		t.Fatal("completed reconciliation did not resume the watcher")
	}
}

func TestWatcherDisableStartsNewBaseline(t *testing.T) {
	for _, stopped := range []bool{false, true} {
		name := "running"
		if stopped {
			name = "after restart"
		}
		t.Run(name, func(t *testing.T) {
			engines := withFakeEngines(t)
			h := newWatchHome(t)
			d := newLearningDaemon(t)
			w := startWatching(t, d)
			e := (*engines)[0]
			e.mu.Lock()
			e.respond = func(learn.Candidate) (learn.Outcome, error) {
				return learn.Outcome{Deferred: true}, nil
			}
			e.mu.Unlock()
			h.deliver(t, "pending.M1.host", "Subject: pending\r\n\r\npending")
			if p := watcherPass(t, w); p.Pending != 1 || p.Submitted != 0 {
				t.Fatalf("pending pass: %+v", p)
			}
			db := store.Global()
			if err := db.LearnUpdate(func(tx store.LearnTx) error {
				return tx.Put(store.LearnMetaBucket, []byte("test-guard"), []byte("keep"))
			}); err != nil {
				t.Fatal(err)
			}
			if stopped {
				d.stopLearner()
			}
			d.cfg.EmailProtection.Antispam.Learning.Enabled = false
			d.syncLearner(reconcile.Outcome{})
			h.deliver(t, "disabled.M1.host", "Subject: disabled\r\n\r\ndisabled")
			d.cfg.EmailProtection.Antispam.Learning.Enabled = true
			w = startWatching(t, d)
			e = (*engines)[1]
			e.mu.Lock()
			n := len(e.submits)
			e.mu.Unlock()
			if n != 0 {
				t.Fatalf("re-enable submitted %d old or disabled-period messages", n)
			}
			h.deliver(t, "new.M1.host", "Subject: new\r\n\r\nnew")
			if p := watcherPass(t, w); p.Submitted != 1 || p.Pending != 0 {
				t.Fatalf("post-baseline pass: %+v", p)
			}
			if err := db.LearnView(func(tx store.LearnTx) error {
				guard, err := tx.Get(store.LearnMetaBucket, []byte("test-guard"))
				if err == nil && string(guard) != "keep" {
					t.Error("disable cleared the learner's contribution guards")
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestWatcherResetFailureBlocksReenable(t *testing.T) {
	engines := withFakeEngines(t)
	newWatchHome(t)
	d := newLearningDaemon(t)
	startWatching(t, d)
	db := store.Global()
	dir := filepath.Dir(db.Path())
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	d.cfg.EmailProtection.Antispam.Learning.Enabled = false
	d.syncLearner(reconcile.Outcome{})
	d.cfg.EmailProtection.Antispam.Learning.Enabled = true
	d.syncLearner(learnedOutcome(antispam.LearningGate{Install: true, Publish: true}, testTarget))
	if d.antispamLearner.Load() != nil || len(*engines) != 1 {
		t.Fatal("learning resumed before the failed baseline reset was retried")
	}
	db, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	store.SetGlobal(db)
	t.Cleanup(func() {
		d.stopLearner()
		_ = db.Close()
	})
	startWatching(t, d)
	if len(*engines) != 2 {
		t.Fatal("learning did not resume after the state database recovered")
	}
}

func TestWatcherObserveKeepsPending(t *testing.T) {
	engines := withFakeEngines(t)
	h := newWatchHome(t)
	d := newLearningDaemon(t)
	w := startWatching(t, d)
	e := (*engines)[0]
	e.mu.Lock()
	e.respond = func(learn.Candidate) (learn.Outcome, error) {
		return learn.Outcome{Deferred: true}, nil
	}
	e.mu.Unlock()
	h.deliver(t, "pending.M1.host", "Subject: pending\r\n\r\npending")
	if p := watcherPass(t, w); p.Pending != 1 {
		t.Fatalf("pending pass: %+v", p)
	}
	d.cfg.Mode = "observe"
	d.syncLearner(reconcile.Outcome{})
	h.deliver(t, "observed.M1.host", "Subject: observed\r\n\r\nobserved")
	d.cfg.Mode = ""
	startWatching(t, d)
	e = (*engines)[1]
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.submits) != 2 {
		t.Fatalf("observe mode lost the baseline or pending report: %d submissions", len(e.submits))
	}
	seen := map[string]bool{}
	for _, c := range e.submits {
		_, body, _ := strings.Cut(string(c.Snapshot), "\r\n\r\n")
		seen[body] = true
	}
	if !seen["pending"] || !seen["observed"] {
		t.Fatalf("resumed reports: %v", seen)
	}
}
