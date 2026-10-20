package daemon

import (
	"context"
	"testing"

	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/antispam/learn"
	"github.com/pidginhost/csm/internal/antispam/reconcile"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/eximlock"
	"github.com/pidginhost/csm/internal/platform"
)

func learningOffConfigs() map[string]func(*config.Config) {
	return map[string]func(*config.Config){
		"learning disabled": func(c *config.Config) { c.EmailProtection.Antispam.Learning.Enabled = false },
		"antispam disabled": func(c *config.Config) { c.EmailProtection.Antispam.Enabled = false },
		"observe":           func(c *config.Config) { c.Mode = "observe" },
	}
}

func assertLearnerStopped(t *testing.T, d *Daemon, e *fakeEngine) {
	t.Helper()
	select {
	case <-e.stopped:
	default:
		t.Fatal("returned before the learner stopped")
	}
	if e.lastGate() != (antispam.LearningGate{}) || d.antispamLearner.Load() != nil {
		t.Fatal("stopped learner still has an open gate or accepts requests")
	}
}

func TestLearningStopsOnBusyPass(t *testing.T) {
	for name, disable := range learningOffConfigs() {
		t.Run(name, func(t *testing.T) {
			engines := withFakeEngines(t)
			d := newLearningDaemon(t)
			d.syncLearner(learnedOutcome(antispam.LearningGate{Install: true, Publish: true}, testTarget))
			disable(d.cfg)
			d.syncLearner(reconcile.Outcome{Retry: reconcile.BusyRetry})
			assertLearnerStopped(t, d, (*engines)[0])
		})
	}
}

func TestLearningReloadStopsBeforeReconcile(t *testing.T) {
	for name, disable := range learningOffConfigs() {
		t.Run(name, func(t *testing.T) {
			engines := withFakeEngines(t)
			d := newLearningDaemon(t)
			d.syncLearner(learnedOutcome(antispam.LearningGate{Install: true, Publish: true}, testTarget))
			// A pending or blocked pass cannot acknowledge the reload yet.
			d.antispamLoop.Store(reconcile.NewLoop(nil, nil))
			disable(d.cfg)
			d.reconcileAntispam()
			assertLearnerStopped(t, d, (*engines)[0])
			// A result computed before the reload cannot reopen the gate.
			d.syncLearner(learnedOutcome(antispam.LearningGate{Install: true, Publish: true}, testTarget))
			if len(*engines) != 1 || d.antispamLearner.Load() != nil {
				t.Fatal("stale pass restarted learning")
			}
		})
	}
}

func TestLearningPausesBeforeHostReconcile(t *testing.T) {
	engines := withFakeEngines(t)
	d := newLearningDaemon(t)
	d.stopCh = make(chan struct{})
	usePanel(t, platform.PanelCPanel)
	useActiveConfig(t, d.cfg)
	stop := antispamTestShutdown(t, d)
	d.syncLearner(learnedOutcome(antispam.LearningGate{Install: true, Publish: true}, testTarget))
	e := (*engines)[0]
	seen := make(chan antispam.LearningGate, 1)
	old := antispamReconciler
	t.Cleanup(func() { antispamReconciler = old })
	antispamReconciler = func() reconcile.Reconciler {
		return reconcile.Reconciler{Invalidate: func(context.Context) error {
			seen <- e.lastGate()
			return eximlock.ErrBusy
		}}
	}
	d.startAntispam()
	if g := <-seen; g != (antispam.LearningGate{}) {
		t.Errorf("configuration reconciliation began with an open learner gate: %+v", g)
	}
	stop()
	assertLearnerStopped(t, d, e)
}

func TestLearningDoesNotStartAfterShutdown(t *testing.T) {
	engines := withFakeEngines(t)
	d := newLearningDaemon(t)
	d.scanCtx, d.scanCancel = context.WithCancel(context.Background())
	d.scanCancel()
	d.syncLearner(learnedOutcome(antispam.LearningGate{Install: true, Publish: true}, testTarget))
	if len(*engines) != 0 || d.antispamLearner.Load() != nil {
		t.Fatal("a late reconcile result started a learner after shutdown")
	}
}

type drainingLearnEngine struct {
	*fakeEngine
	canceled chan struct{}
	release  chan struct{}
}

func (e *drainingLearnEngine) Run(ctx context.Context) {
	<-ctx.Done()
	close(e.canceled)
	<-e.release
	close(e.stopped)
}

func TestLearningDisableDuringRetarget(t *testing.T) {
	d := newLearningDaemon(t)
	old := newLearnEngine
	t.Cleanup(func() { newLearnEngine = old })
	e := &drainingLearnEngine{
		fakeEngine: &fakeEngine{stopped: make(chan struct{})},
		canceled:   make(chan struct{}), release: make(chan struct{}),
	}
	created := 0
	newLearnEngine = func(cfg learn.EngineConfig) learnEngine {
		created++
		if created == 1 {
			return e
		}
		return &fakeEngine{cfg: cfg, stopped: make(chan struct{})}
	}
	gate := antispam.LearningGate{Install: true, Publish: true}
	d.syncLearner(learnedOutcome(gate, testTarget))
	other := testTarget
	other.Controller = "/run/rspamd/replacement.sock"
	done := make(chan struct{})
	go func() {
		d.syncLearner(learnedOutcome(gate, other))
		close(done)
	}()
	<-e.canceled
	cfg := *d.currentCfg()
	cfg.EmailProtection.Antispam.Learning.Enabled = false
	config.SetActive(&cfg)
	close(e.release)
	<-done
	if created != 1 || d.antispamLearner.Load() != nil {
		t.Fatal("retarget used stale config after waiting for the old engine")
	}
}
