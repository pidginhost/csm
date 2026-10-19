package daemon

import (
	"context"
	"slices"
	"sync"

	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/antispam/learn"
	"github.com/pidginhost/csm/internal/antispam/reconcile"
	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/obs"
	"github.com/pidginhost/csm/internal/store"
)

type learnEngine interface {
	Run(context.Context)
	SetGate(antispam.LearningGate)
	Problems() []antispam.Problem
	Operator(context.Context, learn.OperatorRequest) (learn.OperatorResult, error)
}

// newLearnEngine builds the learning engine; tests replace it.
var newLearnEngine = func(cfg learn.EngineConfig) learnEngine { return learn.NewEngine(cfg) }

// learnerRunner is one running engine and what it was built for.
type learnerRunner struct {
	target reconcile.LearnerTarget
	engine learnEngine
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// syncLearner follows a completed reconcile pass: it starts the learning
// engine when the pass names where it runs, passes it the gate, and stops
// it once learning is no longer wanted. Stopping closes the gate first, so
// no new read or send starts, then waits for calls in flight to end within
// their deadlines.
func (d *Daemon) syncLearner(out reconcile.Outcome) {
	if !slices.Contains(out.Checks, reconcile.CheckLearning) {
		return
	}
	cfg := d.currentCfg()
	as := cfg.EmailProtection.Antispam
	if !as.Enabled || !as.Learning.Enabled || cfg.ObserveMode() {
		d.stopLearner()
		return
	}
	cur := d.antispamLearner.Load()
	if out.Learner == (reconcile.LearnerTarget{}) {
		// Wanted, but this pass could not name its controller or keys.
		if cur != nil {
			cur.engine.SetGate(antispam.LearningGate{})
		}
		return
	}
	if cur != nil && cur.target != out.Learner {
		d.stopLearner()
		cur = nil
	}
	if cur == nil {
		if cur = d.startLearning(d.scanContext(), out.Learner); cur == nil {
			return
		}
	}
	cur.engine.SetGate(out.LearningGate)
}

// startLearning starts an engine for target with a closed gate.
func (d *Daemon) startLearning(ctx context.Context, target reconcile.LearnerTarget) *learnerRunner {
	db := store.Global()
	if db == nil {
		csmlog.Warn("antispam learning cannot start: the state database is not open")
		return nil
	}
	engine := newLearnEngine(learn.EngineConfig{
		Client:         learn.Client{Controller: target.Controller, RspamdUID: target.RspamdUID},
		Ledger:         learn.Open(db),
		Bodies:         &learn.Bodies{Dir: learn.DefaultBodiesDir},
		HashGeneration: target.HashGeneration,
		Prefix:         target.Prefix,
	})
	runCtx, cancel := context.WithCancel(ctx)
	r := &learnerRunner{target: target, engine: engine, cancel: cancel}
	r.wg.Add(1)
	d.wg.Add(1)
	obs.Go("antispam-learn", func() {
		defer d.wg.Done()
		defer r.wg.Done()
		engine.Run(runCtx)
	})
	d.antispamLearner.Store(r)
	return r
}

// stopLearner stops the running engine, if any, and waits for it.
func (d *Daemon) stopLearner() {
	r := d.antispamLearner.Swap(nil)
	if r == nil {
		return
	}
	r.engine.SetGate(antispam.LearningGate{})
	r.cancel()
	r.wg.Wait()
}

// learnerProblems is the reconcile pass's view of the engine.
func (d *Daemon) learnerProblems() []antispam.Problem {
	if r := d.antispamLearner.Load(); r != nil {
		return r.engine.Problems()
	}
	return nil
}
