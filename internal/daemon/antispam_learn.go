package daemon

import (
	"context"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"

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
	Pause()
	Publishing() bool
	Problems() []antispam.Problem
	Operator(context.Context, learn.OperatorRequest) (learn.OperatorResult, error)
	SubmitReport(context.Context, learn.Candidate) (learn.Outcome, error)
	Stats() (learn.Stats, error)
}

// newLearnEngine builds the learning engine; tests replace it.
var newLearnEngine = func(cfg learn.EngineConfig) learnEngine { return learn.NewEngine(cfg) }

// learnerRunner is one running engine, its Spam folder watcher and what
// they were built for.
type learnerRunner struct {
	target  reconcile.LearnerTarget
	engine  learnEngine
	watcher learnWatcher
	gate    atomic.Pointer[antispam.LearningGate]
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

// setGate passes g to the engine and to the watcher's gates.
func (r *learnerRunner) setGate(g antispam.LearningGate) {
	// Do not let the watcher read while the engine is still changing gates.
	r.gate.Store(nil)
	r.engine.SetGate(g)
	r.gate.Store(&g)
}

func (r *learnerRunner) currentGate() antispam.LearningGate {
	if g := r.gate.Load(); g != nil {
		return *g
	}
	return antispam.LearningGate{}
}

// syncLearner follows a completed reconcile pass: it starts the learning
// engine when the pass names where it runs, passes it the gate, and stops
// it once learning is no longer wanted. Stopping closes the gate first, so
// no new read or send starts, then waits for calls in flight to end within
// their deadlines.
func (d *Daemon) syncLearner(out reconcile.Outcome) {
	// Config decides before pass timing: a busy or canceled pass must not
	// keep a learner running that observe mode or disable stopped.
	d.antispamLearnerMu.Lock()
	defer d.antispamLearnerMu.Unlock()
	cfg := d.currentCfg()
	as := cfg.EmailProtection.Antispam
	if !cfg.ObserveMode() && (!as.Enabled || !as.Learning.Enabled) {
		d.antispamWatchReset = true
	}
	if !as.Enabled || !as.Learning.Enabled || cfg.ObserveMode() || d.scanContext().Err() != nil {
		d.stopLearnerLocked()
		d.confirmRestoreIfDisabled()
		if d.antispamWatchReset && !cfg.ObserveMode() && d.scanContext().Err() == nil {
			d.resetLearningWatcher()
		}
		return
	}
	if d.antispamWatchReset && !d.resetLearningWatcher() {
		return
	}
	if !slices.Contains(out.Checks, reconcile.CheckLearning) {
		return
	}
	cur := d.antispamLearner.Load()
	if out.Learner == (reconcile.LearnerTarget{}) {
		// Wanted, but this pass could not name its controller or keys.
		if cur != nil {
			cur.setGate(antispam.LearningGate{})
		}
		return
	}
	if cur != nil && cur.target != out.Learner {
		d.stopLearnerLocked()
		cur = nil
	}
	if cur == nil {
		// Draining the old engine can overlap a config reload.
		if !d.learningWanted() {
			return
		}
		if cur = d.startLearning(d.scanContext(), out.Learner, out.LearningGate); cur == nil {
			return
		}
		if !d.learningWanted() {
			d.stopLearnerLocked()
		}
		return
	}
	if !d.learningWanted() {
		d.stopLearnerLocked()
		return
	}
	cur.setGate(out.LearningGate)
}

// learningWanted reports whether the current config asks for learning and
// the daemon is not shutting down.
func (d *Daemon) learningWanted() bool {
	cfg := d.currentCfg()
	as := cfg.EmailProtection.Antispam
	return as.Enabled && as.Learning.Enabled && !cfg.ObserveMode() && d.scanContext().Err() == nil
}

// pauseLearner drains native work before a pass can change rspamd's
// configuration. A busy or canceled pass leaves the gate closed.
func (d *Daemon) pauseLearner() {
	d.antispamLearnerMu.Lock()
	defer d.antispamLearnerMu.Unlock()
	if r := d.antispamLearner.Load(); r != nil {
		r.gate.Store(nil)
		r.engine.Pause()
	}
}

// startLearning applies the first gate before launching either loop, so
// the watcher's immediate pass cannot miss an already open gate.
func (d *Daemon) startLearning(ctx context.Context, target reconcile.LearnerTarget, gate antispam.LearningGate) *learnerRunner {
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
		OnReportCommit: func() { learningMetricsSet().Committed.Inc() },
	})
	runCtx, cancel := context.WithCancel(ctx)
	r := &learnerRunner{target: target, engine: engine, cancel: cancel}
	r.setGate(gate)
	r.watcher = newRunnerWatcher(db, r)
	r.wg.Add(2)
	d.wg.Add(2)
	obs.Go("antispam-learn", func() {
		defer d.wg.Done()
		defer r.wg.Done()
		engine.Run(runCtx)
	})
	obs.Go("antispam-learnwatch", func() {
		defer d.wg.Done()
		defer r.wg.Done()
		r.watcher.Run(runCtx)
	})
	d.antispamLearner.Store(r)
	return r
}

// stopLearner stops the running engine, if any, and waits for it.
func (d *Daemon) stopLearner() {
	d.antispamLearnerMu.Lock()
	defer d.antispamLearnerMu.Unlock()
	d.stopLearnerLocked()
}

func (d *Daemon) stopLearnerLocked() {
	r := d.antispamLearner.Swap(nil)
	if r == nil {
		return
	}
	r.setGate(antispam.LearningGate{})
	r.cancel()
	r.wg.Wait()
}

// learnerProblems is the reconcile pass's view of the engine. Before an
// engine runs, a restored ledger awaiting confirmation already holds
// learning, so restored keys are never installed for a pass.
func (d *Daemon) learnerProblems() []antispam.Problem {
	if db := store.Global(); db != nil {
		held, err := learn.Open(db).DeclaredRestore()
		if err != nil {
			return []antispam.Problem{{Code: antispam.CodeLearning, Severity: antispam.Warning, Key: antispam.ReasonStateMismatch,
				Detail: "cannot read restored learning state; learning stays off: " + err.Error()}}
		}
		if held {
			return []antispam.Problem{{Code: antispam.CodeLearning, Severity: antispam.Warning, Key: antispam.ReasonStateMismatch,
				Detail: "restored learning state awaits confirmation: disable learning, then enable it again, or run csm antispam learn --fresh-namespace"}}
		}
	}
	if r := d.antispamLearner.Load(); r != nil {
		return withWatcherCapacity(r.engine.Problems(), r.watcher)
	}
	return nil
}

// withWatcherCapacity adds the accounts whose Spam folder state reached its
// allowance in the last pass to the engine's account_capacity Warning.
func withWatcherCapacity(problems []antispam.Problem, w learnWatcher) []antispam.Problem {
	rep, _ := w.Last()
	n := rep.Skipped[learn.SkipAccountCapacity]
	if n == 0 {
		return problems
	}
	detail := strconv.Itoa(n) + " accounts reached their Spam folder learning allowance in the last pass; their new reports wait"
	for i, p := range problems {
		if p.Key == antispam.ReasonAccountCapacity {
			problems[i].Detail = p.Detail + "; " + detail
			return problems
		}
	}
	return append(problems, antispam.Problem{Code: antispam.CodeLearning, Severity: antispam.Warning, Key: antispam.ReasonAccountCapacity, Detail: detail})
}

// confirmRestoreIfDisabled treats learning seen disabled as the operator's
// confirmation of a restore (spec 7.4): the next enable resumes the
// restored ledger. Observe mode and shutdown confirm nothing.
func (d *Daemon) confirmRestoreIfDisabled() {
	cfg := d.currentCfg()
	as := cfg.EmailProtection.Antispam
	if (as.Enabled && as.Learning.Enabled) || cfg.ObserveMode() || d.scanContext().Err() != nil {
		return
	}
	if db := store.Global(); db != nil {
		if err := learn.Open(db).ClearDeclaredRestore(); err != nil {
			csmlog.Warn("antispam learning: cannot confirm the restored learning state", "error", err)
		}
	}
}
