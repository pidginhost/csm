package daemon

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/antispam/learn"
	"github.com/pidginhost/csm/internal/antispam/reconcile"
)

// fakeEngine records its gates and how long Run ran.
type fakeEngine struct {
	mu      sync.Mutex
	cfg     learn.EngineConfig
	gates   []antispam.LearningGate
	running bool
	stopped chan struct{}
	submits []learn.Candidate
	respond func(learn.Candidate) (learn.Outcome, error)
}

func (f *fakeEngine) Run(ctx context.Context) {
	f.mu.Lock()
	f.running = true
	f.mu.Unlock()
	<-ctx.Done()
	f.mu.Lock()
	f.running = false
	f.mu.Unlock()
	close(f.stopped)
}

func (f *fakeEngine) SetGate(g antispam.LearningGate) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gates = append(f.gates, g)
}

// Pause records the closed state a pause holds.
func (f *fakeEngine) Pause() { f.SetGate(antispam.LearningGate{}) }

func (f *fakeEngine) Problems() []antispam.Problem { return nil }

func (f *fakeEngine) Stats() (learn.Stats, error) { return learn.Stats{}, nil }

func (f *fakeEngine) Publishing() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.gates) == 0 {
		return false
	}
	g := f.gates[len(f.gates)-1]
	return g.Install && g.Publish
}

// Submit records reports; respond, when set, decides the outcome.
func (f *fakeEngine) Submit(_ context.Context, c learn.Candidate) (learn.Outcome, error) {
	f.mu.Lock()
	f.submits = append(f.submits, c)
	respond := f.respond
	f.mu.Unlock()
	if respond != nil {
		return respond(c)
	}
	return learn.Outcome{Ref: c.Ref, Committed: []uint64{1}}, nil
}

func (f *fakeEngine) Operator(context.Context, learn.OperatorRequest) (learn.OperatorResult, error) {
	return learn.OperatorResult{}, nil
}

func (f *fakeEngine) lastGate() antispam.LearningGate {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.gates[len(f.gates)-1]
}

// withFakeEngines makes every learner a fakeEngine and returns them in
// creation order.
func withFakeEngines(t *testing.T) *[]*fakeEngine {
	t.Helper()
	var engines []*fakeEngine
	saved := newLearnEngine
	newLearnEngine = func(cfg learn.EngineConfig) learnEngine {
		e := &fakeEngine{cfg: cfg, stopped: make(chan struct{})}
		engines = append(engines, e)
		return e
	}
	t.Cleanup(func() { newLearnEngine = saved })
	return &engines
}

var testTarget = reconcile.LearnerTarget{Controller: "/run/rspamd/controller.sock", RspamdUID: 979, HashGeneration: "gen", Prefix: "csmfz_test"}

func learnedOutcome(gate antispam.LearningGate, target reconcile.LearnerTarget) reconcile.Outcome {
	return reconcile.Outcome{Checks: []string{reconcile.CheckLearning}, LearningGate: gate, Learner: target}
}

func newLearningDaemon(t *testing.T) *Daemon {
	t.Helper()
	d := newDaemonForListener(t)
	d.cfg.EmailProtection.Antispam.Enabled = true
	d.cfg.EmailProtection.Antispam.Learning.Enabled = true
	_, closeDB := openTestBoltStore(t, t.TempDir())
	t.Cleanup(func() {
		d.stopLearner()
		closeDB()
	})
	return d
}

func TestLearningStartsWhenGateOpens(t *testing.T) {
	engines := withFakeEngines(t)
	d := newLearningDaemon(t)
	open := antispam.LearningGate{Install: true, Publish: true}
	d.syncLearner(learnedOutcome(open, testTarget))
	if len(*engines) != 1 || d.antispamLearner.Load() == nil {
		t.Fatalf("engines %d", len(*engines))
	}
	e := (*engines)[0]
	c, ok := e.cfg.Client.(learn.Client)
	if !ok || c.Controller != testTarget.Controller || c.RspamdUID != testTarget.RspamdUID ||
		e.cfg.HashGeneration != "gen" || e.cfg.Prefix != "csmfz_test" || e.cfg.Bodies == nil || e.cfg.Ledger == nil {
		t.Fatalf("engine config %+v", e.cfg)
	}
	if e.lastGate() != open {
		t.Fatalf("gate %+v", e.lastGate())
	}
	waitFor(t, func() bool {
		e.mu.Lock()
		defer e.mu.Unlock()
		return e.running
	})
	// An incomplete pass changes nothing.
	d.syncLearner(reconcile.Outcome{})
	if len(*engines) != 1 || d.antispamLearner.Load() == nil || len(e.gates) != 1 {
		t.Fatal("a busy or canceled pass moved the learner")
	}
}

func TestLearningPausesOnPublishFalse(t *testing.T) {
	engines := withFakeEngines(t)
	d := newLearningDaemon(t)
	d.syncLearner(learnedOutcome(antispam.LearningGate{Install: true, Publish: true}, testTarget))
	d.syncLearner(learnedOutcome(antispam.LearningGate{Install: true}, testTarget))
	if len(*engines) != 1 {
		t.Fatalf("pausing restarted the learner: %d engines", len(*engines))
	}
	if g := (*engines)[0].lastGate(); g.Publish || !g.Install {
		t.Fatalf("gate %+v", g)
	}
	// A pass that cannot see the controller socket pauses a learner that is
	// still wanted, without stopping it.
	d.syncLearner(learnedOutcome(antispam.LearningGate{Install: true}, reconcile.LearnerTarget{}))
	if len(*engines) != 1 || d.antispamLearner.Load() == nil || (*engines)[0].lastGate() != (antispam.LearningGate{}) {
		t.Fatal("an unseen controller stopped or kept publishing the learner")
	}
	// New keys or another controller socket mean a new engine.
	other := testTarget
	other.HashGeneration = "gen2"
	d.syncLearner(learnedOutcome(antispam.LearningGate{Install: true, Publish: true}, other))
	if len(*engines) != 2 {
		t.Fatalf("engines %d", len(*engines))
	}
	select {
	case <-(*engines)[0].stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("the old engine kept running")
	}
}

func TestLearningStopsOnDisable(t *testing.T) {
	engines := withFakeEngines(t)
	d := newLearningDaemon(t)
	d.syncLearner(learnedOutcome(antispam.LearningGate{Install: true, Publish: true}, testTarget))
	d.cfg.EmailProtection.Antispam.Learning.Enabled = false
	d.syncLearner(learnedOutcome(antispam.LearningGate{}, reconcile.LearnerTarget{}))
	e := (*engines)[0]
	select {
	case <-e.stopped:
	default:
		t.Fatal("disable returned before the engine stopped")
	}
	if g := e.lastGate(); g != (antispam.LearningGate{}) {
		t.Fatalf("the gate stayed open: %+v", g)
	}
	if d.antispamLearner.Load() != nil || antispamLearnOperator(d) != nil {
		t.Fatal("a stopped learner still takes requests")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(time.Millisecond)
	}
}

// Observe mode stops a running learner even if a pass still named a target.
func TestLearningStopsInObserveMode(t *testing.T) {
	engines := withFakeEngines(t)
	d := newLearningDaemon(t)
	d.syncLearner(learnedOutcome(antispam.LearningGate{Install: true, Publish: true}, testTarget))
	d.cfg.Mode = "observe"
	d.syncLearner(learnedOutcome(antispam.LearningGate{Install: true, Publish: true}, testTarget))
	select {
	case <-(*engines)[0].stopped:
	default:
		t.Fatal("observe mode left the learner running")
	}
	if len(*engines) != 1 || d.antispamLearner.Load() != nil {
		t.Fatal("observe mode started a learner")
	}
}

// Config wins over pass timing: observe mode or disabled learning stops the
// learner on reload and on a busy or canceled pass, not at the next
// completed pass.
func TestLearningStopsWithoutCompletedPass(t *testing.T) {
	for name, change := range map[string]func(d *Daemon){
		"observe":      func(d *Daemon) { d.cfg.Mode = "observe" },
		"learning off": func(d *Daemon) { d.cfg.EmailProtection.Antispam.Learning.Enabled = false },
		"antispam off": func(d *Daemon) { d.cfg.EmailProtection.Antispam.Enabled = false },
	} {
		t.Run(name, func(t *testing.T) {
			for _, trigger := range []func(d *Daemon){
				func(d *Daemon) { d.syncLearner(reconcile.Outcome{}) },
				func(d *Daemon) { d.reconcileAntispam() },
			} {
				engines := withFakeEngines(t)
				d := newLearningDaemon(t)
				d.syncLearner(learnedOutcome(antispam.LearningGate{Install: true, Publish: true}, testTarget))
				change(d)
				trigger(d)
				select {
				case <-(*engines)[0].stopped:
				default:
					t.Fatal("the learner kept running")
				}
				if d.antispamLearner.Load() != nil {
					t.Fatal("a stopped learner is still published")
				}
			}
		})
	}
}
