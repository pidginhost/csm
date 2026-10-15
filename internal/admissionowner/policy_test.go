package admissionowner

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/verdict"
)

var errNoCallback = errors.New("no verdict callback is configured")

func noVerdict(context.Context, string, string) (verdict.Response, error) {
	return verdict.Response{}, errNoCallback
}

// validPolicy is a live policy with the callback off.
func validPolicy(epoch uint64) ExecutionPolicy {
	return ExecutionPolicy{
		Epoch: epoch, VerdictTimeout: 2 * time.Second, CeilingLimit: 2000, CeilingSource: "default",
		Expiry:     func(admission.Candidate) time.Duration { return 24 * time.Hour },
		AskVerdict: noVerdict,
	}
}

// livePolicy publishes a live policy from opts' ceiling and expiry, with a
// new epoch whenever the ceiling changes, as the daemon's publisher does.
func livePolicy(opts Options) func() ExecutionPolicy {
	var mu sync.Mutex
	var current ExecutionPolicy
	return func() ExecutionPolicy {
		limit, source := opts.Ceiling()
		mu.Lock()
		defer mu.Unlock()
		if current.Epoch == 0 || limit != current.CeilingLimit || source != current.CeilingSource {
			current = validPolicy(current.Epoch + 1)
			current.CeilingLimit, current.CeilingSource, current.Expiry = limit, source, opts.Expiry
		}
		return current
	}
}

// policyReader is a provider the test publishes to.
type policyReader struct {
	mu    sync.Mutex
	p     ExecutionPolicy
	reads int
}

func (r *policyReader) read() ExecutionPolicy {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reads++
	return r.p
}

func (r *policyReader) publish(p ExecutionPolicy) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.p = p
}

func (r *policyReader) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.reads
}

func ownerStarted(t *testing.T, o *Owner) bool {
	t.Helper()
	var started bool
	if err := o.do(func() error { started = o.started; return nil }); err != nil {
		t.Fatal(err)
	}
	return started
}

// D11: an owner with Blocks binds to one coherent policy. It does not
// start without a provider or with a policy that is unpublished, lacks
// its asker or expiry, runs in mode: observe or carries a ceiling or
// timeout out of range, even with the callback off. It names the refusal,
// opens nothing and never reaches the engine.
func TestExecutableOwnerRefusesStartWithoutAValidPolicy(t *testing.T) {
	for name, mutate := range map[string]func(*Options, *ExecutionPolicy){
		"no provider": func(o *Options, _ *ExecutionPolicy) { o.Policy = nil },
		"unpublished": func(_ *Options, p *ExecutionPolicy) { p.Epoch = 0 },
		"no asker":    func(_ *Options, p *ExecutionPolicy) { p.AskVerdict = nil },
		"no expiry":   func(_ *Options, p *ExecutionPolicy) { p.Expiry = nil },
		"observe":     func(_ *Options, p *ExecutionPolicy) { p.Observe = true },
		"no ceiling":  func(_ *Options, p *ExecutionPolicy) { p.CeilingLimit = 0 },
		"big ceiling": func(_ *Options, p *ExecutionPolicy) { p.CeilingLimit = admission.MaxCeiling + 1 },
		"short wait":  func(_ *Options, p *ExecutionPolicy) { p.VerdictTimeout = time.Second - 1 },
		"long wait":   func(_ *Options, p *ExecutionPolicy) { p.VerdictTimeout = 30*time.Second + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			opts := executeOptions(f, blocks)
			p := validPolicy(1)
			r := &policyReader{}
			opts.Policy = r.read
			mutate(&opts, &p)
			r.publish(p)
			o := Start(opts)
			t.Cleanup(o.Stop)
			if st := o.Status(); st.Owner == nil || !strings.Contains(st.Owner.Error, ErrPolicy.Error()) || st.Ledger != nil {
				t.Fatalf("status = %+v", st.Owner)
			}
			if ownerStarted(t, o) {
				t.Fatal("the owner started")
			}
			if err := o.Reload(); !errors.Is(err, ErrPolicy) {
				t.Fatalf("reload of an owner refused its policy = %v", err)
			}
			if checks, applies := blocks.calls(); len(checks) != 0 || len(applies) != 0 {
				t.Fatalf("engine reached: %d checks, %d applies", len(checks), len(applies))
			}
		})
	}
	// A comparison-only owner needs no policy and never reads one.
	f := newOwnerFixture(t)
	r := &policyReader{}
	opts := previewOptions(f)
	opts.Policy = r.read
	o := f.start(opts)
	if st := o.Status(); st.Owner == nil || st.Owner.Error != "" || !ownerStarted(t, o) {
		t.Fatalf("comparison-only owner = %+v", st.Owner)
	}
	if err := o.Reload(); err != nil {
		t.Fatal(err)
	}
	if r.count() != 0 {
		t.Fatalf("a comparison-only owner read the policy %d times", r.count())
	}
}

// A turn uses the policy installed when it starts, for every pick. A
// policy published during the turn is installed by the reload, which
// returns only after that turn ends; later turns use only the new one.
func TestOwnerTurnKeepsOnePolicyAndReloadWaitsForIt(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	reached, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	first := validPolicy(1)
	first.Expiry = func(admission.Candidate) time.Duration {
		if calls.Add(1) == 1 {
			close(reached)
			<-release
		}
		return time.Hour
	}
	r := &policyReader{p: first}
	opts := executeOptions(f, blocks)
	opts.Policy = r.read
	o := f.start(opts)
	mono := heldMono(t, o)
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.11")
	turned := make(chan error, 1)
	go func() { turned <- o.do(o.turn) }()
	<-reached
	second := validPolicy(2)
	second.Expiry = func(admission.Candidate) time.Duration { return 2 * time.Hour }
	r.publish(second)
	reloaded := make(chan error, 1)
	go func() { reloaded <- o.Reload() }()
	select {
	case err := <-reloaded:
		t.Fatalf("reload acknowledged while a turn ran under the old policy: %v", err)
	default:
	}
	close(release)
	if err := <-turned; err != nil {
		t.Fatal(err)
	}
	if err := <-reloaded; err != nil {
		t.Fatal(err)
	}
	lease := f.host.now()
	_, applies := blocks.calls()
	if len(applies) != 1 || len(applies[0]) != 2 {
		t.Fatalf("applies = %v", applies)
	}
	for _, m := range applies[0] {
		if !m.ExpiresAt.Equal(lease.Add(time.Hour)) {
			t.Fatalf("member %+v does not keep the turn's policy", m)
		}
	}
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.12")
	mono.advance(batchEvery)
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	_, applies = blocks.calls()
	if len(applies) != 2 || len(applies[1]) != 1 || !applies[1][0].ExpiresAt.Equal(lease.Add(2*time.Hour)) {
		t.Fatalf("applies after the reload = %v", applies)
	}
}

// Different settings under the installed epoch and an invalid newer policy
// hold execution: block work waits, deferred as an unavailable engine, and
// status names the refusal. A turn installs a valid newer epoch without a
// reload, and an older epoch is ignored.
func TestOwnerHoldsExecutionOnARefusedPolicy(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	r := &policyReader{p: validPolicy(1)}
	opts := executeOptions(f, blocks)
	opts.Policy = r.read
	o := f.start(opts)
	heldMono(t, o)
	id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	conflict := validPolicy(1)
	conflict.CeilingLimit = 100
	r.publish(conflict)
	if err := o.Reload(); !errors.Is(err, ErrPolicy) {
		t.Fatalf("conflicting reload = %v", err)
	}
	if held := o.Status().Owner.ExecutionHeld; !strings.Contains(held, "epoch 1 was published again") {
		t.Fatalf("execution held = %q", held)
	}
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if c := candidate(t, o, id); c.State != admission.StateQueued || c.Reason != admission.ReasonEngineUnavailable || c.Attempts != 0 {
		t.Fatalf("held pick = %+v", c)
	}
	if checks, applies := blocks.calls(); len(checks) != 0 || len(applies) != 0 {
		t.Fatalf("a held turn reached the engine: %d checks, %d applies", len(checks), len(applies))
	}
	if limit := ceiling(t, o).Limit; limit != 2000 {
		t.Fatalf("a refused policy set the ceiling to %d", limit)
	}
	r.publish(validPolicy(2))
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if c := candidate(t, o, id); c.State != admission.StateVerified || o.Status().Owner.ExecutionHeld != "" {
		t.Fatalf("after a valid epoch: %+v, held %q", c, o.Status().Owner.ExecutionHeld)
	}
	older := validPolicy(1)
	older.DryRun = true
	r.publish(older)
	if err := o.Reload(); err != nil {
		t.Fatalf("an older epoch was not ignored: %v", err)
	}
	invalid := validPolicy(3)
	invalid.AskVerdict = nil
	r.publish(invalid)
	if err := o.Reload(); !errors.Is(err, ErrPolicy) || o.Status().Owner.ExecutionHeld == "" {
		t.Fatalf("invalid newer epoch = %v, held %q", err, o.Status().Owner.ExecutionHeld)
	}
}

// A dry-run policy never reaches the engine: its block picks stay queued
// without an attempt, charge or deferral. A newer live epoch runs them.
func TestOwnerDryRunPolicyNeverReachesTheEngine(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	dry := validPolicy(1)
	dry.DryRun = true
	r := &policyReader{p: dry}
	opts := executeOptions(f, blocks)
	opts.Policy = r.read
	o := f.start(opts)
	heldMono(t, o)
	id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if c := candidate(t, o, id); c.State != admission.StateQueued || c.Reason != 0 || c.Attempts != 0 {
		t.Fatalf("dry-run pick = %+v", c)
	}
	if checks, applies := blocks.calls(); len(checks) != 0 || len(applies) != 0 || ledgerStatus(t, o).Ceiling.General.Used != 0 {
		t.Fatalf("dry run reached the engine: %d checks, %d applies", len(checks), len(applies))
	}
	r.publish(validPolicy(2))
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if c := candidate(t, o, id); c.State != admission.StateVerified {
		t.Fatalf("live pick = %+v", c)
	}
}

// An executable owner takes its ceiling from the installed policy, not
// from Options.Ceiling, and a newer epoch applies its ceiling at the next
// turn.
func TestExecutableOwnerTakesItsPolicyCeiling(t *testing.T) {
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	first := validPolicy(1)
	first.CeilingLimit, first.CeilingSource = 100, "configured"
	r := &policyReader{p: first}
	opts := executeOptions(f, blocks)
	opts.Policy = r.read
	o := f.start(opts)
	if limit := ceiling(t, o).Limit; limit != 100 || o.Status().Owner.CeilingSource != "configured" {
		t.Fatalf("ceiling %d from %q", limit, o.Status().Owner.CeilingSource)
	}
	next := validPolicy(2)
	next.CeilingLimit = 300
	r.publish(next)
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if limit := ceiling(t, o).Limit; limit != 300 {
		t.Fatalf("ceiling after a new epoch = %d", limit)
	}
}
