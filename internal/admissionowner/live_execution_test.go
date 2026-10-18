package admissionowner

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
)

// This package's tests exercise live execution; production keeps it off
// until plan 1.4c-2b. A test that needs the production value says so with
// withLiveExecution.
func init() { liveExecution = true }

// withLiveExecution sets liveExecution for one test. Call it before the
// owners the test starts: cleanup restores it after they have stopped.
func withLiveExecution(t *testing.T, on bool) {
	t.Helper()
	previous := liveExecution
	liveExecution = on
	t.Cleanup(func() { liveExecution = previous })
}

// Ruling C2: until live execution is turned on, an owner with an engine
// previews its block picks under a live policy as an owner without one
// does. Nothing reaches the engine or the panel, status says it does not
// execute and its callback stage does not run.
func TestOwnerPreviewsBlockPicksUnderALivePolicy(t *testing.T) {
	withLiveExecution(t, false)
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	panel := newFakePanel("")
	o, _, _ := verdictOwner(t, f, blocks, panel)
	var ids []admission.CandidateID
	for _, addr := range []string{"192.0.2.10", "2001:db8::10"} {
		id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, addr)
		ids = append(ids, id)
	}
	turn(t, o)
	for _, id := range ids {
		c := candidate(t, o, id)
		if c.State != admission.StateObserved || c.Disposition != admission.DispositionObserve || c.Attempts != 1 {
			t.Fatalf("block pick under a live policy = %+v", c)
		}
	}
	checks, applies := blocks.calls()
	if len(checks) != 0 || len(applies) != 0 || len(blocks.snapshots) != 0 || blocks.marks != 0 || blocks.stateProbes != 0 {
		t.Fatalf("engine calls: %d checks, %d applies, %d snapshots, %d marks, %d probes", len(checks), len(applies), len(blocks.snapshots), blocks.marks, blocks.stateProbes)
	}
	if asked, _, _, _ := panel.state(); len(asked) != 0 {
		t.Fatalf("the panel was asked about %v", asked)
	}
	if s := o.Status(); s.Owner == nil || s.Owner.Executing || s.Owner.ExecutionHeld != "" {
		t.Fatalf("owner status = %+v", s.Owner)
	}
	var stage bool
	if err := o.do(func() error { stage = o.verdicts.stage != nil; return nil }); err != nil {
		t.Fatal(err)
	}
	if v := verdictState(t, o); stage || v.Enabled {
		t.Fatalf("callback stage running %v, status %+v", stage, v)
	}
}

// A refused policy still holds firewall picks while live execution is
// off: they wait as an unavailable engine, nothing is previewed, and
// status names the refusal without claiming execution.
func TestPreviewOnlyOwnerHoldsPicksOnARefusedPolicy(t *testing.T) {
	withLiveExecution(t, false)
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	o, r, _ := policyOwner(t, f, newFakeBlocks(), validPolicy(1))
	id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	refused := validPolicy(2)
	refused.CeilingLimit = 0
	r.publish(refused)
	turn(t, o)
	if c := candidate(t, o, id); c.State != admission.StateQueued || c.Reason != admission.ReasonEngineUnavailable || c.Attempts != 0 {
		t.Fatalf("pick under a refused policy = %+v", c)
	}
	if s := o.Status(); s.Owner == nil || s.Owner.Executing || s.Owner.ExecutionHeld == "" {
		t.Fatalf("owner status = %+v", s.Owner)
	}
}

// A dry-run host whose policy flips to live and back: the live policy ends
// the forecast and its examples are purged, block picks are then previewed
// with no engine call or panel ask, and the next dry-run policy forecasts
// in a session of its own.
func TestPreviewOnlyOwnerFollowsModeFlips(t *testing.T) {
	withLiveExecution(t, false)
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	panel := newFakePanel("")
	dry := verdictPolicy(1, panel)
	dry.DryRun = true
	o, r, mono := policyOwner(t, f, blocks, dry)
	first, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	turn(t, o)
	eventually(t, "the panel", func() bool { return verdictState(t, o).Pending == 0 })
	mono.advance(batchEvery)
	turn(t, o)
	session := forecastOf(t, o)
	if c := candidate(t, o, first); c.State != admission.StateDryRun || session == nil || f.db.DryRunBlocksCount() != 1 {
		t.Fatalf("dry-run pick = %+v, session %+v, %d examples", c, session, f.db.DryRunBlocksCount())
	}
	live := verdictPolicy(2, panel)
	r.publish(live)
	if err := o.Reload(); err != nil {
		t.Fatal(err)
	}
	asked, _, _, _ := panel.state()
	snapshots := len(blocks.snapshots)
	second, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.11")
	mono.advance(batchEvery)
	turn(t, o)
	maintain(t, o, mono)
	if c := candidate(t, o, second); c.State != admission.StateObserved {
		t.Fatalf("pick under a live policy = %+v", c)
	}
	checks, applies := blocks.calls()
	if again, _, _, _ := panel.state(); len(again) != len(asked) || len(blocks.snapshots) != snapshots || len(checks) != 0 || len(applies) != 0 {
		t.Fatalf("a live policy reached the panel %v or the engine: %d snapshots, %d checks, %d applies", again, len(blocks.snapshots), len(checks), len(applies))
	}
	if forecastOf(t, o) != nil || f.db.DryRunBlocksCount() != 0 {
		t.Fatalf("the forecast outlived the flip: %d examples", f.db.DryRunBlocksCount())
	}
	dry.Epoch = 3
	r.publish(dry)
	third, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.12")
	mono.advance(batchEvery)
	turn(t, o)
	eventually(t, "the panel", func() bool { return verdictState(t, o).Pending == 0 })
	mono.advance(batchEvery)
	turn(t, o)
	if c := candidate(t, o, third); c.State != admission.StateDryRun {
		t.Fatalf("pick after the flip back = %+v", c)
	}
	if next := forecastOf(t, o); next == nil || next.id == session.id {
		t.Fatalf("the flip back reused session %+v", next)
	}
}

// While live execution is off, forecasting and previewing leave no genuine safety
// state in the ledger. Every attempt is a preview, every charge is a
// preview's or the imported legacy hour's, and no intent holds an address.
// A build that refuses this ledger forgets nothing legacy blocking does not
// keep itself.
func TestForecastAndPreviewLeaveNoGenuineState(t *testing.T) {
	withLiveExecution(t, false)
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	f.legacy(`{"ips":[],"blocks_this_hour":12,"hour_key":"2026-10-04T12"}`)
	o, r, mono := policyOwner(t, f, newFakeBlocks(), dryPolicy(1))
	forecast, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	turn(t, o)
	r.publish(validPolicy(2))
	previewed, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.11")
	mono.advance(batchEvery)
	turn(t, o)
	if c := candidate(t, o, forecast); c.State != admission.StateDryRun || c.Attempts != 0 {
		t.Fatalf("forecast pick = %+v", c)
	}
	if c := candidate(t, o, previewed); c.State != admission.StateObserved {
		t.Fatalf("previewed pick = %+v", c)
	}
	var charges []admission.Charge
	var intents []admission.Intent
	if err := o.do(func() (err error) {
		if _, charges, err = o.ledger.CeilingSnapshot(); err != nil {
			return err
		}
		intents, err = o.ledger.UnresolvedIntents()
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var legacy, previews uint32
	for _, c := range charges {
		var a admission.AttemptRecord
		err := o.do(func() (err error) { a, err = o.ledger.Attempt(c.Action); return err })
		switch {
		case err != nil:
			end := time.Date(2026, 10, 4, 13, 0, 0, 0, time.UTC)
			reason, ok := admission.ReasonOf(err)
			if !ok || reason != admission.ReasonInvalid || c.Action != admission.LegacyActionID(end, 1) || c.Cost != 12 {
				t.Fatalf("unexpected attempt lookup failure for charge %+v: %v", c, err)
			}
			legacy += c.Cost
		case a.State == admission.StateObserved:
			previews += c.Cost
		default:
			t.Fatalf("charge %s belongs to a genuine attempt %+v", c.Action, a)
		}
	}
	if legacy != 12 || previews != 1 || len(intents) != 0 {
		t.Fatalf("legacy units %d, preview units %d, intents %+v", legacy, previews, intents)
	}
}

// Status says the owner executes only with an engine, live execution and a
// live policy: a forecasting owner and a preview-only owner do not.
func TestOwnerExecutesOnlyUnderALivePolicy(t *testing.T) {
	for _, tc := range []struct {
		name      string
		live, dry bool
		want      bool
	}{
		{"live", true, false, true},
		{"dry run", true, true, false},
		{"preview only", false, false, false},
		{"preview only dry run", false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withLiveExecution(t, tc.live)
			withTestRegistry(t)
			f := newOwnerFixture(t)
			first := validPolicy(1)
			first.DryRun = tc.dry
			o, _, _ := policyOwner(t, f, newFakeBlocks(), first)
			turn(t, o)
			if s := o.status(); s.Owner == nil || s.Owner.Executing != tc.want {
				t.Fatalf("owner status = %+v, want executing %v", s.Owner, tc.want)
			}
		})
	}
}

// Ruling C2: no configuration and no production code turns live execution
// on. Only this package's tests set it.
func TestOnlyTestsTurnOnLiveExecution(t *testing.T) {
	declared := 0
	for path, f := range productionFiles(t) {
		n, violations := liveExecutionUses(path, f)
		declared += n
		for _, v := range violations {
			t.Error(v)
		}
	}
	if declared != 1 {
		t.Fatalf("liveExecution is declared %d times, want once", declared)
	}
}

// The guard finds a write, a pointer that could write and a declaration
// that starts it on.
func TestLiveExecutionGuardRejectsWrites(t *testing.T) {
	for name, src := range map[string]string{
		"assignment":               "package admissionowner\nvar liveExecution = false\nfunc f() { liveExecution = true }\n",
		"parenthesized assignment": "package admissionowner\nvar liveExecution = false\nfunc f() { (liveExecution) = true }\n",
		"parenthesized pointer":    "package admissionowner\nvar liveExecution = false\nfunc f() *bool { return &(liveExecution) }\n",
		"pointer":                  "package admissionowner\nvar liveExecution = false\nfunc f() *bool { return &liveExecution }\n",
		"on":                       "package admissionowner\nvar liveExecution = true\n",
	} {
		f, err := parser.ParseFile(token.NewFileSet(), "x.go", src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		if _, violations := liveExecutionUses("internal/admissionowner/x.go", f); len(violations) == 0 {
			t.Errorf("%s: the guard found nothing", name)
		}
	}
}

// liveExecutionUses counts f's declarations of liveExecution and names
// every write, address or declaration that is not false.
func liveExecutionUses(path string, f *ast.File) (int, []string) {
	declared := 0
	var violations []string
	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.ValueSpec:
			for i, name := range n.Names {
				if name.Name != "liveExecution" {
					continue
				}
				declared++
				if len(n.Values) <= i || !isFalse(n.Values[i]) {
					violations = append(violations, fmt.Sprintf("%s: liveExecution is not declared false", path))
				}
			}
		case *ast.AssignStmt:
			for _, lhs := range n.Lhs {
				if id, ok := unparen(lhs).(*ast.Ident); ok && id.Name == "liveExecution" {
					violations = append(violations, fmt.Sprintf("%s: assigns liveExecution", path))
				}
			}
		case *ast.UnaryExpr:
			if id, ok := unparen(n.X).(*ast.Ident); ok && n.Op == token.AND && id.Name == "liveExecution" {
				violations = append(violations, fmt.Sprintf("%s: takes the address of liveExecution", path))
			}
		}
		return true
	})
	return declared, violations
}

func unparen(e ast.Expr) ast.Expr {
	for {
		p, ok := e.(*ast.ParenExpr)
		if !ok {
			return e
		}
		e = p.X
	}
}

func isFalse(e ast.Expr) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == "false"
}

// Stored real unknowns survive a restart into preview-only mode. Their
// expiry must not let the owner retire engine rows under a live policy.
func TestPreviewOnlyOwnerLeavesStoredUnknownsAlone(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o := f.start(executeOptions(f, blocks))
	c, _ := unknownBlock(t, o, p, f, blocks, "192.0.2.10")
	o.Stop()
	withLiveExecution(t, false)
	f.host.advance(25 * time.Hour)
	fresh := newFakeBlocks()
	o = f.start(executeOptions(f, fresh))
	turn(t, o)
	if got := attemptOf(t, o, c); got.Retired || got.State != admission.StateUnknown {
		t.Fatalf("stored unknown changed: %+v", got)
	}
	if calls := fresh.retireCalls(); len(calls) != 0 {
		t.Fatalf("preview-only retirement reached the engine: %+v", calls)
	}
}

// A retained hold can reach the idle serve tail without any new block
// pick. Neither that path nor direct readiness/dispatch may repair it.
func TestPreviewOnlyOwnerLeavesEngineHoldsAlone(t *testing.T) {
	for _, route := range []string{"serve", "schedule", "ready", "execute"} {
		t.Run(route, func(t *testing.T) {
			withLiveExecution(t, false)
			withTestRegistry(t)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			o, _, mono := policyOwner(t, f, blocks, validPolicy(1))
			if err := o.do(func() error {
				o.hold(firewall.ErrBlockBatchState, false)
				o.scheduleDue, o.wakeAt = false, time.Time{}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			mono.advance(maxProbeWait)
			if err := o.do(func() error {
				switch route {
				case "serve":
					return o.serve()
				case "schedule":
					o.schedule()
					return o.scheduleErr
				case "ready":
					if o.ready(blocks, false) {
						t.Error("preview-only readiness granted execution")
					}
				case "execute":
					return o.execute(nil)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			checks, applies := blocks.calls()
			if len(checks) != 0 || len(applies) != 0 || blocks.marks != 0 || blocks.stateProbes != 0 || executionHeld(t, o) == "" {
				t.Fatalf("%s changed a held engine: checks=%d applies=%d marks=%d probes=%d hold=%q", route, len(checks), len(applies), blocks.marks, blocks.stateProbes, executionHeld(t, o))
			}
		})
	}
}
