package admissionowner

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/store"
	"github.com/pidginhost/csm/internal/verdict"
)

func dryPolicy(epoch uint64) ExecutionPolicy {
	p := validPolicy(epoch)
	p.DryRun = true
	return p
}

// policyOwner starts an executable owner under the policies r publishes.
func policyOwner(t *testing.T, f *ownerFixture, blocks *fakeBlocks, first ExecutionPolicy) (*Owner, *policyReader, *fakeMono) {
	t.Helper()
	r := &policyReader{p: first}
	opts := executeOptions(f, blocks)
	opts.Policy = r.read
	o := f.start(opts)
	return o, r, heldMono(t, o)
}

// forecastView is a copy of the owner's forecast session.
type forecastView struct {
	id      string
	reset   resetReason
	entries map[string]shadowEntry
	picks   [predictionEnd]uint64
	ceiling admission.CeilingState
}

// forecastOf reads the forecast session on the owner goroutine; nil when
// none runs.
func forecastOf(t *testing.T, o *Owner) *forecastView {
	t.Helper()
	var v *forecastView
	if err := o.do(func() error {
		if s := o.shadow; s != nil {
			v = &forecastView{id: s.id, reset: s.reset, entries: maps.Clone(s.entries), picks: s.picks, ceiling: s.ceiling}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return v
}

func turn(t *testing.T, o *Owner) {
	t.Helper()
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
}

// observe hands the ingress a new observation of addr and drains it, so
// the ledger names the episode and generation. An observation of an ended
// episode's target must be later than its ending.
func observe(t *testing.T, o *Owner, p *admission.Producer, f *ownerFixture, addr, cursor string) admission.CandidateID {
	t.Helper()
	submitObservation(t, o, p, addr, cursor, f.host.now())
	if err := o.do(o.drain); err != nil {
		t.Fatal(err)
	}
	for _, c := range queuedCandidates(t, o) {
		if c.Key.Target.Key() == "ip:"+addr {
			id, err := c.ID()
			if err != nil {
				t.Fatal(err)
			}
			return id
		}
	}
	t.Fatalf("no queued candidate for %s", addr)
	return ""
}

func liveUsed(t *testing.T, o *Owner) uint32 {
	t.Helper()
	c := ceiling(t, o)
	return c.General.Used + c.Reserved.Used
}

// D1, spec 3.3: under a dry-run policy each block pick ends as a dry run
// with a prediction and no attempt, charge, link or engine change. One
// read-only snapshot answers the turn. With real occupancy 8 of 10, two
// distinct picks, of either family, fit the forecast and the third finds
// the modelled set full. Only the forecast's own ceiling is charged.
func TestOwnerEndsDryRunPicksAsForecasts(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	blocks.temp, blocks.limit = 8, 10
	o, _, _ := policyOwner(t, f, blocks, dryPolicy(1))
	var ids []admission.CandidateID
	for _, addr := range []string{"192.0.2.10", "2001:db8::10", "192.0.2.11"} {
		id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, addr)
		ids = append(ids, id)
	}
	history := ledgerStatus(t, o).Storage
	turn(t, o)
	for _, id := range ids {
		c := candidate(t, o, id)
		if c.State != admission.StateDryRun || c.Disposition != admission.DispositionDryRun || c.Reason != 0 || c.Attempts != 0 || c.Link != (admission.EffectLink{}) {
			t.Fatalf("dry-run pick = %+v", c)
		}
	}
	checks, applies := blocks.calls()
	if len(checks) != 0 || len(applies) != 0 || len(blocks.snapshots) != 1 || len(blocks.snapshots[0]) != 3 || blocks.marks != 0 || blocks.stateProbes != 0 {
		t.Fatalf("engine calls: %d checks, %d applies, %d snapshots, %d marks, %d probes", len(checks), len(applies), len(blocks.snapshots), blocks.marks, blocks.stateProbes)
	}
	if used := liveUsed(t, o); used != 0 {
		t.Fatalf("a forecast charged the live ceiling %d units", used)
	}
	if s := ledgerStatus(t, o).Storage; s.General.Used != history.General.Used || s.Reserved.Used != history.Reserved.Used || len(pendingAudit(t, o)) != 0 {
		t.Fatalf("a forecast allocated history or audit rows: %+v", s)
	}
	if n := outcomes(ledgerStatus(t, o), admission.DispositionDryRun); n != 3 {
		t.Fatalf("dry-run outcomes = %d", n)
	}
	fc := forecastOf(t, o)
	if fc == nil || fc.reset != resetStartup || len(fc.entries) != 2 || fc.picks[predictCapacityAdmit] != 2 || fc.picks[predictSetFull] != 1 {
		t.Fatalf("forecast = %+v", fc)
	}
	if fc.ceiling.General.Used+fc.ceiling.Reserved.Used != 2 {
		t.Fatalf("forecast ceiling = %+v", fc.ceiling)
	}
	if s := verdictState(t, o); s.Pending != 0 || s.Asked != 0 {
		t.Fatalf("a forecast without a callback asked: %+v", s)
	}
}

// Spec 3.4, 6.2: a forecast starts from the real ceiling, spent credit
// included, when the mode changes, and then lives apart from it. With L=5
// a live block spends the one general unit; the forecast of the next pick
// waits for the ceiling, fifteen minutes later one fits, and another at
// once waits again although live credit has refilled meanwhile: live
// credit is never copied over a running forecast.
func TestOwnerForecastStartsFromTheRealCeiling(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	live := validPolicy(1)
	live.CeilingLimit = 5
	o, r, mono := policyOwner(t, f, blocks, live)
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	turn(t, o)
	if _, applies := blocks.calls(); len(applies) != 1 || ceiling(t, o).Budget(admission.LaneGeneral) != 0 {
		t.Fatalf("fixture: the live block did not spend the general unit: %d applies", len(applies))
	}
	dry := dryPolicy(2)
	dry.CeilingLimit = 5
	r.publish(dry)
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.11")
	turn(t, o)
	fc := forecastOf(t, o)
	if fc == nil || fc.reset != resetModeChange || fc.picks[predictCeiling] != 1 || len(fc.entries) != 0 || fc.ceiling.General.Used != 1 {
		t.Fatalf("forecast after a live block = %+v", fc)
	}
	mono.advance(15 * time.Minute)
	f.host.advance(15 * time.Minute)
	if err := o.do(o.tick); err != nil {
		t.Fatal(err)
	}
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.12")
	turn(t, o)
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.13")
	turn(t, o)
	fc = forecastOf(t, o)
	if fc.picks[predictCapacityAdmit] != 1 || fc.picks[predictCeiling] != 2 || len(fc.entries) != 1 || fc.ceiling.General.Used != 2 {
		t.Fatalf("forecast = %+v", fc)
	}
	if budget := ceiling(t, o).Budget(admission.LaneGeneral); budget != 1 || liveUsed(t, o) != 1 {
		t.Fatalf("live budget %d, used %d: the forecast touched the ledger", budget, liveUsed(t, o))
	}
}

// Spec 3.3, 3.4: a real block that already covers the address ends the pick
// as existing_actual, unlinked, without answering the episode. A forecast
// block that lasts as long answers a later generation as existing_shadow,
// a shorter one holds it as pending_recovery, neither renews it, and a
// dry-run policy change keeps the session. Once its lease ends on the
// engine's clock the address can be forecast again.
func TestOwnerForecastsExistingAndCoveringBlocks(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	blocks.refuse["192.0.2.20"] = firewall.BlockRefusedExisting
	o, r, mono := policyOwner(t, f, blocks, dryPolicy(1))
	existing := observe(t, o, p, f, "192.0.2.20", "offset=1")
	turn(t, o)
	if c := candidate(t, o, existing); c.State != admission.StateDryRun || c.Link != (admission.EffectLink{}) {
		t.Fatalf("existing pick = %+v", c)
	}
	f.host.advance(time.Second)
	if next := observe(t, o, p, f, "192.0.2.20", "offset=2"); next == existing {
		t.Fatal("an existing effect answered the episode")
	}
	first := f.host.now().Add(24 * time.Hour)
	observe(t, o, p, f, "192.0.2.10", "offset=1")
	turn(t, o)
	fc := forecastOf(t, o)
	if fc.picks[predictExistingActual] != 2 || fc.picks[predictCapacityAdmit] != 1 || !fc.entries["192.0.2.10"].expires.Equal(first) {
		t.Fatalf("forecast = %+v", fc)
	}
	session := fc.id
	shorter := dryPolicy(2)
	shorter.Expiry = func(admission.Candidate) time.Duration { return time.Hour }
	r.publish(shorter)
	mono.advance(time.Second)
	f.host.advance(time.Second)
	observe(t, o, p, f, "192.0.2.10", "offset=2")
	turn(t, o)
	longer := dryPolicy(3)
	longer.Expiry = func(admission.Candidate) time.Duration { return 48 * time.Hour }
	r.publish(longer)
	f.host.advance(time.Second)
	observe(t, o, p, f, "192.0.2.10", "offset=3")
	turn(t, o)
	fc = forecastOf(t, o)
	if fc.id != session || fc.picks[predictExistingShadow] != 1 || fc.picks[predictPendingRecovery] != 1 || fc.picks[predictCapacityAdmit] != 1 || !fc.entries["192.0.2.10"].expires.Equal(first) {
		t.Fatalf("forecast after repeats = %+v", fc)
	}
	if shadows := blocks.shadows[len(blocks.shadows)-1]; len(shadows) != 1 || shadows[0] != "192.0.2.10" {
		t.Fatalf("the snapshot was not told the forecast blocks: %v", shadows)
	}
	f.host.advance(24 * time.Hour)
	mono.advance(24 * time.Hour)
	if err := o.do(o.tick); err != nil {
		t.Fatal(err)
	}
	observe(t, o, p, f, "192.0.2.10", "offset=4")
	turn(t, o)
	if fc = forecastOf(t, o); fc.picks[predictCapacityAdmit] != 2 || !fc.entries["192.0.2.10"].expires.Equal(f.host.now().Add(48*time.Hour)) {
		t.Fatalf("forecast after the lease ended = %+v", fc)
	}
}

// Spec 3.1: kinds without a capacity model end as not_modelled dry runs
// without a snapshot, forecast block or charge; a challenge keeps its
// comparison preview. No kind reaches a mutating engine method or the
// live ceiling.
func TestOwnerForecastsEveryKindWithoutEffects(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o, _, _ := policyOwner(t, f, blocks, dryPolicy(1))
	promote, _ := queuedKind(t, o, p, f.host, admission.SeverityHigh, "192.0.2.20", admission.KindPromote)
	prefix, err := admission.CanonicalPrefix("198.51.100.0/24", admission.Caps{IPv6: true})
	if err != nil {
		t.Fatal(err)
	}
	subnet, _ := queuedTarget(t, o, p, f.host, admission.SeverityHigh, "198.51.100.7", admission.KindBlockSubnet, prefix)
	challenge, _ := queuedKind(t, o, p, f.host, admission.SeverityHigh, "192.0.2.21", admission.KindChallenge)
	before := forecastOf(t, o)
	turn(t, o)
	for _, id := range []admission.CandidateID{promote, subnet} {
		if c := candidate(t, o, id); c.State != admission.StateDryRun || c.Attempts != 0 {
			t.Fatalf("unmodelled pick = %+v", c)
		}
	}
	if c := candidate(t, o, challenge); c.State != admission.StateObserved {
		t.Fatalf("challenge = %+v", c)
	}
	fc := forecastOf(t, o)
	if before != nil || fc == nil || fc.picks[predictNotModelled] != 2 || len(fc.entries) != 0 || fc.ceiling.General.Used+fc.ceiling.Reserved.Used != 0 {
		t.Fatalf("forecast = %+v", fc)
	}
	checks, applies := blocks.calls()
	if len(checks) != 0 || len(applies) != 0 || len(blocks.snapshots) != 0 || blocks.marks != 0 || liveUsed(t, o) != 0 {
		t.Fatalf("engine calls: %d checks, %d applies, %d snapshots, %d marks, live used %d", len(checks), len(applies), len(blocks.snapshots), blocks.marks, liveUsed(t, o))
	}
}

// Spec 3.3 step 1, 3.4: without an engine, with a degraded clock, or with
// a snapshot that fails or answers other members, block picks wait as an
// unavailable engine with no forecast change; nothing repairs or probes
// the engine. Unmodelled kinds need no engine, but a degraded clock
// freezes every prediction.
func TestOwnerForecastWaitsForTheEngineAndClock(t *testing.T) {
	for _, fault := range []string{"engine", "clock", "snapshot", "mismatch"} {
		t.Run(fault, func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			r := &policyReader{p: dryPolicy(1)}
			opts := executeOptions(f, blocks)
			opts.Policy = r.read
			switch fault {
			case "engine":
				opts.Blocks = func() BlockEngine { return nil }
			case "snapshot":
				blocks.checkErr = errors.New("state file unreadable")
			case "mismatch":
				blocks.shortChecks = true
			}
			o := f.start(opts)
			heldMono(t, o)
			queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.9")
			turn(t, o)
			block, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
			promote, _ := queuedKind(t, o, p, f.host, admission.SeverityHigh, "192.0.2.11", admission.KindPromote)
			before := forecastOf(t, o)
			if fault == "clock" {
				f.host.set(func(h *fakeHost) { h.wall = h.wall.Add(-time.Minute) })
			}
			snapshots := len(blocks.snapshots)
			turn(t, o)
			if c := candidate(t, o, block); c.State != admission.StateQueued || c.Reason != admission.ReasonEngineUnavailable || c.Attempts != 0 {
				t.Fatalf("block pick = %+v", c)
			}
			c := candidate(t, o, promote)
			if fault == "clock" {
				if c.State != admission.StateQueued || c.Reason != admission.ReasonEngineUnavailable {
					t.Fatalf("a degraded clock forecast %+v", c)
				}
				if len(blocks.snapshots) != snapshots {
					t.Fatal("a degraded clock read the engine")
				}
			} else if c.State != admission.StateDryRun {
				t.Fatalf("unmodelled pick = %+v", c)
			}
			after := forecastOf(t, o)
			if fault != "clock" {
				after.picks[predictNotModelled]--
			}
			if !maps.Equal(after.entries, before.entries) || after.picks != before.picks || after.ceiling != before.ceiling {
				t.Fatalf("forecast changed: before %+v, after %+v", before, after)
			}
			if checks, applies := blocks.calls(); len(checks) != 0 || len(applies) != 0 || blocks.marks != 0 || blocks.stateProbes != 0 {
				t.Fatalf("engine reached: %d checks, %d applies, %d marks, %d probes", len(checks), len(applies), blocks.marks, blocks.stateProbes)
			}
		})
	}
}

// Spec 3.5, 6.1: a decision is installed only after its ending commits. A
// failed ending stops the turn with its pick and the rest queued; only
// the picks already ended changed the forecast. The retry charges each
// remaining pick once.
func TestOwnerForecastInstallsOnlyCommittedEndings(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o, _, _ := policyOwner(t, f, blocks, dryPolicy(1))
	fail := errors.New("disk full")
	calls := 0
	end := endDryRunLedger
	setOwnerHook(t, o, &endDryRunLedger, func(l *store.AdmissionLedger, id admission.CandidateID) (admission.Candidate, bool, error) {
		calls++
		if calls == 2 {
			return admission.Candidate{}, false, fail
		}
		return end(l, id)
	})
	for _, addr := range []string{"192.0.2.10", "192.0.2.11", "192.0.2.12"} {
		queuedAt(t, o, p, f.host, admission.SeverityHigh, addr)
	}
	if err := o.do(o.turn); !errors.Is(err, fail) {
		t.Fatalf("turn = %v", err)
	}
	if n := len(queuedCandidates(t, o)); n != 2 {
		t.Fatalf("%d picks still queued", n)
	}
	for _, c := range queuedCandidates(t, o) {
		if c.Attempts != 0 || c.Reason != 0 {
			t.Fatalf("an unended pick changed: %+v", c)
		}
	}
	fc := forecastOf(t, o)
	if len(fc.entries) != 1 || fc.picks[predictCapacityAdmit] != 1 || fc.ceiling.General.Used+fc.ceiling.Reserved.Used != 1 {
		t.Fatalf("forecast after a failed ending = %+v", fc)
	}
	turn(t, o)
	fc = forecastOf(t, o)
	if len(queuedCandidates(t, o)) != 0 || len(fc.entries) != 3 || fc.picks[predictCapacityAdmit] != 3 || fc.ceiling.General.Used+fc.ceiling.Reserved.Used != 3 {
		t.Fatalf("forecast after the retry = %+v", fc)
	}
	if n := outcomes(ledgerStatus(t, o), admission.DispositionDryRun); n != 3 {
		t.Fatalf("dry-run outcomes = %d", n)
	}
}

// Spec 3.7: a restart starts a new session from the real ceiling, without
// the forecast blocks or counts of the old one; the durable outcomes stay.
func TestOwnerRestartStartsANewForecast(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	r := &policyReader{p: dryPolicy(1)}
	opts := executeOptions(f, blocks)
	opts.Policy = r.read
	o := f.start(opts)
	observe(t, o, p, f, "192.0.2.10", "offset=1")
	turn(t, o)
	old := forecastOf(t, o)
	o.Stop()
	o = f.start(opts)
	f.host.advance(time.Second)
	observe(t, o, p, f, "192.0.2.10", "offset=2")
	turn(t, o)
	fc := forecastOf(t, o)
	if fc.id == old.id || fc.reset != resetStartup || fc.picks[predictCapacityAdmit] != 1 || fc.picks[predictExistingShadow] != 0 || len(fc.entries) != 1 {
		t.Fatalf("forecast after a restart = %+v, before %+v", fc, old)
	}
	if fc.ceiling.General.Used+fc.ceiling.Reserved.Used != 1 || liveUsed(t, o) != 0 {
		t.Fatalf("restart seeded simulated charges: %+v", fc.ceiling)
	}
	if n := outcomes(ledgerStatus(t, o), admission.DispositionDryRun); n != 2 {
		t.Fatalf("dry-run outcomes = %d", n)
	}
}

// Spec 3.2, 6.2: spent live ceiling and history budgets do not stop
// forecast selection, and nothing waits on them: picks reach the model,
// no ceiling deferral is recorded, and work left over by the member
// bound wakes the next turn without new input.
func TestOwnerForecastIgnoresLiveBudgets(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	live := validPolicy(1)
	live.CeilingLimit = 2
	o, r, mono := policyOwner(t, f, blocks, live)
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	turn(t, o)
	if budget := ceiling(t, o).Budget(admission.LaneGeneral); budget != 0 {
		t.Fatalf("fixture: live budget %d", budget)
	}
	dry := dryPolicy(2)
	dry.CeilingLimit = 2
	r.publish(dry)
	for i := range admission.MaxBatchMembers + 1 {
		queuedAt(t, o, p, f.host, admission.SeverityHigh, fmt.Sprintf("2001:db8::%x", i+1))
	}
	mono.advance(time.Second)
	if err := o.do(func() error { o.scheduleDue = true; o.schedule(); return o.scheduleErr }); err != nil {
		t.Fatal(err)
	}
	if n := len(queuedCandidates(t, o)); n != 1 {
		t.Fatalf("%d picks left after one forecast turn", n)
	}
	mono.advance(time.Second)
	if err := o.do(func() error { o.schedule(); return o.scheduleErr }); err != nil {
		t.Fatal(err)
	}
	if n := len(queuedCandidates(t, o)); n != 0 {
		t.Fatalf("the forecast did not wake for the rest: %d queued", n)
	}
	if fc := forecastOf(t, o); fc.picks[predictCeiling] != admission.MaxBatchMembers+1 {
		t.Fatalf("forecast = %+v", fc)
	}
	for _, row := range ledgerStatus(t, o).Counters.Rows {
		if row.Reason == admission.ReasonCeiling.String() || row.Reason == admission.ReasonStorageShare.String() {
			t.Fatalf("a forecast recorded a live wait: %+v", row)
		}
	}
}

// Spec 3.4: the snapshot counts forecast addresses the real sets already
// hold. A manual timed block of a forecast address is not counted twice,
// an untimed one leaves the temporary set, and neither refunds the
// forecast's charge.
func TestOwnerForecastCountsRealBlocksOfForecastAddresses(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	blocks.temp, blocks.limit = 8, 10
	blocks.liveTemp, blocks.livePerm = map[string]bool{}, map[string]bool{}
	o, _, _ := policyOwner(t, f, blocks, dryPolicy(1))
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.11")
	turn(t, o)
	blocks.set(func(b *fakeBlocks) { b.temp, b.liveTemp["192.0.2.10"] = 9, true })
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.12")
	turn(t, o)
	if fc := forecastOf(t, o); fc.picks[predictCapacityAdmit] != 2 || fc.picks[predictSetFull] != 1 || fc.ceiling.General.Used+fc.ceiling.Reserved.Used != 2 {
		t.Fatalf("forecast after a manual timed block = %+v", fc)
	}
	blocks.set(func(b *fakeBlocks) { b.livePerm["192.0.2.11"] = true })
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.13")
	turn(t, o)
	if fc := forecastOf(t, o); fc.picks[predictCapacityAdmit] != 3 || fc.ceiling.General.Used+fc.ceiling.Reserved.Used != 3 {
		t.Fatalf("forecast after a manual untimed block = %+v", fc)
	}
}

func dryVerdictPolicy(epoch uint64, panel *fakePanel) ExecutionPolicy {
	p := verdictPolicy(epoch, panel)
	p.DryRun = true
	return p
}

// D8, spec 3.3 step 6: a dry run asks the panel about each pick the model
// would otherwise judge, and the pick waits for its answer with no
// forecast change. Block, an empty verdict or a failed exchange continues
// the forecast, which consumes the answer.
func TestOwnerForecastAsksThePanel(t *testing.T) {
	for name, answer := range map[string]func(string) (verdict.Response, error){
		"block": func(string) (verdict.Response, error) { return verdict.Response{Verdict: "block"}, nil },
		"empty": func(string) (verdict.Response, error) { return verdict.Response{}, nil },
		"error": func(string) (verdict.Response, error) {
			return unconfiguredClient.Ask(context.Background(), verdict.Request{})
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			panel := newFakePanel("")
			panel.answer = answer
			o, _, _ := policyOwner(t, f, blocks, dryVerdictPolicy(1, panel))
			id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
			turn(t, o)
			if c := candidate(t, o, id); c.State != admission.StateQueued || c.Reason != 0 || c.Attempts != 0 {
				t.Fatalf("asked pick = %+v", c)
			}
			if fc := forecastOf(t, o); len(fc.entries) != 0 || fc.picks != ([predictionEnd]uint64{}) {
				t.Fatalf("a pending pick changed the forecast: %+v", fc)
			}
			readyAnswers(t, o, 1)
			turn(t, o)
			if c := candidate(t, o, id); c.State != admission.StateDryRun || c.Attempts != 0 {
				t.Fatalf("answered pick = %+v", c)
			}
			if fc := forecastOf(t, o); fc.picks[predictCapacityAdmit] != 1 || len(fc.entries) != 1 {
				t.Fatalf("forecast = %+v", fc)
			}
			if s := verdictState(t, o); s.Asked != 1 || s.Ready != 0 || s.Pending != 0 {
				t.Fatalf("verdict status = %+v", s)
			}
			if _, applies := blocks.calls(); len(applies) != 0 || liveUsed(t, o) != 0 {
				t.Fatalf("a dry run applied %v", applies)
			}
		})
	}
}

// D5, spec 3.3 step 3, 4.1: a ready allow ends its pick as verdict_allow
// before any modelled capacity is judged, so it takes no forecast slot or
// charge, even once the set is full. Ready block answers then meet the
// model in order: a decision committed earlier in the turn fills the set
// for the next.
func TestOwnerForecastEndsPanelAllowsFirst(t *testing.T) {
	for name, temp := range map[string]int{"room": 9, "full": 10} {
		t.Run(name, func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			blocks.temp, blocks.limit = 8, 10
			panel := newFakePanel("block")
			panel.answer = func(ip string) (verdict.Response, error) {
				if ip == "192.0.2.10" {
					return verdict.Response{Verdict: "allow"}, nil
				}
				return verdict.Response{Verdict: "block"}, nil
			}
			o, _, _ := policyOwner(t, f, blocks, dryVerdictPolicy(1, panel))
			allowed, _ := queuedAt(t, o, p, f.host, admission.SeverityCritical, "192.0.2.10")
			queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.11")
			queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.12")
			turn(t, o)
			readyAnswers(t, o, 3)
			blocks.set(func(b *fakeBlocks) { b.temp = temp })
			turn(t, o)
			if c := candidate(t, o, allowed); c.State != admission.StateRefused || c.Reason != admission.ReasonVerdictAllow || c.Attempts != 0 {
				t.Fatalf("allowed pick = %+v", c)
			}
			fc := forecastOf(t, o)
			want := [predictionEnd]uint64{}
			want[predictCapacityAdmit], want[predictSetFull] = 1, 1
			if temp == 10 {
				want[predictCapacityAdmit], want[predictSetFull] = 0, 2
			}
			if fc.picks != want || uint64(len(fc.entries)) != want[predictCapacityAdmit] || uint64(fc.ceiling.General.Used+fc.ceiling.Reserved.Used) != want[predictCapacityAdmit] {
				t.Fatalf("forecast = %+v, want picks %v", fc, want)
			}
			if s := verdictState(t, o); s.AllowEndings != 1 || s.Asked != 3 || s.Ready != 0 {
				t.Fatalf("verdict status = %+v", s)
			}
			if len(queuedCandidates(t, o)) != 0 || liveUsed(t, o) != 0 {
				t.Fatal("picks left queued or the live ceiling was charged")
			}
		})
	}
}

// Spec 3.2, 3.3: a pick waiting for its answer is passed over and takes no
// forecast slot, so later picks with answers fit before it.
func TestOwnerForecastPendingPicksTakeNoSlot(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	blocks.temp, blocks.limit = 8, 10
	gate := make(chan struct{})
	panel := newFakePanel("block")
	panel.answer = func(ip string) (verdict.Response, error) {
		if ip == "192.0.2.10" {
			<-gate
		}
		return verdict.Response{Verdict: "block"}, nil
	}
	o, _, _ := policyOwner(t, f, blocks, dryVerdictPolicy(1, panel))
	t.Cleanup(func() {
		select {
		case <-gate:
		default:
			close(gate)
		}
	})
	waiting, _ := queuedAt(t, o, p, f.host, admission.SeverityCritical, "192.0.2.10")
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.11")
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.12")
	turn(t, o)
	readyAnswers(t, o, 2)
	turn(t, o)
	if c := candidate(t, o, waiting); c.State != admission.StateQueued || c.Reason != 0 {
		t.Fatalf("pending pick = %+v", c)
	}
	if fc := forecastOf(t, o); fc.picks[predictCapacityAdmit] != 2 || fc.picks[predictSetFull] != 0 {
		t.Fatalf("forecast = %+v", fc)
	}
	close(gate)
	readyAnswers(t, o, 1)
	turn(t, o)
	if fc := forecastOf(t, o); fc.picks[predictSetFull] != 1 || len(queuedCandidates(t, o)) != 0 {
		t.Fatalf("forecast after the answer = %+v", fc)
	}
}

// Spec 3.3 steps 1-5: a real block that covers the address, a forecast
// block that holds it, a full modelled set and a kind without a model end
// without a call.
func TestOwnerForecastAsksNothingItNeedNotAsk(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	blocks.refuse["192.0.2.11"] = firewall.BlockRefusedExisting
	panel := newFakePanel("block")
	o, _, _ := policyOwner(t, f, blocks, dryVerdictPolicy(1, panel))
	observe(t, o, p, f, "192.0.2.10", "offset=1")
	turn(t, o)
	readyAnswers(t, o, 1)
	turn(t, o)
	f.host.advance(time.Second)
	observe(t, o, p, f, "192.0.2.10", "offset=2")
	observe(t, o, p, f, "192.0.2.11", "offset=1")
	queuedKind(t, o, p, f.host, admission.SeverityHigh, "192.0.2.12", admission.KindPromote)
	turn(t, o)
	blocks.set(func(b *fakeBlocks) { b.temp, b.limit = 4, 4 })
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.13")
	turn(t, o)
	fc := forecastOf(t, o)
	// The repeat asks a day from a second later: the forecast block holds it.
	if fc.picks[predictCapacityAdmit] != 1 || fc.picks[predictPendingRecovery] != 1 || fc.picks[predictExistingActual] != 1 || fc.picks[predictNotModelled] != 1 || fc.picks[predictSetFull] != 1 {
		t.Fatalf("forecast = %+v", fc)
	}
	if asked, _, _, _ := panel.state(); len(asked) != 1 || len(queuedCandidates(t, o)) != 0 {
		t.Fatalf("asked %v", asked)
	}
}

// Spec 3.7: no answer from a dry run authorizes a live attempt. A live
// epoch drops it, and the pick asks again before it runs.
func TestOwnerForecastAnswersDoNotCarryIntoLive(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	panel := newFakePanel("allow")
	o, r, _ := policyOwner(t, f, blocks, dryVerdictPolicy(1, panel))
	id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	turn(t, o)
	readyAnswers(t, o, 1)
	panel.set(func(p *fakePanel) {
		p.answer = func(string) (verdict.Response, error) { return verdict.Response{Verdict: "block"}, nil }
	})
	r.publish(verdictPolicy(2, panel))
	if err := o.Reload(); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the dry-run stage to retire", func() bool { return !verdictState(t, o).StageRetiring })
	turn(t, o)
	if c := candidate(t, o, id); c.State != admission.StateQueued || c.Reason != 0 {
		t.Fatalf("a dry-run allow ended a live pick: %+v", c)
	}
	readyAnswers(t, o, 1)
	turn(t, o)
	if c := candidate(t, o, id); c.State != admission.StateVerified {
		t.Fatalf("live pick = %+v", c)
	}
	if asked, _, _, _ := panel.state(); len(asked) != 2 {
		t.Fatalf("asked %v", asked)
	}
}

// Spec 3.7, 6.4: a flip to dry run first finishes the live outcome a
// failed write left pending, without a refund or a second dispatch, and
// the forecast then starts from the ceiling that includes its charge. An
// unknown attempt from live work is still retired once its expiry passes,
// a bookkeeping write about earlier real work, not a new effect.
func TestOwnerFinishesLiveWorkAfterAFlipToDryRun(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	blocks.results["192.0.2.11"] = firewall.BlockResult{Effect: firewall.BlockUnknown}
	o, r, mono := policyOwner(t, f, blocks, validPolicy(1))
	failed := false
	finish := finishLedger
	setOwnerHook(t, o, &finishLedger, func(l *store.AdmissionLedger, id admission.ActionID, d admission.Disposition) (admission.Candidate, admission.AttemptRecord, error) {
		if d == admission.DispositionApplied && !failed {
			failed = true
			return admission.Candidate{}, admission.AttemptRecord{}, errors.New("disk full")
		}
		return finish(l, id, d)
	})
	applied, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	unknown, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.11")
	if err := o.do(o.turn); err == nil {
		t.Fatal("a failed outcome write did not fail the turn")
	}
	if c := candidate(t, o, applied); c.State != admission.StateExecuting {
		t.Fatalf("pending outcome = %+v", c)
	}
	r.publish(dryPolicy(2))
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.12")
	turn(t, o)
	if c := candidate(t, o, applied); c.State != admission.StateVerified || c.Attempts != 1 {
		t.Fatalf("live outcome after the flip = %+v", c)
	}
	_, applies := blocks.calls()
	if len(applies) != 1 || liveUsed(t, o) != 2 {
		t.Fatalf("%d applies, live used %d after the flip", len(applies), liveUsed(t, o))
	}
	fc := forecastOf(t, o)
	if fc.reset != resetModeChange || fc.picks[predictCapacityAdmit] != 1 || fc.ceiling.General.Used+fc.ceiling.Reserved.Used != 3 {
		t.Fatalf("forecast = %+v", fc)
	}
	c := candidate(t, o, unknown)
	// Retirement waits for the attempt's audit rows to be delivered.
	if err := o.do(o.deliverAudit); err != nil {
		t.Fatal(err)
	}
	mono.advance(25 * time.Hour)
	f.host.advance(25 * time.Hour)
	turn(t, o)
	if a := attemptOf(t, o, c); !a.Retired || len(blocks.retireCalls()) != 1 {
		t.Fatalf("unknown attempt in a dry run = %+v, %d retirement calls", a, len(blocks.retireCalls()))
	}
	if _, applies = blocks.calls(); len(applies) != 1 || blocks.marks != 0 {
		t.Fatalf("a dry run dispatched or repaired: %d applies, %d marks", len(applies), blocks.marks)
	}
}

// Spec 1.2, 3.7: a forecast neither probes nor repairs an engine a live
// hold names, so the hold's probe deadline does not run a turn every
// second while the dry run lasts; the hold stays for the next live turn.
func TestOwnerForecastLeavesALiveHoldAlone(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	blocks.results["192.0.2.10"] = firewall.BlockResult{Effect: firewall.BlockUnknown, Err: fmt.Errorf("%w: no space left on device", firewall.ErrBlockBatchState)}
	o, r, mono := policyOwner(t, f, blocks, validPolicy(1))
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	turn(t, o)
	if executionHeld(t, o) == "" {
		t.Fatal("fixture: no execution hold")
	}
	r.publish(dryPolicy(2))
	if err := o.Reload(); err != nil {
		t.Fatal(err)
	}
	selections := 0
	preview := previewLedger
	setOwnerHook(t, o, &previewLedger, func(l *store.AdmissionLedger, answers map[admission.CandidateID]admission.Answer) ([]admission.Pick, error) {
		selections++
		return preview(l, answers)
	})
	if err := o.do(func() error { o.schedule(); return o.scheduleErr }); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		mono.advance(maxProbeWait)
		if err := o.do(func() error { o.schedule(); return o.scheduleErr }); err != nil {
			t.Fatal(err)
		}
	}
	if selections != 1 || blocks.marks != 0 || blocks.stateProbes != 0 || executionHeld(t, o) == "" {
		t.Fatalf("%d forecast turns, %d repairs, %d probes, held %q", selections, blocks.marks, blocks.stateProbes, executionHeld(t, o))
	}
}
