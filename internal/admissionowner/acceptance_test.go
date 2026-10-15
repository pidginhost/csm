package admissionowner

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/store"
	"github.com/pidginhost/csm/internal/verdict"
)

// commitRun is what the commit scenario leaves once every pick has ended.
type commitRun struct {
	States   map[string]string
	Picks    [admission.PredictionSlots]uint64
	Entries  []string
	Charged  uint32
	Summary  [admission.PredictionSlots]uint64
	Named    []string
	Examples []string
	Counts   map[string]uint64
	DryRuns  uint64
	Asked    []string
	Endings  uint64
	Logged   int
}

// runCommitScenario forecasts six picks over two turns under a dry-run
// policy that asks the panel: two fit the model, one is protected, one the
// panel allows, a real block already covers one and a promotion has no
// model. The call'th write through hook ("end" or "terminate") fails once,
// and the turn it stops runs again. The panel answers only after the first
// turn, retried or not, so its answers meet the second.
func runCommitScenario(t *testing.T, hook string, call int) commitRun {
	t.Helper()
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	blocks.refuse["192.0.2.11"] = firewall.BlockRefusedProtected
	blocks.refuse["192.0.2.13"] = firewall.BlockRefusedExisting
	panel := newFakePanel("block")
	release := make(chan struct{})
	panel.hold = release
	panel.answer = func(ip string) (verdict.Response, error) {
		if ip == "192.0.2.12" {
			return verdict.Response{Verdict: "allow"}, nil
		}
		return verdict.Response{Verdict: "block"}, nil
	}
	o, _, _ := policyOwner(t, f, blocks, dryVerdictPolicy(1, panel))
	w := watchExamples(t, o)
	logged := 0
	setOwnerHook(t, o, &logVerdictAllow, func(admission.CandidateID, string, verdictResult) { logged++ })
	names := map[admission.CandidateID]string{}
	for _, addr := range []string{"192.0.2.10", "192.0.2.11", "192.0.2.12", "192.0.2.13", "2001:db8::10"} {
		id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, addr)
		names[id] = addr
	}
	promote, _ := queuedKind(t, o, p, f.host, admission.SeverityHigh, "192.0.2.14", admission.KindPromote)
	names[promote] = "promote 192.0.2.14"

	fail := errors.New("disk full")
	calls := 0
	var committed uint64
	var failed admission.CandidateID
	failing := func(name string, id admission.CandidateID) bool {
		if name != hook {
			return false
		}
		calls++
		if calls != call {
			return false
		}
		failed = id
		return true
	}
	end := endDryRunLedger
	setOwnerHook(t, o, &endDryRunLedger, func(l *store.AdmissionLedger, id admission.CandidateID) (admission.Candidate, bool, error) {
		if failing("end", id) {
			return admission.Candidate{}, false, fail
		}
		c, changed, err := end(l, id)
		if changed {
			committed++
		}
		return c, changed, err
	})
	terminate := terminateLedger
	setOwnerHook(t, o, &terminateLedger, func(l *store.AdmissionLedger, id admission.CandidateID, r admission.Reason) (admission.Candidate, error) {
		if failing("terminate", id) {
			return admission.Candidate{}, fail
		}
		return terminate(l, id, r)
	})
	// step runs a turn. A turn the injected failure stops leaves its pick
	// queued and has installed only the endings that committed before it;
	// it then runs again.
	step := func() {
		t.Helper()
		before := failed
		err := o.do(o.turn)
		if failed == before {
			if err != nil {
				t.Fatal(err)
			}
			return
		}
		if !errors.Is(err, fail) {
			t.Fatalf("turn after a failed %s write = %v", hook, err)
		}
		if c := candidate(t, o, failed); c.State != admission.StateQueued || c.Reason != 0 || c.Attempts != 0 {
			t.Fatalf("the failed pick %s changed: %+v", names[failed], c)
		}
		var installed uint64
		for _, n := range forecastOf(t, o).picks {
			installed += n
		}
		if installed != committed {
			t.Fatalf("the forecast holds %d predictions for %d committed endings", installed, committed)
		}
		turn(t, o)
	}
	step()
	close(release)
	readyAnswers(t, o, 3)
	step()
	if call != 0 && failed == "" {
		t.Fatalf("the %s write was not reached %d times", hook, call)
	}

	run := commitRun{States: map[string]string{}, Counts: map[string]uint64{}}
	for id, name := range names {
		c := candidate(t, o, id)
		run.States[name] = c.State.String()
		if c.Reason != 0 {
			run.States[name] += " " + c.Reason.String()
		}
	}
	fc := forecastOf(t, o)
	run.Picks, run.Entries = fc.picks, slices.Sorted(maps.Keys(fc.entries))
	run.Charged = fc.ceiling.General.Used + fc.ceiling.Reserved.Used
	if err := o.do(func() error {
		s := o.summary.pending
		if s == nil {
			return errors.New("no summary is pending")
		}
		run.Summary = s.counts
		for _, e := range s.examples {
			run.Named = append(run.Named, e.target)
		}
		o.compare.mu.Lock()
		defer o.compare.mu.Unlock()
		for k, n := range o.compare.counts {
			run.Counts[k.kind.String()+" "+k.decision+" "+k.prediction.String()] += n
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	slices.Sort(run.Named)
	for _, batch := range w.written() {
		for _, b := range batch {
			run.Examples = append(run.Examples, names[b.Candidate])
		}
	}
	slices.Sort(run.Examples)
	run.DryRuns = outcomes(ledgerStatus(t, o), admission.DispositionDryRun)
	run.Asked, _, _, _ = panel.state()
	slices.Sort(run.Asked)
	run.Endings, run.Logged = verdictState(t, o).AllowEndings, logged

	checks, applies := blocks.calls()
	blocks.set(func(b *fakeBlocks) {
		if len(checks) != 0 || len(applies) != 0 || b.marks != 0 || b.stateProbes != 0 || len(b.retires) != 0 {
			t.Errorf("engine reached: %d checks, %d applies, %d marks, %d probes, %d retirements", len(checks), len(applies), b.marks, b.stateProbes, len(b.retires))
		}
	})
	if used := liveUsed(t, o); used != 0 || len(pendingAudit(t, o)) != 0 {
		t.Fatalf("a dry run charged %d live units or wrote audit rows", used)
	}
	return run
}

// Spec 3.5, 4.2, 6.1: a write that fails at any commit point of a dry-run
// turn stops the turn with that pick queued and installs nothing for it.
// Retrying the turn ends every pick exactly once: the forecast, its
// summary, examples and comparison counts, the durable outcomes and the
// allow endings and logs match a run without the failure. The panel is
// asked once per pick and the engine is only read.
func TestOwnerForecastCountsOnceAcrossFailedCommits(t *testing.T) {
	want := commitRun{
		States: map[string]string{
			"192.0.2.10": "dry_run", "192.0.2.11": "refused protected", "192.0.2.12": "refused verdict_allow",
			"192.0.2.13": "dry_run", "2001:db8::10": "dry_run", "promote 192.0.2.14": "dry_run",
		},
		Entries: []string{"192.0.2.10", "2001:db8::10"}, Charged: 2,
		Named: []string{"192.0.2.10", "2001:db8::10"}, Examples: []string{"192.0.2.10", "2001:db8::10"},
		Counts:  map[string]uint64{"block_ip dry_run capacity_admit": 2, "block_ip dry_run existing_actual": 1, "promote dry_run not_modelled": 1},
		DryRuns: 4, Asked: []string{"192.0.2.10", "192.0.2.12", "2001:db8::10"}, Endings: 1, Logged: 1,
	}
	want.Picks[admission.PredictCapacityAdmit], want.Picks[admission.PredictExistingActual], want.Picks[admission.PredictNotModelled] = 2, 1, 1
	want.Summary = want.Picks
	for _, tc := range []struct {
		hook string
		call int
	}{{"", 0}, {"end", 1}, {"end", 2}, {"end", 3}, {"end", 4}, {"terminate", 1}, {"terminate", 2}} {
		name := "no failure"
		if tc.hook != "" {
			name = fmt.Sprintf("%s %d", tc.hook, tc.call)
		}
		t.Run(name, func(t *testing.T) {
			if got := runCommitScenario(t, tc.hook, tc.call); !reflect.DeepEqual(got, want) {
				t.Fatalf("after the run:\n got %+v\nwant %+v", got, want)
			}
		})
	}
}

// Spec 3.6, 3.8: a forecast session that cannot be named holds the
// forecast. Its picks stay queued; nothing is asked, read from the engine
// or written as an example, and no earlier session is resumed: after a
// live epoch ended the first session, the next starts only with a fresh ID.
func TestOwnerSessionIDFailureHoldsTheForecast(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	panel := newFakePanel("block")
	o, r, _ := policyOwner(t, f, blocks, dryVerdictPolicy(1, panel))
	w := watchExamples(t, o)
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	turn(t, o)
	readyAnswers(t, o, 1)
	turn(t, o)
	first := forecastOf(t, o)
	if first == nil || first.picks[admission.PredictCapacityAdmit] != 1 {
		t.Fatalf("fixture: first session = %+v", first)
	}
	r.publish(verdictPolicy(2, panel))
	turn(t, o)
	if fc := forecastOf(t, o); fc != nil {
		t.Fatalf("a live epoch kept the session: %+v", fc)
	}
	r.publish(dryVerdictPolicy(3, panel))
	setOwnerHook(t, o, &sessionRand, io.Reader(strings.NewReader("short")))
	id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.11")
	var snapshots int
	blocks.set(func(b *fakeBlocks) { snapshots = len(b.snapshots) })
	batches := len(w.written())
	for range 2 {
		if err := o.do(o.turn); err == nil {
			t.Fatal("a forecast ran without a session ID")
		}
	}
	if c := candidate(t, o, id); c.State != admission.StateQueued || c.Reason != 0 || c.Attempts != 0 {
		t.Fatalf("held pick = %+v", c)
	}
	if fc := forecastOf(t, o); fc != nil {
		t.Fatalf("an unnamed session runs: %+v", fc)
	}
	blocks.set(func(b *fakeBlocks) {
		if len(b.snapshots) != snapshots {
			t.Errorf("an unnamed session read the engine %d times", len(b.snapshots)-snapshots)
		}
	})
	if asked, _, _, _ := panel.state(); len(asked) != 1 || len(w.written()) != batches {
		t.Fatalf("an unnamed session asked %v or wrote %d example batches", asked, len(w.written())-batches)
	}
	if d := dryRunState(t, o); forecastErrorOf(d) != "session_id_unavailable" {
		t.Fatalf("status = %+v", d)
	}
	setOwnerHook(t, o, &sessionRand, io.Reader(strings.NewReader(strings.Repeat("b", 16))))
	eventually(t, "the old stage to retire", func() bool { return !verdictState(t, o).StageRetiring })
	turn(t, o)
	readyAnswers(t, o, 1)
	turn(t, o)
	fc := forecastOf(t, o)
	if fc == nil || fc.id == first.id || fc.id != strings.Repeat("62", 16) || fc.reset != resetModeChange || fc.picks[admission.PredictCapacityAdmit] != 1 {
		t.Fatalf("session after the failure = %+v, first %s", fc, first.id)
	}
	written := w.written()
	if last := written[len(written)-1]; len(last) != 1 || last[0].Session != fc.id || last[0].Candidate != id {
		t.Fatalf("example after the failure = %+v", last)
	}
}

// Spec 2, 3.7: a dry-run publication while a live batch is applied cannot
// undo it. The turn finishes the batch's real outcomes under the live
// policy and the reload waits for it; the next turn forecasts its pick
// without reaching the engine again, from the ceiling that holds the
// batch's charges.
func TestOwnerFinishesADispatchedBatchAcrossAFlipToDryRun(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	reached, release := make(chan struct{}), make(chan struct{})
	var released sync.Once
	unblock := func() { released.Do(func() { close(release) }) }
	defer unblock()
	blocks.afterApply = func(*fakeBlocks) {
		close(reached)
		<-release
	}
	o, r, mono := policyOwner(t, f, blocks, validPolicy(1))
	v4, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	v6, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "2001:db8::10")
	turned := make(chan error, 1)
	go func() { turned <- o.do(o.turn) }()
	select {
	case <-reached:
	case <-time.After(5 * time.Second):
		t.Fatal("the live batch never reached the engine")
	}
	r.publish(dryPolicy(2))
	reloaded := make(chan error, 1)
	reloading := make(chan struct{})
	go func() { close(reloading); reloaded <- o.Reload() }()
	<-reloading
	select {
	case err := <-reloaded:
		t.Fatalf("reload acknowledged while a live batch ran: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	unblock()
	for name, done := range map[string]<-chan error{"turn": turned, "reload": reloaded} {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s did not finish after the batch was released", name)
		}
	}
	blocks.set(func(b *fakeBlocks) { b.afterApply = nil })
	for _, id := range []admission.CandidateID{v4, v6} {
		if c := candidate(t, o, id); c.State != admission.StateVerified || c.Attempts != 1 {
			t.Fatalf("dispatched pick after the flip = %+v", c)
		}
	}
	if used := liveUsed(t, o); used != 2 {
		t.Fatalf("live used %d after the dispatched batch", used)
	}
	checks, applies := blocks.calls()
	dry, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.11")
	mono.advance(batchEvery)
	turn(t, o)
	if c := candidate(t, o, dry); c.State != admission.StateDryRun || c.Attempts != 0 {
		t.Fatalf("pick after the flip = %+v", c)
	}
	afterChecks, afterApplies := blocks.calls()
	if len(afterChecks) != len(checks) || len(afterApplies) != 1 || len(applies) != 1 || liveUsed(t, o) != 2 {
		t.Fatalf("the dry run reached the engine: %d checks, %d applies, live used %d", len(afterChecks)-len(checks), len(afterApplies), liveUsed(t, o))
	}
	fc := forecastOf(t, o)
	if fc == nil || fc.reset != resetModeChange || fc.picks[admission.PredictCapacityAdmit] != 1 || fc.ceiling.General.Used+fc.ceiling.Reserved.Used != 3 {
		t.Fatalf("forecast = %+v", fc)
	}
}

// Spec 4.3, 4.4: Stop while a dry run waits on the panel cancels the four
// running calls and the queued jobs, and counts each once: a running call
// is asked and cancelled, a queued job discarded unasked; none is an
// answer. The picks stay queued with no forecast change, and a restarted
// owner asks about each again in a new session.
func TestOwnerStopDuringDryRunCallsKeepsCounts(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	panel := newFakePanel("block")
	panel.hold = make(chan struct{})
	r := &policyReader{p: dryVerdictPolicy(1, panel)}
	opts := executeOptions(f, blocks)
	opts.Policy = r.read
	o := f.start(opts)
	heldMono(t, o)
	ids := queueMany(t, o, p, f, 8, 1)
	turn(t, o)
	eventually(t, "four calls", func() bool { _, active, _, _ := panel.state(); return active == verdictWorkers })
	before := forecastOf(t, o)
	o.Stop()
	s := o.Status().Owner.Verdict
	if s.Asked != verdictWorkers || s.Cancelled != verdictWorkers || s.Discarded != uint64(len(ids)-verdictWorkers) ||
		s.InFlight != 0 || s.Pending != 0 || s.Ready != 0 || s.ResponsesAllow+s.ResponsesDefault+s.Failed != 0 {
		t.Fatalf("counters after stop = %+v", s)
	}
	if len(before.entries) != 0 || before.picks != ([admission.PredictionSlots]uint64{}) {
		t.Fatalf("waiting picks changed the forecast: %+v", before)
	}
	panel.set(func(p *fakePanel) { p.hold = nil })
	o = f.start(opts)
	heldMono(t, o)
	for _, id := range ids {
		if c := candidate(t, o, id); c.State != admission.StateQueued || c.Reason != 0 || c.Attempts != 0 {
			t.Fatalf("a cancelled call ended its pick: %+v", c)
		}
	}
	if n := outcomes(ledgerStatus(t, o), admission.DispositionDryRun); n != 0 {
		t.Fatalf("%d dry-run endings from cancelled calls", n)
	}
	turn(t, o)
	readyAnswers(t, o, len(ids))
	turn(t, o)
	fc := forecastOf(t, o)
	if fc == nil || fc.id == before.id || fc.reset != resetStartup || fc.picks[admission.PredictCapacityAdmit] != uint64(len(ids)) {
		t.Fatalf("forecast after the restart = %+v", fc)
	}
	if asked, _, _, _ := panel.state(); len(asked) != verdictWorkers+len(ids) {
		t.Fatalf("asked %d times", len(asked))
	}
	if _, applies := blocks.calls(); len(applies) != 0 {
		t.Fatalf("a dry run applied %v", applies)
	}
}

// Spec 4.3, 6.3: sweeping a full stage again and again, as its picks age
// out while the panel hangs, keeps it at 64 jobs and adds no goroutine.
// Each job counts once: every call a worker started is asked and
// cancelled, every other job is discarded unasked.
func TestOwnerBoundsRepeatedCancellations(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	panel := newFakePanel("block")
	panel.hold = make(chan struct{})
	o, _, _ := policyOwner(t, f, blocks, dryVerdictPolicy(1, panel))
	settled := 0
	for round := range 3 {
		queueMany(t, o, p, f, verdictPending+8, round*0x100+1)
		turn(t, o)
		eventually(t, "four calls", func() bool { _, active, _, _ := panel.state(); return active == verdictWorkers })
		turn(t, o)
		if s := verdictState(t, o); s.Pending != verdictPending {
			t.Fatalf("round %d: %d jobs pending", round, s.Pending)
		}
		f.host.advance(admission.QueueAgeLimit + time.Minute)
		turn(t, o)
		eventually(t, "every swept completion", func() bool { return verdictState(t, o).Pending == 0 })
		jobs := uint64(verdictPending * (round + 1))
		s := verdictState(t, o)
		if s.Asked != s.Cancelled || s.Asked+s.Discarded != jobs || s.Asked < uint64(verdictWorkers*(round+1)) ||
			s.InFlight != 0 || s.Ready != 0 || s.ResponsesAllow+s.ResponsesDefault+s.Failed != 0 {
			t.Fatalf("round %d: counters %+v for %d jobs", round, s, jobs)
		}
		if round == 0 {
			settled = runtime.NumGoroutine()
			continue
		}
		eventually(t, "the goroutines to settle", func() bool { return runtime.NumGoroutine() <= settled })
	}
	if fc := forecastOf(t, o); len(fc.entries) != 0 || fc.picks != ([admission.PredictionSlots]uint64{}) {
		t.Fatalf("swept work changed the forecast: %+v", fc)
	}
}
