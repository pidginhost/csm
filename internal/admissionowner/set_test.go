package admissionowner

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/health"
)

// ownerSet is the set status as the owner reads it now.
func ownerSet(t *testing.T, o *Owner) (*health.AdmissionSet, string) {
	t.Helper()
	s := o.status()
	if s == nil || s.Owner == nil {
		t.Fatal("no owner status")
	}
	return s.Owner.Set, s.Owner.SetError
}

// An executing owner budgets block work by the set the turn reads: work
// with no free slot in its partition waits as set_full without reaching
// the engine's check, and a raised limit lets it run into its slot.
func TestOwnerBudgetsBlockWorkByTheSet(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	// Two slots, one held by an operator block: only the reserve is left.
	blocks.limit, blocks.temp = 2, 1
	o := f.start(executeOptions(f, blocks))
	id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	turn(t, o)
	if c := candidate(t, o, id); c.State != admission.StateQueued || c.Reason != admission.ReasonSetFull || c.Attempts != 0 {
		t.Fatalf("general work into the reserve = %+v", c)
	}
	if checks, applies := blocks.calls(); len(checks) != 0 || len(applies) != 0 || blocks.setReads != 1 {
		t.Fatalf("engine calls: %d checks, %d applies, %d set reads", len(checks), len(applies), blocks.setReads)
	}
	want := &health.AdmissionSet{Limit: 2, Capacity: 2, Unclaimed: 1,
		General: health.AdmissionDryRunPartition{}, Reserved: health.AdmissionDryRunPartition{Size: 1, Free: 1}}
	if set, setErr := ownerSet(t, o); set == nil || *set != *want || setErr != "" {
		t.Fatalf("set status %+v %q, want %+v", set, setErr, want)
	}
	blocks.set(func(b *fakeBlocks) { b.limit = 3 })
	turn(t, o)
	if c := candidate(t, o, id); c.State != admission.StateVerified {
		t.Fatalf("after a raised limit = %+v", c)
	}
	want = &health.AdmissionSet{Limit: 3, Capacity: 3, Unclaimed: 1,
		General: health.AdmissionDryRunPartition{Size: 1, Used: 1}, Reserved: health.AdmissionDryRunPartition{Size: 1, Free: 1}}
	if set, _ := ownerSet(t, o); set == nil || *set != *want {
		t.Fatalf("set status %+v, want the verified block in its slot %+v", set, want)
	}
}

// A preview owner budgets its previews by the same set, read once a turn
// without asking anything else of the engine: work the set cannot take
// waits as set_full instead of being previewed.
func TestOwnerPreviewsBlockWorkWithinTheSet(t *testing.T) {
	withLiveExecution(t, false)
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	// Three slots: an operator block leaves two, and a legacy automatic
	// block holds the only general one.
	blocks.limit, blocks.temp, blocks.imported = 3, 2, 1
	o := f.start(executeOptions(f, blocks))
	id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	turn(t, o)
	if c := candidate(t, o, id); c.State != admission.StateQueued || c.Reason != admission.ReasonSetFull {
		t.Fatalf("preview into a full set = %+v", c)
	}
	want := &health.AdmissionSet{Limit: 3, Capacity: 3, Unclaimed: 1, Imported: 1,
		General: health.AdmissionDryRunPartition{Size: 1, Used: 1}, Reserved: health.AdmissionDryRunPartition{Size: 1, Free: 1}}
	if set, _ := ownerSet(t, o); set == nil || *set != *want {
		t.Fatalf("set status %+v, want %+v", set, want)
	}
	blocks.set(func(b *fakeBlocks) { b.limit = 4 })
	turn(t, o)
	if c := candidate(t, o, id); c.State != admission.StateObserved {
		t.Fatalf("preview after a raised limit = %+v", c)
	}
	checks, applies := blocks.calls()
	if len(checks) != 0 || len(applies) != 0 || len(blocks.snapshots) != 0 || blocks.setReads != 2 || blocks.marks != 0 || blocks.stateProbes != 0 || len(blocks.retireCalls()) != 0 {
		t.Fatalf("engine calls: %d checks, %d applies, %d snapshots, %d set reads", len(checks), len(applies), len(blocks.snapshots), blocks.setReads)
	}
}

// The set is read only for queued work that takes a slot: not on an idle
// turn, for a challenge, or for a retry still in its backoff.
func TestOwnerReadsTheSetOnlyForSlotWork(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	blocks.results["192.0.2.10"] = firewall.BlockResult{Effect: firewall.BlockFailed}
	o := f.start(executeOptions(f, blocks))
	turn(t, o)
	queuedKind(t, o, p, f.host, admission.SeverityHigh, "192.0.2.20", admission.KindChallenge)
	turn(t, o)
	if blocks.setReads != 0 {
		t.Fatalf("%d set reads without block work", blocks.setReads)
	}
	if set, _ := ownerSet(t, o); set != nil {
		t.Fatalf("set status without a read: %+v", set)
	}
	id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	turn(t, o)
	if c := candidate(t, o, id); c.State != admission.StateQueued || c.Attempts != 1 || blocks.setReads != 1 {
		t.Fatalf("failed block %+v after %d set reads", c, blocks.setReads)
	}
	turn(t, o)
	if blocks.setReads != 1 {
		t.Fatalf("a retry in its backoff read the set: %d reads", blocks.setReads)
	}
}

type advancingSetEngine struct {
	BlockEngine
	host *fakeHost
}

func (e advancingSetEngine) BlockAdmissionSnapshot(members []firewall.BlockMember, shadow []string) (firewall.BlockAdmission, error) {
	e.host.advance(time.Nanosecond)
	return e.BlockEngine.BlockAdmissionSnapshot(members, shadow)
}

// Time spent reading the engine cannot make a retry ready within the
// turn. At its exact deadline the next turn must read and enforce the set.
func TestOwnerSetReadKeepsTheCommittedAdmissionTime(t *testing.T) {
	withLiveExecution(t, false)
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	blocks.limit = 2
	opts := executeOptions(f, blocks)
	opts.Blocks = func() BlockEngine { return advancingSetEngine{BlockEngine: blocks, host: f.host} }
	o := f.start(opts)
	retry, now := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	if err := o.do(func() error {
		_, attempt, _, err := o.ledger.Reserve(retry, admission.LaneGeneral, now.Add(time.Hour))
		if err != nil {
			return err
		}
		_, _, err = o.ledger.Finish(attempt.Attempt.ID, admission.DispositionFailed)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	due := candidate(t, o, retry).NotBefore
	f.host.advance(admission.RetryBackoff(1) - time.Nanosecond)
	ready, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.11")
	turn(t, o)
	if c := candidate(t, o, ready); c.State != admission.StateObserved {
		t.Fatalf("ready work was not previewed: %+v", c)
	}
	if c := candidate(t, o, retry); c.State != admission.StateQueued || c.Attempts != 1 || c.NotBefore != due {
		t.Fatalf("the set read advanced retry readiness: %+v", c)
	}
	if blocks.setReads != 1 || !f.host.now().Equal(due) {
		t.Fatalf("set reads = %d, wall time = %v, want one read reaching %v", blocks.setReads, f.host.now(), due)
	}
	if st := o.status(); !st.Owner.LastTick.Equal(due.Add(-time.Nanosecond)) {
		t.Fatalf("a tick ran between the set read and schedule: %v", st.Owner.LastTick)
	}
	blocks.set(func(b *fakeBlocks) { b.temp = b.limit })
	turn(t, o)
	if c := candidate(t, o, retry); c.State != admission.StateQueued || c.Attempts != 1 || c.Reason != admission.ReasonSetFull {
		t.Fatalf("retry at its deadline escaped the full set: %+v", c)
	}
	if blocks.setReads != 2 {
		t.Fatalf("retry at its exact deadline made %d set reads, want two total", blocks.setReads)
	}
	if checks, applies := blocks.calls(); len(checks) != 0 || len(applies) != 0 {
		t.Fatalf("preview reached the engine: %d checks, %d applies", len(checks), len(applies))
	}
}

// A set the turn could not read shows in status and leaves block work
// without a slot budget; the preview goes on.
func TestOwnerShowsAnUnreadableSet(t *testing.T) {
	withLiveExecution(t, false)
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	blocks.checkErr = errors.New("set dump failed")
	o := f.start(executeOptions(f, blocks))
	id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	turn(t, o)
	if c := candidate(t, o, id); c.State != admission.StateObserved {
		t.Fatalf("preview with an unreadable set = %+v", c)
	}
	if set, setErr := ownerSet(t, o); set != nil || setErr != "set dump failed" {
		t.Fatalf("set status %+v %q", set, setErr)
	}
	blocks.set(func(b *fakeBlocks) { b.checkErr = nil })
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.11")
	turn(t, o)
	if set, setErr := ownerSet(t, o); set == nil || setErr != "" {
		t.Fatalf("successful read kept a stale error: %+v %q", set, setErr)
	}
	turn(t, o)
	if set, setErr := ownerSet(t, o); set != nil || setErr != "" {
		t.Fatalf("idle scheduling turn kept the old set or error: %+v %q", set, setErr)
	}
}

// A forecast models its own set: a dry run drops the set a live turn read.
func TestOwnerForecastDropsTheLiveSet(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	blocks.limit, blocks.temp = 1, 1
	o, r, _ := policyOwner(t, f, blocks, validPolicy(1))
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	turn(t, o)
	if set, _ := ownerSet(t, o); set == nil {
		t.Fatal("no set status after a live turn")
	}
	r.publish(dryPolicy(2))
	if err := o.do(func() error { return o.runTurn(false) }); err != nil {
		t.Fatal(err)
	}
	if set, setErr := ownerSet(t, o); set != nil || setErr != "" {
		t.Fatalf("forecast kept the live set on a nonselecting turn: %+v %q", set, setErr)
	}
	turn(t, o)
	if set, setErr := ownerSet(t, o); set != nil || setErr != "" {
		t.Fatalf("forecast kept the live set: %+v %q", set, setErr)
	}
}

// Installing a dry-run policy must discard the live set and its read error
// even when no selection follows or the next clock reading fails.
func TestOwnerDryRunPolicyDropsTheSetBeforeATurn(t *testing.T) {
	for _, tc := range []struct {
		name        string
		reload      bool
		selecting   bool
		clockFailed bool
	}{
		{name: "reload", reload: true},
		{name: "reload with failed clock", reload: true, clockFailed: true},
		{name: "turn with failed clock", selecting: true, clockFailed: true},
		{name: "maintenance with failed clock", clockFailed: true},
	} {
		for _, unreadable := range []bool{false, true} {
			name := tc.name + "/snapshot"
			if unreadable {
				name = tc.name + "/read error"
			}
			t.Run(name, func(t *testing.T) {
				withLiveExecution(t, false)
				p := withTestRegistry(t)
				f := newOwnerFixture(t)
				blocks := newFakeBlocks()
				blocks.limit, blocks.temp = 1, 1
				if unreadable {
					blocks.checkErr = errors.New("set dump failed")
				}
				o, r, _ := policyOwner(t, f, blocks, validPolicy(1))
				queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
				turn(t, o)
				set, setErr := ownerSet(t, o)
				if unreadable && (set != nil || setErr != "set dump failed") || !unreadable && (set == nil || setErr != "") {
					t.Fatalf("initial set status = %+v %q", set, setErr)
				}
				reads := blocks.setReads
				r.publish(dryPolicy(2))
				var clockErr error
				if tc.clockFailed {
					clockErr = errors.New("clock unavailable")
					f.host.set(func(h *fakeHost) { h.clockErr = clockErr })
				}
				var err error
				if tc.reload {
					err = o.Reload()
				} else {
					err = o.do(func() error { return o.runTurn(tc.selecting) })
				}
				if !errors.Is(err, clockErr) {
					t.Fatalf("policy boundary error = %v, want %v", err, clockErr)
				}
				s := o.Status().Owner
				if s.DryRun == nil || !s.DryRun.Active || s.Set != nil || s.SetError != "" {
					t.Fatalf("dry-run policy retained live set status: %+v", s)
				}
				if blocks.setReads != reads {
					t.Fatalf("policy boundary read the set: %d reads, want %d", blocks.setReads, reads)
				}
			})
		}
	}
}

// Apply-time capacity rejection keeps the charged attempt and its chain's
// backoff. Once it ends, the slot budget waits without charging another attempt.
func TestOwnerSetFullAfterApplyKeepsTheRetryProof(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	blocks.limit = 2
	blocks.results["192.0.2.10"] = firewall.BlockResult{Effect: firewall.BlockFailed, Refusal: firewall.BlockRefusedFull}
	blocks.afterApply = func(b *fakeBlocks) { b.temp = b.limit }
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	before := candidate(t, o, id)
	turn(t, o)
	failed := candidate(t, o, id)
	a := attemptOf(t, o, failed)
	if failed.State != admission.StateQueued || failed.Attempts != 1 || a.State != admission.StateFailed || a.Disposition != admission.DispositionFailed ||
		a.Attempt.Seq != 1 || a.ExpiresAt != failed.ExpiresAt || a.Reserved.Before(before.FirstQueued) || !a.Reserved.Before(before.AgeOut) ||
		!failed.NotBefore.Equal(a.Finished.Add(admission.RetryBackoff(1))) || failed.FirstQueued != before.FirstQueued || failed.AgeOut != before.AgeOut {
		t.Fatalf("capacity rejection changed the retry contract: %+v %+v", failed, a)
	}
	if status := ledgerStatus(t, o); status.Ceiling.General.Used != 1 || status.Effects.General != 0 {
		t.Fatalf("failed capacity attempt charged or held the wrong amount: %+v %+v", status.Ceiling, status.Effects)
	}
	mono.advance(admission.RetryBackoff(1))
	f.host.advance(admission.RetryBackoff(1))
	turn(t, o)
	if c := candidate(t, o, id); c.Reason != admission.ReasonSetFull || c.Attempts != 1 || c.NotBefore != failed.NotBefore || c.ExpiresAt != failed.ExpiresAt {
		t.Fatalf("full set after backoff: %+v", c)
	}
	if _, applies := blocks.calls(); len(applies) != 1 {
		t.Fatal("full set dispatched a second attempt")
	}
	blocks.set(func(b *fakeBlocks) { b.temp = 0; b.afterApply = nil; delete(b.results, "192.0.2.10") })
	turn(t, o)
	retried := candidate(t, o, id)
	second := attemptOf(t, o, retried)
	if retried.State != admission.StateVerified || retried.Attempts != 2 || retried.ExpiresAt != failed.ExpiresAt ||
		retried.FirstQueued != before.FirstQueued || retried.AgeOut != before.AgeOut || second.Attempt.Seq != 2 ||
		second.Reserved.Before(a.Finished.Add(admission.RetryBackoff(1))) || !second.Reserved.Before(before.AgeOut) || second.ExpiresAt != a.ExpiresAt {
		t.Fatalf("freed slot did not admit the valid retry chain: %+v %+v", retried, second)
	}
	if status := ledgerStatus(t, o); status.Ceiling.General.Used != 2 || status.Effects.General != 1 {
		t.Fatalf("successful retry charged or held the wrong amount: %+v %+v", status.Ceiling, status.Effects)
	}
}

// Consecutive turns see already applied admission rows in the engine.
// Status counts those only through the ledger, including the current turn's
// new reservation. Repeated refreshes cannot accumulate either count.
func TestOwnerSetStatusCountsReservationsOnce(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	blocks.limit, blocks.temp, blocks.imported = 5, 1, 1
	blocks.afterApply = func(b *fakeBlocks) { b.temp++; b.admitted++ }
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	for i, addr := range []string{"192.0.2.10", "192.0.2.11"} {
		if i > 0 {
			// Distinct serving turns must respect the existing batch pace.
			mono.advance(batchEvery)
			f.host.advance(batchEvery)
		}
		id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, addr)
		turn(t, o)
		if c := candidate(t, o, id); c.State != admission.StateVerified {
			t.Fatalf("turn %d: %+v", i, c)
		}
		want := health.AdmissionSet{Limit: 5, Capacity: 5, Imported: 1,
			General:  health.AdmissionDryRunPartition{Size: 4, Used: i + 2, Free: 2 - i},
			Reserved: health.AdmissionDryRunPartition{Size: 1, Free: 1}}
		for range 3 {
			if set, setErr := ownerSet(t, o); set == nil || *set != want || setErr != "" {
				t.Fatalf("turn %d: refreshed set %+v %q, want %+v", i, set, setErr, want)
			}
		}
	}
	before, _ := ownerSet(t, o)
	want := *before
	reads := blocks.setReads
	// A maintenance turn must not silently refresh the non-admission side.
	blocks.set(func(b *fakeBlocks) { b.temp++; b.imported++ })
	if err := o.do(func() error { return o.runTurn(false) }); err != nil {
		t.Fatal(err)
	}
	if set, setErr := ownerSet(t, o); set == nil || *set != want || setErr != "" || blocks.setReads != reads {
		t.Fatalf("maintenance replaced the scheduling snapshot: %+v %q, reads %d", set, setErr, blocks.setReads)
	}
	turn(t, o)
	if set, setErr := ownerSet(t, o); set != nil || setErr != "" || blocks.setReads != reads {
		t.Fatalf("idle scheduling turn retained or reread the set: %+v %q", set, setErr)
	}
}

// A capacity rejection remains a proven failure on every attempt: exact
// retry deadlines for the first two, then terminal exhaustion on the third.
func TestOwnerSetFullAfterApplyExhaustsAttempts(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	blocks.limit = 2
	blocks.results["192.0.2.10"] = firewall.BlockResult{Effect: firewall.BlockFailed, Refusal: firewall.BlockRefusedFull}
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	initial := candidate(t, o, id)
	var previous admission.AttemptRecord
	for seq := uint32(1); seq <= admission.MaxAttempts; seq++ {
		turn(t, o)
		c := candidate(t, o, id)
		a := attemptOf(t, o, c)
		if c.Attempts != seq || a.Attempt.Seq != seq || a.State != admission.StateFailed || a.Disposition != admission.DispositionFailed ||
			c.FirstQueued != initial.FirstQueued || c.AgeOut != initial.AgeOut || a.ExpiresAt != c.ExpiresAt ||
			a.Reserved.Before(initial.FirstQueued) || !a.Reserved.Before(initial.AgeOut) {
			t.Fatalf("attempt %d lost its chain proof: %+v %+v", seq, c, a)
		}
		if seq > 1 && (a.ExpiresAt != previous.ExpiresAt || a.Reserved.Before(previous.Finished.Add(admission.RetryBackoff(seq-1)))) {
			t.Fatalf("retry %d changed expiry or ran before its predecessor's backoff: %+v %+v", seq, previous, a)
		}
		if status := ledgerStatus(t, o); status.Ceiling.General.Used != seq || status.Effects.General != 0 {
			t.Fatalf("attempt %d refunded a charge or retained a slot: %+v %+v", seq, status.Ceiling, status.Effects)
		}
		if seq < admission.MaxAttempts {
			if c.State != admission.StateQueued || !c.NotBefore.Equal(a.Finished.Add(admission.RetryBackoff(seq))) {
				t.Fatalf("retry %d has the wrong deadline: %+v %+v", seq, c, a)
			}
			wait := admission.RetryBackoff(seq)
			mono.advance(wait - time.Nanosecond)
			f.host.advance(wait - time.Nanosecond)
			turn(t, o)
			if early := candidate(t, o, id); early.Attempts != seq || early.NotBefore != c.NotBefore {
				t.Fatalf("retry ran before its exact deadline: %+v", early)
			}
			mono.advance(time.Nanosecond)
			f.host.advance(time.Nanosecond)
		} else if c.State != admission.StateFailed || c.Disposition != admission.DispositionFailed {
			t.Fatalf("third capacity failure did not end the generation: %+v", c)
		}
		previous = a
	}
	turn(t, o)
	if _, applies := blocks.calls(); len(applies) != int(admission.MaxAttempts) {
		t.Fatalf("capacity exhaustion dispatched %d attempts", len(applies))
	}
}

// JSON field names and unknown drain values match the documented API, and
// a successful or absent view never leaves a stale set_error behind.
func TestOwnerSetWireFields(t *testing.T) {
	s := setStatus(firewall.BlockAdmission{Limit: 5, Unclaimed: 1, Imported: 1, Drain: -time.Second}, admission.EffectsStatus{General: 1})
	raw, err := json.Marshal(health.AdmissionOwner{Set: s})
	if err != nil {
		t.Fatal(err)
	}
	var owner map[string]json.RawMessage
	if err = json.Unmarshal(raw, &owner); err != nil {
		t.Fatal(err)
	}
	var set map[string]json.RawMessage
	if err = json.Unmarshal(owner["set"], &set); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"limit": "5", "unlimited": "false", "capacity": "5", "unclaimed": "1", "imported": "1", "drain_seconds": "-1",
		"general": `{"size":3,"used":2,"free":1}`, "reserved": `{"size":1,"used":0,"free":1}`}
	if len(set) != len(want) {
		t.Fatalf("set fields: %s", owner["set"])
	}
	for key, value := range want {
		if string(set[key]) != value {
			t.Errorf("%s = %s, want %s", key, set[key], value)
		}
	}
	if _, ok := owner["set_error"]; ok {
		t.Fatal("successful read has set_error")
	}
	raw, err = json.Marshal(health.AdmissionOwner{SetError: "set dump failed"})
	if err != nil {
		t.Fatal(err)
	}
	owner = nil
	if err = json.Unmarshal(raw, &owner); err != nil {
		t.Fatal(err)
	}
	if string(owner["set_error"]) != `"set dump failed"` || owner["set"] != nil {
		t.Fatalf("failed read fields: %s", raw)
	}
}
