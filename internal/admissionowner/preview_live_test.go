package admissionowner

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/store"
)

// observeKind hands the ingress an observation of addr asking for kind and
// drains it, so the ledger names the episode and generation.
func observeKind(t *testing.T, o *Owner, p *admission.Producer, f *ownerFixture, addr, cursor string, kind admission.Kind) admission.CandidateID {
	t.Helper()
	target, err := admission.CanonicalAddress(addr, admission.Caps{IPv6: true})
	if err != nil {
		t.Fatal(err)
	}
	e, err := p.Mint(admission.EvidenceInput{
		Check: "ssh_brute", Attribution: admission.AttributionPeer, FindingID: "0123456789abcdef", Severity: admission.SeverityHigh,
		Observation: admission.ObservationRef{Stream: "log:sshd_log", Cursor: cursor, Version: 1},
		ObservedAt:  f.host.now(), Parser: admission.ParserRef{Name: "sshd", Version: 1}, Target: target,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = o.ingress.Submit(admission.Submission{Kind: kind, Target: target, Evidence: e}); err != nil {
		t.Fatal(err)
	}
	if err = o.do(o.drain); err != nil {
		t.Fatal(err)
	}
	for _, c := range queuedCandidates(t, o) {
		if c.Key.Kind == kind && c.Key.Target == target {
			id, idErr := c.ID()
			if idErr != nil {
				t.Fatal(idErr)
			}
			return id
		}
	}
	t.Fatalf("no queued %s for %s", kind, addr)
	return ""
}

// Once the ledger has started live a preview spends nothing that live work
// lives on. It makes no attempt, charges neither the ceiling nor the
// history, and leaves its episode open: the next observation of the
// address is previewed again, not answered by the preview. The comparison
// still counts each preview as observed.
func TestOwnerPreviewsSpendNothingOnceLive(t *testing.T) {
	for _, kind := range []admission.Kind{admission.KindChallenge, admission.KindPromote} {
		t.Run(kind.String(), func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			o := f.start(executeOptions(f, blocks))
			if !liveStarted(t, o) {
				t.Fatal("the live policy did not start live")
			}
			before, used := ledgerStatus(t, o), liveUsed(t, o)
			for n := uint32(1); n <= 2; n++ {
				id := observeKind(t, o, p, f, "192.0.2.11", fmt.Sprintf("offset=%d", n), kind)
				c := candidate(t, o, id)
				if c.State != admission.StateQueued || c.Key.Generation != n {
					t.Fatalf("observation %d was not queued as generation %d: %+v", n, n, c)
				}
				turn(t, o)
				if c = candidate(t, o, id); c.State != admission.StateDryRun || c.Attempts != 0 || !c.ExpiresAt.IsZero() {
					t.Fatalf("preview %d after the live start = %+v", n, c)
				}
				f.host.advance(time.Second)
			}
			after := ledgerStatus(t, o)
			if liveUsed(t, o) != used || after.Storage.General != before.Storage.General || after.Storage.Reserved != before.Storage.Reserved {
				t.Fatalf("previews spent live capacity: ceiling %d -> %d, history %+v -> %+v", used, liveUsed(t, o), before.Storage, after.Storage)
			}
			if n := outcomes(after, admission.DispositionObserve) - outcomes(before, admission.DispositionObserve); n != 0 {
				t.Fatalf("%d previews made an attempt", n)
			}
			var compared uint64
			o.compare.mu.Lock()
			for k, n := range o.compare.counts {
				if k.kind == kind && k.decision == decisionObserve {
					compared += n
				}
			}
			o.compare.mu.Unlock()
			if compared != 2 {
				t.Fatalf("comparison counted %d observed previews, want 2", compared)
			}
			if _, applies := blocks.calls(); len(applies) != 0 {
				t.Fatalf("a preview reached the engine: %+v", applies)
			}
		})
	}
}

// observedCount is how many previews of kind the comparison counted.
func observedCount(o *Owner, kind admission.Kind) (n uint64) {
	o.compare.mu.Lock()
	defer o.compare.mu.Unlock()
	for k, c := range o.compare.counts {
		if k.kind == kind && k.decision == decisionObserve {
			n += c
		}
	}
	return n
}

// noReservedPreview fails the test when a preview reserves an attempt.
func noReservedPreview(t *testing.T, o *Owner) {
	t.Helper()
	setOwnerHook(t, o, &observeLedger, func(*store.AdmissionLedger, admission.CandidateID, admission.Lane, time.Time) (admission.Candidate, admission.AttemptRecord, bool, admission.EvictionVictim, error) {
		t.Error("a preview on a live ledger reserved an attempt")
		return admission.Candidate{}, admission.AttemptRecord{}, false, admission.EvictionVictim{}, errors.New("reserved preview")
	})
}

// spentNothing fails unless id ended as a preview that made no attempt
// and the ceiling and history stand where before left them.
func spentNothing(t *testing.T, o *Owner, id admission.CandidateID, before admission.LedgerStatus, used uint32) {
	t.Helper()
	if c := candidate(t, o, id); c.State != admission.StateDryRun || c.Attempts != 0 || !c.ExpiresAt.IsZero() {
		t.Fatalf("preview on the live ledger = %+v", c)
	}
	after := ledgerStatus(t, o)
	if liveUsed(t, o) != used || after.Storage.General != before.Storage.General || after.Storage.Reserved != before.Storage.Reserved ||
		after.Storage.Outstanding != before.Storage.Outstanding || after.Unresolved != before.Unresolved {
		t.Fatalf("the preview spent live capacity: ceiling %d -> %d, storage %+v -> %+v", used, liveUsed(t, o), before.Storage, after.Storage)
	}
	if n := outcomes(after, admission.DispositionObserve) - outcomes(before, admission.DispositionObserve); n != 0 {
		t.Fatalf("%d previews made an attempt", n)
	}
}

// Every path that previews on a live ledger takes the uncharged ending:
// an owner that lost its engine previewing a block, the challenge a dry
// run still previews, and the challenge beside work a refused policy
// holds. None reserves an attempt or reaches the engine, and the held
// block is not a preview: it waits and runs once a valid policy returns.
func TestOwnerStartedPreviewPathsPreserveLiveState(t *testing.T) {
	t.Run("an owner without an engine", func(t *testing.T) {
		p := withTestRegistry(t)
		f := newOwnerFixture(t)
		blocks := newFakeBlocks()
		o := f.start(executeOptions(f, blocks))
		if !liveStarted(t, o) {
			t.Fatal("the live policy did not start live")
		}
		o.Stop()
		o = f.start(previewOptions(f))
		noReservedPreview(t, o)
		before, used := ledgerStatus(t, o), liveUsed(t, o)
		for n := uint32(1); n <= 2; n++ {
			id := observe(t, o, p, f, "192.0.2.30", fmt.Sprintf("offset=%d", n))
			if c := candidate(t, o, id); c.Key.Generation != n {
				t.Fatalf("observation %d joined generation %d: a preview answered the episode", n, c.Key.Generation)
			}
			turn(t, o)
			spentNothing(t, o, id, before, used)
			f.host.advance(time.Second)
		}
		if n := observedCount(o, admission.KindBlockIP); n != 2 {
			t.Fatalf("comparison counted %d block previews, want 2", n)
		}
		if _, applies := blocks.calls(); len(applies) != 0 {
			t.Fatalf("a preview reached the engine: %+v", applies)
		}
	})
	t.Run("a dry run's challenge", func(t *testing.T) {
		p := withTestRegistry(t)
		f := newOwnerFixture(t)
		o, r, _ := policyOwner(t, f, newFakeBlocks(), validPolicy(1))
		if !liveStarted(t, o) {
			t.Fatal("the live policy did not start live")
		}
		r.publish(dryPolicy(2))
		if err := o.Reload(); err != nil {
			t.Fatal(err)
		}
		noReservedPreview(t, o)
		before, used := ledgerStatus(t, o), liveUsed(t, o)
		id := observeKind(t, o, p, f, "192.0.2.31", "offset=1", admission.KindChallenge)
		turn(t, o)
		spentNothing(t, o, id, before, used)
		if n := observedCount(o, admission.KindChallenge); n != 1 {
			t.Fatalf("comparison counted %d challenge previews, want 1", n)
		}
	})
	t.Run("beside work a refused policy holds", func(t *testing.T) {
		p := withTestRegistry(t)
		f := newOwnerFixture(t)
		blocks := newFakeBlocks()
		first := validPolicy(1)
		o, r, mono := policyOwner(t, f, blocks, first)
		noReservedPreview(t, o)
		before, used := ledgerStatus(t, o), liveUsed(t, o)
		block, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.32")
		challenge := observeKind(t, o, p, f, "192.0.2.33", "offset=1", admission.KindChallenge)
		conflict := first
		conflict.CeilingLimit = 100
		r.publish(conflict)
		if err := o.Reload(); !errors.Is(err, ErrPolicy) {
			t.Fatalf("conflicting reload = %v", err)
		}
		mono.advance(time.Second)
		turn(t, o)
		if c := candidate(t, o, block); c.State != admission.StateQueued || c.Reason != admission.ReasonEngineUnavailable || c.Attempts != 0 {
			t.Fatalf("held block = %+v, want it queued for the engine", c)
		}
		spentNothing(t, o, challenge, before, used)
		r.publish(validPolicy(2))
		if err := o.Reload(); err != nil {
			t.Fatal(err)
		}
		mono.advance(time.Second)
		turn(t, o)
		if c := candidate(t, o, block); c.State != admission.StateVerified {
			t.Fatalf("held block under a valid policy = %+v, want it applied", c)
		}
	})
}

// livePick queues a challenge of addr on a live owner and returns it as a
// schedule would hand it to the preview.
func livePick(t *testing.T, o *Owner, p *admission.Producer, f *ownerFixture, addr string) execPick {
	t.Helper()
	id := observeKind(t, o, p, f, addr, "offset=1", admission.KindChallenge)
	return execPick{pick: admission.Pick{ID: id, Lane: admission.LaneGeneral, Tier: highTier}, c: candidate(t, o, id)}
}

// A live preview meets every answer the uncharged ending can give. Stale
// work ends as stale; a held target defers once and is not written again
// while it stays held; work in its backoff is left alone; the same ending
// again counts nothing; a storage failure is reported and the next try
// succeeds. A pick that ended or went in flight elsewhere fails that call
// without touching it, and the next turn still serves other work.
func TestOwnerLivePreviewRefusals(t *testing.T) {
	start := func(t *testing.T) (*Owner, *admission.Producer, *ownerFixture) {
		p := withTestRegistry(t)
		f := newOwnerFixture(t)
		o := f.start(executeOptions(f, newFakeBlocks()))
		if !liveStarted(t, o) {
			t.Fatal("the live policy did not start live")
		}
		return o, p, f
	}
	preview := func(o *Owner, pick execPick) error {
		return o.do(func() error { return o.preview(pick) })
	}
	answer := func(t *testing.T, o *Owner, err error) {
		setOwnerHook(t, o, &endDryRunLedger, func(*store.AdmissionLedger, admission.CandidateID) (admission.Candidate, bool, error) {
			return admission.Candidate{}, false, err
		})
	}
	t.Run("stale", func(t *testing.T) {
		o, p, f := start(t)
		pick := livePick(t, o, p, f, "192.0.2.40")
		f.host.advance(pick.c.AgeOut.Sub(f.host.now()) + time.Second)
		if err := o.do(o.tick); err != nil {
			t.Fatal(err)
		}
		endedAt := f.host.now()
		o.compare.addAt(compareKey{entry: admission.EntryScan, kind: admission.KindBlockIP, decision: decisionObserve}, endedAt.Add(time.Hour))
		terminate := terminateLedger
		fault := errors.New("fixture ending failure")
		setOwnerHook(t, o, &terminateLedger, func(*store.AdmissionLedger, admission.CandidateID, admission.Reason) (admission.Candidate, error) {
			return admission.Candidate{}, fault
		})
		if err := preview(o, pick); !errors.Is(err, fault) {
			t.Fatalf("failed refusal ending = %v, want %v", err, fault)
		}
		if c := candidate(t, o, pick.pick.ID); !reflect.DeepEqual(c, pick.c) {
			t.Fatalf("a failed ending changed the pick: %+v", c)
		}
		rows, _ := o.compare.take(endedAt, false)
		for _, row := range rows {
			if row.Result == actionlog.Refused {
				t.Fatalf("a failed ending counted a refusal: %+v", row)
			}
		}
		setOwnerHook(t, o, &terminateLedger, terminate)
		if err := preview(o, pick); err != nil {
			t.Fatal(err)
		}
		if c := candidate(t, o, pick.pick.ID); !c.State.Terminal() || c.Reason != admission.ReasonStale || c.Attempts != 0 {
			t.Fatalf("stale pick = %+v", c)
		}
		if n := observedCount(o, admission.KindChallenge); n != 0 {
			t.Fatalf("a stale pick counted as %d previews", n)
		}
		rows, _ = o.compare.take(endedAt, true)
		var refused uint64
		for _, row := range rows {
			if row.Result == actionlog.Refused && row.Action == admission.KindChallenge.String() && row.Error == admission.ReasonStale.String() {
				if !row.Timestamp.Equal(endedAt.UTC().Truncate(time.Hour).Add(time.Hour)) {
					t.Fatalf("refusal counted in the wrong hour: %+v", row)
				}
				refused += row.Count
			}
		}
		if refused != 1 {
			t.Fatalf("a stale preview counted %d refusals, want 1: %+v", refused, rows)
		}
	})
	t.Run("held target", func(t *testing.T) {
		o, p, f := start(t)
		pick := livePick(t, o, p, f, "192.0.2.41")
		answer(t, o, &admission.Error{Reason: admission.ReasonPendingRecovery, Detail: "an unresolved attempt holds the target"})
		if err := preview(o, pick); err != nil {
			t.Fatal(err)
		}
		deferred := candidate(t, o, pick.pick.ID)
		if deferred.State != admission.StateQueued || deferred.Reason != admission.ReasonPendingRecovery || deferred.Transitions != pick.c.Transitions+1 {
			t.Fatalf("held pick = %+v", deferred)
		}
		pick.c = deferred
		if err := preview(o, pick); err != nil {
			t.Fatal(err)
		}
		if c := candidate(t, o, pick.pick.ID); !reflect.DeepEqual(c, deferred) {
			t.Fatalf("a pick still held was written again: %+v", c)
		}
	})
	t.Run("not ready", func(t *testing.T) {
		o, p, f := start(t)
		pick := livePick(t, o, p, f, "192.0.2.42")
		answer(t, o, admission.ErrNotReady)
		if err := preview(o, pick); err != nil {
			t.Fatal(err)
		}
		if c := candidate(t, o, pick.pick.ID); !reflect.DeepEqual(c, pick.c) {
			t.Fatalf("a pick in its backoff changed: %+v", c)
		}
	})
	t.Run("same ending again", func(t *testing.T) {
		o, p, f := start(t)
		pick := livePick(t, o, p, f, "192.0.2.43")
		for range 2 {
			if err := preview(o, pick); err != nil {
				t.Fatal(err)
			}
		}
		if n := observedCount(o, admission.KindChallenge); n != 1 {
			t.Fatalf("the same ending counted %d previews, want 1", n)
		}
	})
	t.Run("storage failure", func(t *testing.T) {
		o, p, f := start(t)
		pick := livePick(t, o, p, f, "192.0.2.44")
		end := endDryRunLedger
		answer(t, o, errors.New("fixture write failure"))
		if err := preview(o, pick); err == nil {
			t.Fatal("a failed write was not reported")
		}
		if c := candidate(t, o, pick.pick.ID); !reflect.DeepEqual(c, pick.c) || observedCount(o, admission.KindChallenge) != 0 {
			t.Fatalf("a failed write changed the pick or counted a preview: %+v", c)
		}
		setOwnerHook(t, o, &endDryRunLedger, end)
		if err := preview(o, pick); err != nil {
			t.Fatal(err)
		}
		if c := candidate(t, o, pick.pick.ID); c.State != admission.StateDryRun || observedCount(o, admission.KindChallenge) != 1 {
			t.Fatalf("pick after the write recovered = %+v", c)
		}
	})
	for name, change := range map[string]func(*store.AdmissionLedger, admission.CandidateID, time.Time) error{
		"ended elsewhere": func(l *store.AdmissionLedger, id admission.CandidateID, _ time.Time) error {
			_, err := l.Terminate(id, admission.ReasonDisabled)
			return err
		},
		"in flight": func(l *store.AdmissionLedger, id admission.CandidateID, now time.Time) error {
			_, _, _, err := l.Reserve(id, admission.LaneGeneral, now.Add(time.Hour))
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			o, p, f := start(t)
			pick := livePick(t, o, p, f, "192.0.2.45")
			if err := o.do(func() error { return change(o.ledger, pick.pick.ID, o.now) }); err != nil {
				t.Fatal(err)
			}
			changed := candidate(t, o, pick.pick.ID)
			if err := preview(o, pick); err == nil {
				t.Fatal("a pick that left the queue was previewed")
			}
			if c := candidate(t, o, pick.pick.ID); !reflect.DeepEqual(c, changed) || observedCount(o, admission.KindChallenge) != 0 {
				t.Fatalf("the refused preview changed the pick or counted: %+v", c)
			}
			other := observeKind(t, o, p, f, "192.0.2.46", "offset=2", admission.KindChallenge)
			turn(t, o)
			if c := candidate(t, o, other); c.State != admission.StateDryRun {
				t.Fatalf("the next turn did not serve other work: %+v", c)
			}
			if c := candidate(t, o, pick.pick.ID); !reflect.DeepEqual(c, changed) {
				t.Fatalf("the next turn touched the pick that left the queue: %+v", c)
			}
		})
	}
}

// A block waiting for a retry is previewed on a live ledger like any other
// work the owner does not run: the preview makes no new attempt and no
// charge, and what the failed attempt spent stays as it was.
func TestOwnerLivePreviewOfARetryKeepsWhatItSpent(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	o := f.start(executeOptions(f, newFakeBlocks()))
	mono := heldMono(t, o)
	if !liveStarted(t, o) {
		t.Fatal("the live policy did not start live")
	}
	id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.50")
	if err := o.do(func() error {
		_, a, _, err := o.ledger.Reserve(id, admission.LaneGeneral, o.now.Add(time.Hour))
		if err != nil {
			return err
		}
		if _, _, _, err = o.ledger.Execute(a.Attempt.ID); err != nil {
			return err
		}
		_, _, err = o.ledger.Finish(a.Attempt.ID, admission.DispositionFailed)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	f.host.advance(admission.RetryBackoff(1))
	mono.advance(admission.RetryBackoff(1))
	if err := o.do(o.tick); err != nil {
		t.Fatal(err)
	}
	retry := candidate(t, o, id)
	if retry.State != admission.StateQueued || retry.Attempts != 1 {
		t.Fatalf("fixture is not a queued retry: %+v", retry)
	}
	before, used := ledgerStatus(t, o), liveUsed(t, o)
	pick := execPick{pick: admission.Pick{ID: id, Lane: admission.LaneGeneral, Tier: highTier}, c: retry}
	if err := o.do(func() error { return o.previewLive(pick) }); err != nil {
		t.Fatal(err)
	}
	c := candidate(t, o, id)
	if c.State != admission.StateDryRun || c.Attempts != 1 || !c.ExpiresAt.Equal(retry.ExpiresAt) {
		t.Fatalf("previewed retry = %+v, was %+v", c, retry)
	}
	after := ledgerStatus(t, o)
	if liveUsed(t, o) != used || after.Storage.General != before.Storage.General || after.Storage.Reserved != before.Storage.Reserved {
		t.Fatalf("previewing a retry spent capacity: ceiling %d -> %d, storage %+v -> %+v", used, liveUsed(t, o), before.Storage, after.Storage)
	}
	if n := outcomes(after, admission.DispositionDryRun) - outcomes(before, admission.DispositionDryRun); n != 1 || observedCount(o, admission.KindBlockIP) != 1 {
		t.Fatalf("the preview counted %d dry-run outcomes and %d observed previews, want one each", n, observedCount(o, admission.KindBlockIP))
	}
}
