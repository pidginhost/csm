package admissionowner

import (
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/store"
	"github.com/pidginhost/csm/internal/verdict"
)

// exampleWrites records each example batch the owner writes.
type exampleWrites struct {
	mu      sync.Mutex
	batches [][]store.DryRunBlock
	fail    error
}

func watchExamples(t *testing.T, o *Owner) *exampleWrites {
	t.Helper()
	w := &exampleWrites{}
	write := recordExamples
	setOwnerHook(t, o, &recordExamples, func(db *store.DB, blocks []store.DryRunBlock) error {
		w.mu.Lock()
		defer w.mu.Unlock()
		w.batches = append(w.batches, slices.Clone(blocks))
		if w.fail != nil {
			return w.fail
		}
		return write(db, blocks)
	})
	return w
}

func (w *exampleWrites) written() [][]store.DryRunBlock {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Clone(w.batches)
}

func (w *exampleWrites) failWith(err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.fail = err
}

// outputOf copies the owner's dry-run output bookkeeping.
func outputOf(t *testing.T, o *Owner) dryRunOutput {
	t.Helper()
	var out dryRunOutput
	if err := o.do(func() error { out = o.out; out.batch = nil; return nil }); err != nil {
		t.Fatal(err)
	}
	return out
}

// maintain runs one maintenance step a second after the last.
func maintain(t *testing.T, o *Owner, mono *fakeMono) {
	t.Helper()
	mono.advance(time.Second)
	if err := o.do(func() error { o.maintainExamples(); return nil }); err != nil {
		t.Fatal(err)
	}
}

// Spec 3.6: each committed capacity admission leaves one example, written
// in one batch per turn after its endings, with the session, candidate,
// address, registered check and expiry; other predictions leave none.
// Examples already committed are written even when a later ending fails
// and stops the turn.
func TestOwnerWritesOneExampleBatchPerTurn(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	blocks.temp, blocks.limit = 8, 11
	o, _, _ := policyOwner(t, f, blocks, dryPolicy(1))
	w := watchExamples(t, o)
	ids := map[string]admission.CandidateID{}
	for _, addr := range []string{"192.0.2.10", "2001:db8::10", "192.0.2.11"} {
		ids[addr], _ = queuedAt(t, o, p, f.host, admission.SeverityHigh, addr)
	}
	turn(t, o)
	fc := forecastOf(t, o)
	got := w.written()
	if len(got) != 1 || len(got[0]) != 2 || len(fc.entries) != 2 {
		t.Fatalf("example batches = %+v, want one batch of the two capacity admissions %+v", got, fc)
	}
	for i, b := range got[0] {
		entry, admitted := fc.entries[b.IP]
		if !admitted || b.Candidate != ids[b.IP] || b.Session != fc.id || b.Kind != admission.KindBlockIP || b.Check != "unknown" ||
			!b.At.Equal(f.host.now()) || !b.ExpiresAt.Equal(entry.expires) {
			t.Fatalf("example %d = %+v", i, b)
		}
	}
	if n := f.db.DryRunBlocksCount(); n != 2 {
		t.Fatalf("stored examples = %d", n)
	}
	fail := errors.New("disk full")
	end := endDryRunLedger
	calls := 0
	setOwnerHook(t, o, &endDryRunLedger, func(l *store.AdmissionLedger, id admission.CandidateID) (admission.Candidate, bool, error) {
		calls++
		if calls == 2 {
			return admission.Candidate{}, false, fail
		}
		return end(l, id)
	})
	blocks.set(func(b *fakeBlocks) { b.temp = 0 })
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.12")
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.13")
	if err := o.do(o.turn); !errors.Is(err, fail) {
		t.Fatalf("turn = %v", err)
	}
	if got = w.written(); len(got) != 2 || len(got[1]) != 1 || got[1][0].IP != "192.0.2.12" {
		t.Fatalf("batches after a failed ending = %+v", got)
	}
	if out := outputOf(t, o); out.examplesLost != 0 || out.recordErrors != 0 {
		t.Fatalf("output = %+v", out)
	}
}

// A panel allow ends its pick with no forecast change and no example.
func TestOwnerWritesNoExampleForAPanelAllow(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	panel := newFakePanel("allow")
	panel.answer = func(string) (verdict.Response, error) { return verdict.Response{Verdict: "allow"}, nil }
	o, _, _ := policyOwner(t, f, blocks, dryVerdictPolicy(1, panel))
	w := watchExamples(t, o)
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	turn(t, o)
	readyAnswers(t, o, 1)
	turn(t, o)
	if got := w.written(); len(got) != 0 || f.db.DryRunBlocksCount() != 0 {
		t.Fatalf("a panel allow wrote examples %+v", got)
	}
	if fc := forecastOf(t, o); len(fc.entries) != 0 || verdictState(t, o).AllowEndings != 1 {
		t.Fatalf("forecast = %+v", fc)
	}
}

// A failed example write keeps the committed endings and the forecast:
// the batch counts as lost with one record error, and nothing retries it.
// A bucket above its cap discards the batch as lost without an error.
func TestOwnerCountsLostExamples(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o, _, _ := policyOwner(t, f, blocks, dryPolicy(1))
	w := watchExamples(t, o)
	w.failWith(errors.New("disk full"))
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.11")
	turn(t, o)
	if out := outputOf(t, o); out.examplesLost != 2 || out.recordErrors != 1 {
		t.Fatalf("output after a failed write = %+v", out)
	}
	if fc := forecastOf(t, o); fc.picks[admission.PredictCapacityAdmit] != 2 || len(queuedCandidates(t, o)) != 0 {
		t.Fatalf("a failed example write undid the forecast: %+v", fc)
	}
	w.failWith(store.ErrDryRunBlocksFull)
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.12")
	turn(t, o)
	if out := outputOf(t, o); out.examplesLost != 3 || out.recordErrors != 1 {
		t.Fatalf("output after a full bucket = %+v", out)
	}
	if got := w.written(); len(got) != 2 {
		t.Fatalf("a lost batch was retried: %d writes", len(got))
	}
}

// Spec 3.6, 6.4: a change to live discards the forecast and asks for a
// purge at the same boundary. Until a purge pass completes the examples
// are stale; a failed step is counted and retried on a later maintenance
// turn, at most once a second, and nothing of the old session is written
// after the boundary. The next dry run starts a session of its own.
func TestOwnerPurgesExamplesAfterAFlipToLive(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o, r, mono := policyOwner(t, f, blocks, dryPolicy(1))
	w := watchExamples(t, o)
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	turn(t, o)
	maintain(t, o, mono)
	if out := outputOf(t, o); out.stale || f.db.DryRunBlocksCount() != 1 {
		t.Fatalf("a dry run purged its own examples: %+v, %d stored", out, f.db.DryRunBlocksCount())
	}
	r.publish(validPolicy(2))
	if err := o.Reload(); err != nil {
		t.Fatal(err)
	}
	if out := outputOf(t, o); !out.stale || forecastOf(t, o) != nil {
		t.Fatalf("a flip to live left %+v", out)
	}
	fail := errors.New("disk full")
	step := maintainStore
	failing := true
	setOwnerHook(t, o, &maintainStore, func(db *store.DB, m store.DryRunMaintenance) (store.DryRunMaintained, error) {
		if failing {
			return store.DryRunMaintained{}, fail
		}
		return step(db, m)
	})
	maintain(t, o, mono)
	if out := outputOf(t, o); !out.stale || out.recordErrors != 1 || f.db.DryRunBlocksCount() != 1 {
		t.Fatalf("after a failed purge step: %+v, %d stored", out, f.db.DryRunBlocksCount())
	}
	// A second step in the same second does nothing.
	if err := o.do(func() error { failing = false; o.maintainExamples(); return nil }); err != nil {
		t.Fatal(err)
	}
	if f.db.DryRunBlocksCount() != 1 {
		t.Fatal("maintenance ran twice in one second")
	}
	maintain(t, o, mono)
	if out := outputOf(t, o); out.stale || out.recordErrors != 1 || f.db.DryRunBlocksCount() != 0 {
		t.Fatalf("after the purge: %+v, %d stored", out, f.db.DryRunBlocksCount())
	}
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.11")
	turn(t, o)
	if got := w.written(); len(got) != 1 {
		t.Fatalf("live work wrote examples: %+v", got)
	}
}

// Spec 3.6, 6.4: a purge still pending when a new dry run starts keeps
// that session's examples, whatever their key times, and removes the
// ended session's. Its pass starts over once the kept session changes.
func TestOwnerPurgeKeepsTheNewSession(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o, r, mono := policyOwner(t, f, blocks, dryPolicy(1))
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.11")
	turn(t, o)
	old := forecastOf(t, o).id
	r.publish(validPolicy(2))
	if err := o.Reload(); err != nil {
		t.Fatal(err)
	}
	fail := errors.New("disk full")
	step := maintainStore
	failing := true
	setOwnerHook(t, o, &maintainStore, func(db *store.DB, m store.DryRunMaintenance) (store.DryRunMaintained, error) {
		if failing {
			return store.DryRunMaintained{}, fail
		}
		return step(db, m)
	})
	maintain(t, o, mono)
	r.publish(dryPolicy(3))
	mono.advance(time.Second)
	f.host.advance(time.Second)
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.12")
	turn(t, o)
	fresh := forecastOf(t, o)
	if fresh == nil || fresh.id == old || fresh.reset != resetModeChange || f.db.DryRunBlocksCount() != 3 {
		t.Fatalf("new session %+v with %d stored", fresh, f.db.DryRunBlocksCount())
	}
	// The wall clock steps back; the purge keeps the session, not a time.
	f.host.set(func(h *fakeHost) { h.wall = h.wall.Add(-time.Hour) })
	if err := o.do(func() error { failing = false; return nil }); err != nil {
		t.Fatal(err)
	}
	maintain(t, o, mono)
	if out := outputOf(t, o); out.stale || f.db.DryRunBlocksCount() != 1 {
		t.Fatalf("after the purge: %+v, %d stored", out, f.db.DryRunBlocksCount())
	}
}

// Maintenance also removes examples older than a week, one bounded step a
// second, without a purge.
func TestOwnerPrunesOldExamples(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o, _, mono := policyOwner(t, f, blocks, dryPolicy(1))
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	turn(t, o)
	f.host.advance(7*24*time.Hour + time.Second)
	mono.advance(7*24*time.Hour + time.Second)
	if err := o.do(o.tick); err != nil {
		t.Fatal(err)
	}
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.11")
	turn(t, o)
	maintain(t, o, mono)
	if n := f.db.DryRunBlocksCount(); n != 1 {
		t.Fatalf("stored examples after a week = %d", n)
	}
	if out := outputOf(t, o); out.stale || out.recordErrors != 0 {
		t.Fatalf("output = %+v", out)
	}
}
