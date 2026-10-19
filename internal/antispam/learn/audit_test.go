package learn

import (
	"context"
	"reflect"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

const day = 24 * time.Hour

// auditFixture holds several clusters, each with a committed body and an
// idle target already verified at its value.
type auditFixture struct {
	*publishFixture
}

func newAuditFixture(t *testing.T) *auditFixture {
	t.Helper()
	l, _ := openLedger(t)
	return &auditFixture{&publishFixture{ledger: l, bodies: testBodies(t), storage: newStorage()}}
}

// add stores cluster id with anchor d at target tv, verified, and the
// matching value in storage.
func (f *auditFixture) add(t *testing.T, id uint64, d Digest, tv int32, last time.Time, uids ...int) {
	t.Helper()
	body := []byte("From: x@example.com\r\n\r\nanchor " + string(d[:4]) + "\r\n")
	f.storage.bodies[string(body)] = d
	s := stageCommit(t, f.bodies, body, id)
	if err := f.ledger.Update(func(tx LedgerTx) error {
		if _, err := tx.NextClusterID(); err != nil {
			return err
		}
		c := Cluster{ID: id, Anchor: d, BodyLen: s.Len, BodySHA: s.SHA, UIDs: uids, Aliases: []Digest{d}, Revision: 1, Created: last, LastReport: last,
			Charges: []Charge{{UID: uids[0], Usage: Usage{BodyBytes: s.Len, Aliases: 1}}}}
		if err := tx.PutCluster(c); err != nil {
			return err
		}
		if err := tx.PutAlias(d, id); err != nil {
			return err
		}
		if err := tx.AddUsage(uids[0], false, Usage{BodyBytes: s.Len, Aliases: 1}); err != nil {
			return err
		}
		return tx.PutTarget(Target{Digest: d, ClusterID: id, T: tv, Revision: 1, Phase: PhaseIdle})
	}); err != nil {
		t.Fatal(err)
	}
	f.storage.set(d, int64(tv))
}

func (f *auditFixture) guard(t *testing.T, d Digest) {
	t.Helper()
	if err := f.ledger.Update(func(tx LedgerTx) error {
		return tx.PutTarget(Target{Digest: d, ClusterID: 99, T: 0, Revision: 2, Phase: PhaseIdle})
	}); err != nil {
		t.Fatal(err)
	}
}

// rotation runs audit turns until one rotation completes, then repairs.
func rotation(t *testing.T, p *Publisher, batch int, now time.Time) AuditProgress {
	t.Helper()
	var total AuditProgress
	for range 100 {
		prog, err := p.AuditTurn(context.Background(), batch, now)
		if err != nil {
			t.Fatal(err)
		}
		total.Checked += prog.Checked
		total.Repaired += prog.Repaired
		if prog.RotationDone {
			total.RotationDone = true
			break
		}
	}
	if !total.RotationDone {
		t.Fatal("rotation never completed")
	}
	for range 10 {
		n, err := p.RepairTurn(context.Background(), 10)
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			break
		}
	}
	return total
}

func (f *auditFixture) targetOf(t *testing.T, d Digest) (Target, bool) {
	t.Helper()
	var got Target
	var ok bool
	if err := f.ledger.View(func(v LedgerView) error {
		var err error
		got, ok, err = v.Target(d)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return got, ok
}

// Review focus 2: an old add arriving after verification and an old delete
// arriving after a re-add. One rotation restores exactly T.
func TestAuditRepairsLateAddAndLateDelete(t *testing.T) {
	f := newAuditFixture(t)
	f.add(t, 1, digest('a'), 4, t0, 1001)
	f.add(t, 2, digest('b'), 2, t0, 1002)
	f.storage.set(digest('a'), 6)
	f.storage.mu.Lock()
	delete(f.storage.values, digest('b'))
	f.storage.mu.Unlock()
	p := f.publisher()
	prog := rotation(t, p, AuditBatch, t0)
	if prog.Checked != 2 || prog.Repaired != 2 {
		t.Fatalf("progress %+v", prog)
	}
	if v, _ := f.storage.value(digest('a')); v != 4 {
		t.Fatalf("late add left %d", v)
	}
	if v, ok := f.storage.value(digest('b')); !ok || v != 2 {
		t.Fatalf("late delete left %d present %v", v, ok)
	}
	for _, d := range []Digest{digest('a'), digest('b')} {
		if got, _ := f.targetOf(t, d); got.Phase != PhaseIdle {
			t.Fatalf("%s left in %s", d[:1], got.Phase)
		}
	}
}

func TestAuditIdleClusterWithoutMail(t *testing.T) {
	f := newAuditFixture(t)
	f.add(t, 1, digest('a'), 2, t0, 1001)
	f.storage.set(digest('a'), 10)
	rotation(t, f.publisher(), AuditBatch, t0)
	if v, _ := f.storage.value(digest('a')); v != 2 {
		t.Fatalf("idle cluster left at %d", v)
	}
}

func TestAuditZeroTargetResurrection(t *testing.T) {
	f := newAuditFixture(t)
	f.guard(t, digest('z'))
	f.storage.set(digest('z'), 2)
	rotation(t, f.publisher(), AuditBatch, t0)
	if _, ok := f.storage.value(digest('z')); ok {
		t.Fatal("resurrected digest left in storage")
	}
	if got, ok := f.targetOf(t, digest('z')); !ok || got.T != 0 {
		t.Fatalf("guard dropped: %+v %v", got, ok)
	}
}

func TestRetireAt90DaysFromAdmission(t *testing.T) {
	f := newAuditFixture(t)
	f.add(t, 1, digest('a'), 2, t0, 1001)
	f.add(t, 2, digest('b'), 2, t0.Add(-70*day), 1002)
	// A reserved, unsent admission counts; a cancelled one does not.
	if err := f.ledger.Update(func(tx LedgerTx) error {
		if err := tx.PutIntent(Intent{ID: "late", Kind: IntentReport, UID: 1003, Admitted: t0.Add(10 * day), Clusters: []IntentCluster{{ClusterID: 1}}}); err != nil {
			return err
		}
		return tx.PutIntent(Intent{ID: "cancelled", Kind: IntentReport, UID: 1004, Admitted: t0.Add(50 * day), Clusters: []IntentCluster{{ClusterID: 1}}, Done: true})
	}); err != nil {
		t.Fatal(err)
	}
	p := f.publisher()
	retire := func(now time.Time) []uint64 {
		t.Helper()
		ids, err := p.RetireDue(now)
		if err != nil {
			t.Fatal(err)
		}
		return ids
	}
	if ids := retire(t0.Add(15 * day)); len(ids) != 0 {
		t.Fatalf("retired early: %v", ids)
	}
	// The clock steps back below the watermark: nothing retires, not even
	// cluster 3, admitted under the old clock and due by the new one.
	f.add(t, 3, digest('c'), 2, t0.Add(-80*day), 1005)
	if ids := retire(t0.Add(12 * day)); len(ids) != 0 {
		t.Fatalf("retired on a stepped-back clock: %v", ids)
	}
	if ids := retire(t0.Add(15*day + time.Hour)); !reflect.DeepEqual(ids, []uint64{3}) {
		t.Fatalf("retired %v", ids)
	}
	if ids := retire(t0.Add(20 * day)); !reflect.DeepEqual(ids, []uint64{2}) {
		t.Fatalf("retired %v", ids)
	}
	// Storage TTL refreshes and present values change nothing; the
	// reserved admission moves cluster 1's deadline to day 100.
	if ids := retire(t0.Add(99 * day)); len(ids) != 0 {
		t.Fatalf("retired before the reserved admission's deadline: %v", ids)
	}
	if ids := retire(t0.Add(100 * day)); !reflect.DeepEqual(ids, []uint64{1}) {
		t.Fatalf("retired %v", ids)
	}
	got, _ := f.targetOf(t, digest('a'))
	if got.T != 0 || got.Revision != 2 || got.Phase == PhaseIdle {
		t.Fatalf("target %+v", got)
	}
	var alias, cluster bool
	var usage Usage
	if err := f.ledger.View(func(v LedgerView) error {
		var err error
		if _, alias, err = v.Alias(digest('a')); err != nil {
			return err
		}
		if _, cluster, err = v.Cluster(1); err != nil {
			return err
		}
		usage, err = v.Usage(1001, false)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if alias || cluster || usage != (Usage{}) {
		t.Fatalf("alias %v cluster %v usage %+v left after retirement", alias, cluster, usage)
	}
	if _, err := f.bodies.Read(1, 1, ""); err == nil {
		t.Fatal("body left after retirement")
	}
}

func TestRebuildAfterFlush(t *testing.T) {
	f := newAuditFixture(t)
	f.add(t, 1, digest('a'), 4, t0, 1001, 1002)
	f.add(t, 2, digest('b'), 2, t0.Add(-100*day), 1003)
	f.storage.mu.Lock()
	f.storage.values = map[Digest]int64{}
	f.storage.mu.Unlock()
	p := f.publisher()
	if ids, err := p.RetireDue(t0); err != nil || !reflect.DeepEqual(ids, []uint64{2}) {
		t.Fatalf("retired %v err %v", ids, err)
	}
	if _, err := p.AuditTurn(context.Background(), AuditBatch, t0); err != nil {
		t.Fatal(err)
	}
	if !p.RebuildNeeded() || p.FreshMatchingAllowed() {
		t.Fatal("absent anchors did not pause fresh matching")
	}
	rotation(t, p, AuditBatch, t0)
	if v, ok := f.storage.value(digest('a')); !ok || v != 4 {
		t.Fatalf("live anchor rebuilt to %d present %v", v, ok)
	}
	if _, ok := f.storage.value(digest('b')); ok {
		t.Fatal("expired anchor rebuilt")
	}
	var c Cluster
	if err := f.ledger.View(func(v LedgerView) error {
		var err error
		c, _, err = v.Cluster(1)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c.UIDs, []int{1001, 1002}) || !c.LastReport.Equal(t0) {
		t.Fatalf("rebuild counted contributions: %+v", c)
	}
	if p.RebuildNeeded() || !p.FreshMatchingAllowed() {
		t.Fatal("fresh matching still paused after the rebuild")
	}
}

func TestFreshMatchingWaitsForRotation(t *testing.T) {
	f := newAuditFixture(t)
	f.add(t, 1, digest('a'), 2, t0, 1001)
	f.add(t, 2, digest('b'), 2, t0, 1002)
	f.add(t, 3, digest('c'), 2, t0, 1003)
	p := f.publisher()
	if p.FreshMatchingAllowed() {
		t.Fatal("fresh matching allowed before any audit")
	}
	prog, err := p.AuditTurn(context.Background(), 2, t0)
	if err != nil || prog.RotationDone || p.FreshMatchingAllowed() {
		t.Fatalf("after a partial rotation: %+v %v", prog, err)
	}
	if prog, err = p.AuditTurn(context.Background(), 2, t0); err != nil || !prog.RotationDone {
		t.Fatalf("second turn %+v %v", prog, err)
	}
	if !p.FreshMatchingAllowed() {
		t.Fatal("fresh matching still paused after a clean rotation")
	}
}

func TestAuditNoUnconditionalReset(t *testing.T) {
	f := newAuditFixture(t)
	for i, c := range []byte("abcde") {
		f.add(t, uint64(i+1), digest(c), int32(2*(i+1)), t0, 1001+i)
	}
	p := f.publisher()
	for range 3 {
		if prog := rotation(t, p, 2, t0); prog.Repaired != 0 {
			t.Fatalf("repaired %d", prog.Repaired)
		}
	}
	if adds, deletes := f.storage.counts(); len(adds) != 0 || deletes != 0 {
		t.Fatalf("adds %v deletes %d", adds, deletes)
	}
}

// An anchor absent because its reset is under way, or because it awaits its
// first publication, is not a lost backend.
func TestAuditPendingAbsenceIsNotLoss(t *testing.T) {
	f := newAuditFixture(t)
	f.add(t, 1, digest('a'), 4, t0, 1001)
	if err := f.ledger.Update(func(tx LedgerTx) error {
		return tx.PutTarget(Target{Digest: digest('a'), ClusterID: 1, T: 4, Revision: 1, Phase: PhaseAddPending, ResetPending: true, RestoreT: 4})
	}); err != nil {
		t.Fatal(err)
	}
	f.storage.mu.Lock()
	delete(f.storage.values, digest('a'))
	f.storage.mu.Unlock()
	p := f.publisher()
	if _, err := p.AuditTurn(context.Background(), AuditBatch, t0); err != nil {
		t.Fatal(err)
	}
	if p.RebuildNeeded() {
		t.Fatal("a reset in progress read as a lost backend")
	}
}
