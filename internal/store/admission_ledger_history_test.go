package store

import (
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

func (f *ledgerFixture) historyEntry(id admission.CandidateID) (admission.HistoryEntry, bool) {
	f.t.Helper()
	return historyEntryIn(f.t.(*testing.T), f.db, id)
}

func (f *ledgerFixture) cost(id admission.CandidateID) uint32 {
	f.t.Helper()
	return costIn(f.t.(*testing.T), f.db, id)
}

func (f *ledgerFixture) adjustStorage(mutate func(*admission.StorageState)) {
	f.t.Helper()
	if err := f.db.bolt.Update(func(tx *bolt.Tx) error { return adjustStorage(tx, mutate) }); err != nil {
		f.t.Fatal(err)
	}
}

// A reservation charges the candidate's history cost to the allowance of
// its lane, from that allowance's credit, in the reservation's own
// transaction. A readback charges nothing.
func TestAdmissionLedgerReserveChargesHistory(t *testing.T) {
	f := newLedgerFixture(t)
	start := f.storageState()
	id := f.queued()
	cost := f.cost(id)
	c, a, granted, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour))
	if err != nil || !granted {
		t.Fatalf("reserve: %v %v", granted, err)
	}
	if h, found := f.historyEntry(id); !found || h != (admission.HistoryEntry{RootMask: 1, General: cost}) {
		t.Fatalf("history entry = %+v (found %t), want %d general bytes", h, found, cost)
	}
	s := f.storageState()
	if s.General.Used != uint64(cost) || s.General.Credit != start.General.Credit-uint64(cost)*uint64(time.Second) || s.Reserved != start.Reserved {
		t.Fatalf("storage after a general charge = %+v", s)
	}
	before := f.snapshot()
	if _, again, granted, readErr := f.l.Reserve(id, admission.LaneGeneral, c.ExpiresAt); readErr != nil || granted || again != a {
		t.Fatalf("readback: %+v %v %v", again, granted, readErr)
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("a readback charged history")
	}
	direct := f.published(evidenceSpec{producer: f.mail, check: "mail_takeover", target: "192.0.2.11", cursor: "direct", severity: admission.SeverityCritical})
	_, directID := f.enqueue(f.request("192.0.2.11", direct))
	if _, _, _, err = f.l.Reserve(directID, admission.LaneDirect, f.wall.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if h, _ := f.historyEntry(directID); h != (admission.HistoryEntry{RootMask: 1, Reserved: f.cost(directID)}) {
		t.Fatalf("direct history entry = %+v", h)
	}
	if s = f.storageState(); s.Reserved.Used != uint64(f.cost(directID)) || s.General.Used != uint64(cost) {
		t.Fatalf("storage after a direct charge = %+v", s)
	}
}

// A retry charges only what the candidate's history grew by since its
// last reservation, on the retry's lane.
func TestAdmissionLedgerRetryChargesOnlyGrowth(t *testing.T) {
	f := newLedgerFixture(t)
	local := f.published(evidenceSpec{})
	_, id := f.enqueue(f.request("192.0.2.10", local))
	first := f.cost(id)
	_, a, _, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.l.Finish(a.Attempt.ID, admission.DispositionFailed); err != nil {
		t.Fatal(err)
	}
	f.tickAt(f.wall.Add(admission.RetryBackoff(1)))
	used := f.storageState().General.Used
	if _, a, _, err = f.l.Reserve(id, admission.LaneGeneral, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if s := f.storageState(); s.General.Used != used {
		t.Fatalf("a retry without growth charged %d bytes", s.General.Used-used)
	}
	if _, _, err = f.l.Finish(a.Attempt.ID, admission.DispositionFailed); err != nil {
		t.Fatal(err)
	}
	f.tickAt(f.wall.Add(admission.RetryBackoff(2)))
	intel := f.published(evidenceSpec{producer: f.rep, check: "reputation", cursor: "intel"})
	if _, _, err = f.l.Enqueue(f.request("192.0.2.10", local, intel)); err != nil {
		t.Fatal(err)
	}
	grown := f.cost(id)
	if grown <= first {
		t.Fatalf("a new root did not grow the cost: %d -> %d", first, grown)
	}
	if e, entryErr := f.entry(id); entryErr != nil || !e.Corroborated {
		t.Fatalf("entry = %+v, %v", e, entryErr)
	}
	if _, _, _, err = f.l.Reserve(id, admission.LaneCorroborated, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if h, _ := f.historyEntry(id); h != (admission.HistoryEntry{RootMask: 3, General: first, Reserved: grown - first}) {
		t.Fatalf("history entry after growth = %+v, want %d general and %d reserved", h, first, grown-first)
	}
	if s := f.storageState(); s.General.Used != uint64(first) || s.Reserved.Used != uint64(grown-first) {
		t.Fatalf("storage after growth = %+v", s)
	}
}

// A reservation the history budget cannot pay for is refused before any
// change: the lane's credit, its allowance and the recovery reserve each
// bind.
func TestAdmissionLedgerReserveRefusesBeyondHistory(t *testing.T) {
	general, _ := admission.HistoryLanes()
	for _, tc := range []struct {
		name   string
		mutate func(*admission.StorageState)
		reason admission.Reason
	}{
		{"no credit", func(s *admission.StorageState) { s.General.Credit = 0 }, admission.ReasonStorageShare},
		{"credit below the cost", func(s *admission.StorageState) { s.General.Credit = 999 * uint64(time.Second) }, admission.ReasonStorageShare},
		{"allowance full", func(s *admission.StorageState) { s.General.Used = general - 999 }, admission.ReasonStorageShare},
		{"recovery reserve full", func(s *admission.StorageState) { s.Recovery = admission.RecoveryReserveBytes - 999 }, admission.ReasonPendingRecovery},
		{"recovery reserve overflow", func(s *admission.StorageState) { s.Recovery = ^uint64(0) }, admission.ReasonPendingRecovery},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newLedgerFixture(t)
			id := f.queued()
			if f.cost(id) < 1000 {
				t.Fatalf("cost %d is below the test's margin", f.cost(id))
			}
			f.adjustStorage(tc.mutate)
			before := f.snapshot()
			_, _, _, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour))
			wantLedgerReason(t, tc.name, err, tc.reason)
			if !reflect.DeepEqual(before, f.snapshot()) {
				t.Fatal("a refused reservation changed the ledger")
			}
		})
	}
}

// A retry whose history has not grown charges nothing, and challenge work
// charges no ceiling either: the lane check must still refuse a
// reservation that names no lane.
func TestAdmissionLedgerRetryWithoutALaneIsRefused(t *testing.T) {
	f := newLedgerFixture(t)
	req := f.request("192.0.2.10", f.published(evidenceSpec{}))
	req.Kind = admission.KindChallenge
	_, id := f.enqueue(req)
	_, a, _, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.l.Finish(a.Attempt.ID, admission.DispositionFailed); err != nil {
		t.Fatal(err)
	}
	f.tickAt(f.wall.Add(admission.RetryBackoff(1)))
	before := f.snapshot()
	_, _, _, err = f.l.Reserve(id, 0, time.Time{})
	wantLedgerReason(t, "a retry without a lane", err, admission.ReasonInvalid)
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("a refused retry changed the ledger")
	}
}

// Every outstanding reservation keeps room for its possible unknown outcome.
func TestAdmissionLedgerRecoveryIncludesOutstandingAttempts(t *testing.T) {
	f := newLedgerFixture(t)
	ids := f.fill(2, evidenceSpec{})
	cost := f.cost(ids[0])
	f.adjustStorage(func(s *admission.StorageState) { leaveRecoveryRoom(s, uint64(cost)) })
	_, a, granted, err := f.l.Reserve(ids[0], admission.LaneGeneral, f.wall.Add(time.Hour))
	if err != nil || !granted {
		t.Fatalf("first reservation: %v %v", granted, err)
	}
	before := f.snapshot()
	_, _, _, err = f.l.Reserve(ids[1], admission.LaneGeneral, f.wall.Add(time.Hour))
	wantLedgerReason(t, "outstanding recovery liability", err, admission.ReasonPendingRecovery)
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("refused recovery reservation changed the ledger")
	}
	if _, _, err = f.l.Finish(a.Attempt.ID, admission.DispositionFailed); err != nil {
		t.Fatal(err)
	}
	if _, _, granted, err = f.l.Reserve(ids[1], admission.LaneGeneral, f.wall.Add(time.Hour)); err != nil || !granted {
		t.Fatalf("proven failure did not release prospective recovery room: %v %v", granted, err)
	}
}

func TestAdmissionLedgerRetryKeepsPaidRootIdentity(t *testing.T) {
	f := newLedgerFixture(t)
	old := f.published(evidenceSpec{cursor: "root-a"})
	added := f.published(evidenceSpec{cursor: "root-b"})
	if old < added {
		old, added = added, old
	}
	_, id := f.enqueue(f.request("192.0.2.10", old))
	_, a, _, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.l.Finish(a.Attempt.ID, admission.DispositionFailed); err != nil {
		t.Fatal(err)
	}
	before := f.snapshot()
	f.failNext("enqueue")
	if _, _, err = f.l.Enqueue(f.request("192.0.2.10", old, added)); err == nil {
		t.Fatal("injected coalesce committed")
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("failed coalesce changed paid roots")
	}
	if _, _, err = f.l.Enqueue(f.request("192.0.2.10", old, added)); err != nil {
		t.Fatal(err)
	}
	h, _ := f.historyEntry(id)
	if h.RootMask != 2 {
		t.Fatalf("paid root moved to the wrong position: %b", h.RootMask)
	}
	f.tickAt(f.wall.Add(admission.RetryBackoff(1)))
	if err = f.db.bolt.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte(admissionHistoryBucket)).Delete([]byte(id)) }); err != nil {
		t.Fatal(err)
	}
	before = f.snapshot()
	if _, _, _, err = f.l.Reserve(id, admission.LaneGeneral, time.Time{}); !isCorrupt(err) {
		t.Fatalf("missing retry history was recreated: %v", err)
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("refused retry changed missing history")
	}
}
