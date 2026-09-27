package store

import (
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

var oneEach = admission.ScheduleLimits{General: 10, Reserved: 10, Members: 1}

func (f *ledgerFixture) schedule(lim admission.ScheduleLimits) []admission.Pick {
	f.t.Helper()
	picks, err := f.l.Schedule(lim)
	if err != nil {
		f.t.Fatal(err)
	}
	return picks
}

func pickIDs(picks []admission.Pick) []admission.CandidateID {
	out := make([]admission.CandidateID, len(picks))
	for i, p := range picks {
		out[i] = p.ID
	}
	return out
}

// Scheduling rotates verified scopes with a persisted cursor: the turn
// order continues across calls and across a reopened ledger, and a pick
// stays queued until the engine reserves it.
func TestAdmissionLedgerScheduleRotatesScopes(t *testing.T) {
	f := newLedgerFixture(t)
	alice, bob := f.owner("alice"), f.owner("bob")
	a := f.fill(3, evidenceSpec{owner: alice})
	b := f.fill(1, evidenceSpec{owner: bob})
	first := f.schedule(oneEach)
	if len(first) != 1 || first[0].Lane != admission.LaneGeneral || first[0].Cost != 1 {
		t.Fatalf("first pick = %+v", first)
	}
	if c, _ := f.l.Candidate(first[0].ID); c.State != admission.StateQueued {
		t.Fatalf("a pick left the queue: %+v", c)
	}
	if _, _, _, err := f.l.Reserve(first[0].ID, first[0].Lane, f.wall.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenAdmissionLedger(f.db, f.reg)
	if err != nil {
		t.Fatal(err)
	}
	f.l = reopened
	f.tickAt(f.wall)
	second := f.schedule(oneEach)
	if len(second) != 1 || f.scopeOf(second[0].ID) == f.scopeOf(first[0].ID) {
		t.Fatalf("the persisted cursor did not pass the turn to the other scope: %v then %v", first, second)
	}
	all := f.schedule(admission.ScheduleLimits{General: 10, Members: 10})
	if len(all) != len(a)+len(b)-1 {
		t.Fatalf("remaining picks = %d", len(all))
	}
}

func (f *ledgerFixture) scopeOf(id admission.CandidateID) string {
	f.t.Helper()
	c, err := f.l.Candidate(id)
	if err != nil {
		f.t.Fatal(err)
	}
	return c.Scope.Key()
}

// Direct compromise takes the reserved lane; general work cannot use its
// budget.
func TestAdmissionLedgerScheduleLanes(t *testing.T) {
	f := newLedgerFixture(t)
	f.queued()
	direct := f.published(evidenceSpec{producer: f.mail, check: "mail_takeover", target: "192.0.2.11", cursor: "direct", severity: admission.SeverityCritical})
	_, directID := f.enqueue(f.request("192.0.2.11", direct))
	picks := f.schedule(admission.ScheduleLimits{Reserved: 5, Members: 5})
	if len(picks) != 1 || picks[0].ID != directID || picks[0].Lane != admission.LaneDirect {
		t.Fatalf("reserved picks = %+v", picks)
	}
}

// Dequeue revalidates each pick: a candidate whose roots fell below a raised
// policy floor ends and its turn goes to the next candidate in the same
// call. A candidate past its age-out ends before picking starts.
func TestAdmissionLedgerScheduleRevalidatesPicks(t *testing.T) {
	f, raise := newFloorLedger(t)
	highRoot := f.published(evidenceSpec{owner: f.owner("alice"), cursor: "high"})
	_, high := f.enqueue(f.request("192.0.2.10", highRoot))
	critical := f.published(evidenceSpec{owner: f.owner("bob"), target: "192.0.2.11", cursor: "critical", severity: admission.SeverityCritical})
	_, kept := f.enqueue(f.request("192.0.2.11", critical))
	f.schedule(admission.ScheduleLimits{Members: 1})
	raise(admission.SeverityCritical)
	picks := f.schedule(oneEach)
	if !reflect.DeepEqual(pickIDs(picks), []admission.CandidateID{kept}) {
		t.Fatalf("picks after the policy change = %v", pickIDs(picks))
	}
	if c, _ := f.l.Candidate(high); c.State != admission.StateRefused || c.Reason != admission.ReasonPolicy {
		t.Fatalf("pick below the new floor = %+v", c)
	}
	f.tickAt(ledgerT0.Add(admission.QueueAgeLimit))
	if picks = f.schedule(oneEach); len(picks) != 0 {
		t.Fatalf("an aged-out candidate was picked: %v", picks)
	}
	if c, _ := f.l.Candidate(kept); c.State != admission.StateDropped || c.Reason != admission.ReasonStale {
		t.Fatalf("aged-out candidate = %+v", c)
	}
}

// The first schedule of a reopened ledger checks every queued candidate,
// including those an upgrade could only mark.
func TestAdmissionLedgerScheduleRecoversAfterReopen(t *testing.T) {
	f := newLedgerFixture(t)
	id := f.queued()
	f.schemaOne()
	db := f.copyDatabase()
	l, err := OpenAdmissionLedger(db, f.reg)
	if err != nil {
		t.Fatal(err)
	}
	f.db, f.l = db, l
	_, err = f.l.Schedule(oneEach)
	wantLedgerReason(t, "schedule without a current reading", err, admission.ReasonEngineUnavailable)
	f.tickAt(f.wall)
	if picks := f.schedule(oneEach); !reflect.DeepEqual(pickIDs(picks), []admission.CandidateID{id}) {
		t.Fatalf("recovered picks = %v", picks)
	}
	if e, err := f.entry(id); err != nil || !e.Assessed() {
		t.Fatalf("recovered entry = %+v, %v", e, err)
	}
}

// A reopened ledger cannot know what changed while it was closed, so its
// first schedule checks every queued candidate, not only the picks: one
// below a raised policy floor ends even though another is picked.
func TestAdmissionLedgerScheduleChecksEveryCandidateAfterReopen(t *testing.T) {
	f, raise := newFloorLedger(t)
	high := f.queued()
	f.nextGeneration()
	critical := f.published(evidenceSpec{target: "192.0.2.11", cursor: "critical", severity: admission.SeverityCritical})
	_, kept := f.enqueue(f.request("192.0.2.11", critical))
	f.schedule(admission.ScheduleLimits{Members: 1})
	l, err := OpenAdmissionLedger(f.db, f.reg)
	if err != nil {
		t.Fatal(err)
	}
	f.l = l
	f.tickAt(f.wall)
	raise(admission.SeverityCritical)
	if picks := f.schedule(oneEach); !reflect.DeepEqual(pickIDs(picks), []admission.CandidateID{kept}) {
		t.Fatalf("picks = %v", pickIDs(picks))
	}
	if c, _ := f.l.Candidate(high); c.State != admission.StateRefused || c.Reason != admission.ReasonPolicy {
		t.Fatalf("unpicked candidate below the new floor = %+v", c)
	}
}

// A proven failure waits out its backoff before it can be picked again, and
// NextWake names the moment it becomes ready.
func TestAdmissionLedgerScheduleRetryTimer(t *testing.T) {
	f := newLedgerFixture(t)
	if _, ok, err := f.l.NextWake(); err != nil || ok {
		t.Fatalf("empty ledger wake = %v, %v", ok, err)
	}
	id := f.queued()
	if wake, ok, err := f.l.NextWake(); err != nil || !ok || !wake.Equal(ledgerT0.Add(admission.QueueAgeLimit)) {
		t.Fatalf("queued wake = %v %v, %v", wake, ok, err)
	}
	_, a, _, err := f.l.Reserve(id, admission.LaneGeneral, ledgerT0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.l.Finish(a.Attempt.ID, admission.DispositionFailed); err != nil {
		t.Fatal(err)
	}
	retry := ledgerT0.Add(admission.RetryBackoff(1))
	if wake, ok, err := f.l.NextWake(); err != nil || !ok || !wake.Equal(retry) {
		t.Fatalf("retry wake = %v %v, %v; want %v", wake, ok, err, retry)
	}
	if picks := f.schedule(oneEach); len(picks) != 0 {
		t.Fatalf("a waiting retry was picked: %v", picks)
	}
	f.tickAt(retry)
	if picks := f.schedule(oneEach); !reflect.DeepEqual(pickIDs(picks), []admission.CandidateID{id}) {
		t.Fatalf("ready retry picks = %v", picks)
	}
}

// A failed schedule changes nothing: not the cursors, not the candidates it
// would have ended.
func TestAdmissionLedgerScheduleIsAtomic(t *testing.T) {
	f := newLedgerFixture(t)
	f.fill(2, evidenceSpec{})
	f.tickAt(ledgerT0.Add(time.Minute))
	before := f.snapshot()
	f.failNext("schedule")
	if _, err := f.l.Schedule(oneEach); err == nil {
		t.Fatal("injected failure did not fail the schedule")
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("a failed schedule changed records")
	}
	if _, err := f.l.Schedule(admission.ScheduleLimits{}); err == nil {
		t.Fatal("a schedule without a member bound was accepted")
	}
	var damaged []byte
	if err := f.db.bolt.View(func(tx *bolt.Tx) error {
		damaged = append([]byte(nil), tx.Bucket([]byte(admissionQueueStateBucket)).Get(scheduleStateKey)...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	damaged[3] ^= 1
	if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(admissionQueueStateBucket)).Put(scheduleStateKey, damaged)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.l.Schedule(oneEach); !isCorrupt(err) {
		t.Fatalf("damaged scheduler state: %v", err)
	}
	if _, err := OpenAdmissionLedger(f.db, f.reg); !isCorrupt(err) {
		t.Fatalf("open with damaged scheduler state: %v", err)
	}
}

// Ready retries no longer have a retry wake; capacity readiness belongs
// to the budget owner. Ended and in-flight work have no queue wake.
func TestAdmissionLedgerNextWakeTracksPendingChanges(t *testing.T) {
	f := newLedgerFixture(t)
	id := f.queued()
	_, a, _, err := f.l.Reserve(id, admission.LaneGeneral, ledgerT0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, wakeErr := f.l.NextWake(); wakeErr != nil || ok {
		t.Fatalf("in-flight wake = %v, %v", ok, wakeErr)
	}
	if _, _, err = f.l.Finish(a.Attempt.ID, admission.DispositionFailed); err != nil {
		t.Fatal(err)
	}
	retry := ledgerT0.Add(admission.RetryBackoff(1))
	for _, at := range []time.Time{retry, retry.Add(time.Second)} {
		f.tickAt(at)
		f.schedule(admission.ScheduleLimits{Members: 1})
		if wake, ok, wakeErr := f.l.NextWake(); wakeErr != nil || !ok || !wake.Equal(ledgerT0.Add(time.Hour)) {
			t.Fatalf("ready retry wake = %v %v, %v", wake, ok, wakeErr)
		}
	}
	if _, err = f.l.Terminate(id, admission.ReasonProtected); err != nil {
		t.Fatal(err)
	}
	if _, ok, wakeErr := f.l.NextWake(); wakeErr != nil || ok {
		t.Fatalf("ended candidate wake = %v, %v", ok, wakeErr)
	}
}

// A wake calculation cannot use a missing or damaged clock checkpoint.
func TestAdmissionLedgerNextWakeRefusesDamagedClock(t *testing.T) {
	f := newLedgerFixture(t)
	f.queued()
	if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(admissionMetaBucket)).Put(admissionClockKey, []byte("damaged"))
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.l.NextWake(); !isCorrupt(err) {
		t.Fatalf("wake without a valid clock = %v", err)
	}
}

// Recovery state is published only after the candidate endings, counts
// and cursors commit. A failed first schedule must retry full recovery.
func TestAdmissionLedgerFailedScheduleRetriesRecovery(t *testing.T) {
	f, raise := newFloorLedger(t)
	high := f.queued()
	root := f.published(evidenceSpec{target: "192.0.2.11", cursor: "critical", severity: admission.SeverityCritical})
	_, kept := f.enqueue(f.request("192.0.2.11", root))
	raise(admission.SeverityCritical)
	before := f.snapshot()
	f.failNext("schedule")
	if _, err := f.l.Schedule(oneEach); err == nil {
		t.Fatal("injected failure did not fail recovery")
	}
	if f.l.revalidated || !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("failed recovery published state or changed records")
	}
	if picks := f.schedule(oneEach); !reflect.DeepEqual(pickIDs(picks), []admission.CandidateID{kept}) {
		t.Fatalf("recovery picks = %v", picks)
	}
	if c, err := f.l.Candidate(high); err != nil || c.State != admission.StateRefused || c.Reason != admission.ReasonPolicy {
		t.Fatalf("recovered ending = %+v, %v", c, err)
	}
	if f.count(ended(admission.ReasonPolicy, sshHigh)) != 1 || !f.l.revalidated {
		t.Fatal("successful recovery did not publish exactly one ending")
	}
}
