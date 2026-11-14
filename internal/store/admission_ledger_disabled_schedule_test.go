package store

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// Disabled responses end without a reservation. Neither live scheduling
// nor challenge preview selection may wait for history or recovery space.
func TestAdmissionLedgerDisabledPicksNeedNoCapacity(t *testing.T) {
	for _, kind := range []admission.Kind{admission.KindBlockIP, admission.KindChallenge} {
		for _, preview := range []bool{false, true} {
			t.Run(kind.String()+"/"+map[bool]string{false: "live", true: "preview"}[preview], func(t *testing.T) {
				f := newLedgerFixture(t)
				f.begin()
				req := f.request("192.0.2.10", f.published(evidenceSpec{}))
				req.Kind = kind
				_, id := f.enqueue(req)
				f.leaveCeilingCredit(0, 0)
				f.adjustStorage(func(s *admission.StorageState) {
					s.General.Credit, s.Reserved.Credit = 0, 0
					leaveRecoveryRoom(s, 0)
				})
				before, storage, ceiling, notices := f.candidateOf(id), f.storageState(), f.ceilingState(), f.notices()
				if err := f.l.RefuseDisabled(func(admission.Candidate, func() []admission.Evidence) bool { return false }); err != nil {
					t.Fatal(err)
				}
				c := f.candidateOf(id)
				if c.State != admission.StateRefused || c.Reason != admission.ReasonDisabled || c.Attempts != 0 || c.Transitions != before.Transitions+1 {
					t.Fatalf("disabled candidate = %+v", c)
				}
				selectFn := func() ([]admission.Pick, error) { return f.l.Schedule(fullSchedule, nil) }
				if preview {
					selectFn = func() ([]admission.Pick, error) { return f.l.SchedulePreview(nil) }
				}
				picks, err := selectFn()
				if err != nil || len(picks) != 0 {
					t.Fatalf("disabled work reached selection: %+v, %v", picks, err)
				}
				after := f.storageState()
				if after.General != storage.General || after.Reserved != storage.Reserved || after.Recovery != storage.Recovery || f.ceilingState() != ceiling || !reflect.DeepEqual(f.notices(), notices) {
					t.Fatal("refusal changed capacity or notices")
				}
			})
		}
	}
}

// Ending queued work cannot affect an unresolved attempt on the same target.
func TestAdmissionLedgerDisabledPickIgnoresRecoveryHold(t *testing.T) {
	f := newLedgerFixture(t)
	unknown, a := f.admitted(time.Hour)
	if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.l.Finish(a.Attempt.ID, admission.DispositionUnknown); err != nil {
		t.Fatal(err)
	}
	f.nextGeneration()
	id := f.queued()
	before, notices := f.candidateOf(id), f.notices()
	ceiling, unknownBefore := f.ceilingState(), f.candidateOf(unknown)
	if err := f.l.RefuseDisabled(func(c admission.Candidate, _ func() []admission.Evidence) bool {
		if c.State != admission.StateQueued {
			t.Fatalf("policy consulted for %s", c.State)
		}
		return false
	}); err != nil {
		t.Fatal(err)
	}
	c := f.candidateOf(id)
	if c.State != admission.StateRefused || c.Reason != admission.ReasonDisabled || c.Transitions != before.Transitions+1 {
		t.Fatalf("disabled candidate = %+v", c)
	}
	if !reflect.DeepEqual(f.notices(), notices) || !reflect.DeepEqual(f.candidateOf(unknown), unknownBefore) || f.ceilingState() != ceiling {
		t.Fatal("refusal changed notices, the unresolved attempt or its charge")
	}
	intents, err := f.l.UnresolvedIntents()
	if err != nil || len(intents) != 1 || intents[0].Action != a.Attempt.ID {
		t.Fatalf("refusal changed the recovery hold: %+v, %v", intents, err)
	}
}

// A failed refusal transaction changes nothing, and a retry counts each
// disabled response once while leaving allowed work byte-for-byte intact.
func TestAdmissionLedgerDisabledRefusalIsAtomic(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	ids := f.criticalArrivals("192.0.2.10", "192.0.2.11", "192.0.2.12")
	allowed := f.candidateOf(ids[2])
	allows := func(c admission.Candidate, _ func() []admission.Evidence) bool {
		return c.Key.Target == allowed.Key.Target
	}
	// Refusal must raise schema 10 even without a prior schema-13 write.
	// Episode rows permit a deliberately lowered schema in this fixture.
	f.setSchema(admissionSchemaVersion)
	var reported []laterRefusal
	f.l.ObserveRefusals(func(c admission.Candidate, err error, at time.Time) {
		reported = append(reported, laterRefusal{key: c.Key, err: err, at: at})
	})
	before := f.snapshot()
	f.failNext("disabled")
	if err := f.l.RefuseDisabled(allows); err == nil || !reflect.DeepEqual(f.snapshot(), before) {
		t.Fatalf("failed refusal changed the ledger: %v", err)
	}
	if len(reported) != 0 {
		t.Fatalf("failed refusal reported %+v", reported)
	}
	if err := f.l.RefuseDisabled(allows); err != nil {
		t.Fatal(err)
	}
	for _, id := range ids[:2] {
		if c := f.candidateOf(id); c.State != admission.StateRefused || c.Reason != admission.ReasonDisabled || c.Attempts != 0 {
			t.Fatalf("disabled candidate = %+v", c)
		}
	}
	if !reflect.DeepEqual(f.candidateOf(ids[2]), allowed) || f.schema() != admissionSchemaDisabled || f.countOf(admission.EventEnded, admission.ReasonDisabled, f.entryTier(ids[2])) != 2 {
		t.Fatal("refusal changed allowed work or recorded the wrong schema or count")
	}
	after := f.snapshot()
	if err := f.l.RefuseDisabled(allows); err != nil || !reflect.DeepEqual(f.snapshot(), after) {
		t.Fatalf("repeated refusal changed the ledger: %v", err)
	}
	if len(reported) != 2 {
		t.Fatalf("reported %+v, want each disabled candidate exactly once", reported)
	}
	seen := map[admission.CandidateKey]bool{}
	for _, r := range reported {
		reason, ok := admission.ReasonOf(r.err)
		if !ok || reason != admission.ReasonDisabled || admission.CauseOf(r.err) != 0 || !r.at.Equal(f.wall) || seen[r.key] {
			t.Fatalf("wrong or duplicate disabled refusal: %+v", r)
		}
		seen[r.key] = true
	}
	for _, id := range ids[:2] {
		if !seen[f.candidateOf(id).Key] {
			t.Fatalf("disabled candidate %s was not reported", id)
		}
	}
	if _, err := f.l.Terminate(ids[2], admission.ReasonDisabled); err != nil {
		t.Fatal(err)
	}
	if len(reported) != 2 {
		t.Fatalf("explicit termination was also reported: %+v", reported)
	}
}

// Reserved work is past the opt-out check: refusal leaves it and still ends
// the queued work beside it.
func TestAdmissionLedgerDisabledLeavesReservedWork(t *testing.T) {
	f := newLedgerFixture(t)
	reserved, _ := f.admitted(time.Hour)
	f.nextGeneration()
	id := f.queued()
	before := f.candidateOf(reserved)
	if before.State != admission.StateReserved {
		t.Fatalf("fixture candidate is %s, want reserved", before.State)
	}
	if err := f.l.RefuseDisabled(func(admission.Candidate, func() []admission.Evidence) bool { return false }); err != nil {
		t.Fatal(err)
	}
	if got := f.candidateOf(reserved); !reflect.DeepEqual(got, before) {
		t.Fatalf("reserved candidate = %+v, want %+v", got, before)
	}
	if c := f.candidateOf(id); c.State != admission.StateRefused || c.Reason != admission.ReasonDisabled {
		t.Fatalf("queued candidate = %+v", c)
	}
}

// A turn whose policy still allows every queued response commits nothing:
// the refusal pass runs before each selection and must not cost a write.
func TestAdmissionLedgerDisabledCommitsNothingWhenAllAllowed(t *testing.T) {
	f := newLedgerFixture(t)
	id := f.queued()
	before := f.db.WriteTxID()
	if err := f.l.RefuseDisabled(func(admission.Candidate, func() []admission.Evidence) bool { return true }); err != nil {
		t.Fatal(err)
	}
	if got := f.db.WriteTxID(); got != before {
		t.Fatalf("an allowed queue committed %d writes", got-before)
	}
	if c := f.candidateOf(id); c.State != admission.StateQueued {
		t.Fatalf("allowed candidate = %+v", c)
	}
	if err := f.l.RefuseDisabled(func(admission.Candidate, func() []admission.Evidence) bool { return false }); err != nil {
		t.Fatal(err)
	}
	if c := f.candidateOf(id); c.State != admission.StateRefused || f.db.WriteTxID() == before {
		t.Fatalf("a disabled candidate was not ended: %+v", c)
	}
}

// Refusal cannot lower a schema already raised by episode placement.
func TestAdmissionLedgerDisabledRefusalKeepsEpisodeSchema(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	ids := f.criticalArrivals("192.0.2.10")
	if f.schema() != admissionSchemaEpisodeElapsed {
		t.Fatal("arrival did not raise the episode schema")
	}
	if err := f.l.RefuseDisabled(func(admission.Candidate, func() []admission.Evidence) bool { return false }); err != nil {
		t.Fatal(err)
	}
	if f.schema() != admissionSchemaEpisodeElapsed || f.candidateOf(ids[0]).Reason != admission.ReasonDisabled {
		t.Fatal("refusal lost the schema or disabled reason")
	}
}

// The refusal pass hands each queued candidate's root evidence to the
// policy on demand, so a policy can test what the roots attest.
func TestAdmissionLedgerDisabledHandsTheQueuedRoots(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	root := f.published(evidenceSpec{})
	_, id := f.enqueue(f.request("192.0.2.10", root))
	var seen []admission.EvidenceID
	if err := f.l.RefuseDisabled(func(c admission.Candidate, roots func() []admission.Evidence) bool {
		for _, e := range roots() {
			seen = append(seen, e.ID())
		}
		return false
	}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(seen, []admission.EvidenceID{root}) {
		t.Fatalf("roots handed = %v, want %v", seen, root)
	}
	if c := f.candidateOf(id); c.State != admission.StateRefused || c.Reason != admission.ReasonDisabled {
		t.Fatalf("candidate = %+v", c)
	}
}

// The loader hands each candidate its own roots, as often as the policy
// asks, inside the refusal pass's one transaction. A pass that refuses
// nothing commits nothing; refusing one candidate ends only that one,
// silently.
func TestAdmissionLedgerDisabledHandsEachCandidateItsRoots(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	first := f.published(evidenceSpec{target: "192.0.2.21", cursor: "offset=21"})
	second := f.published(evidenceSpec{target: "192.0.2.22", cursor: "offset=22"})
	_, firstID := f.enqueue(f.request("192.0.2.21", first))
	_, secondID := f.enqueue(f.request("192.0.2.22", second))
	want := map[admission.CandidateID]admission.EvidenceID{firstID: first, secondID: second}
	check := func(refuse admission.CandidateID) {
		t.Helper()
		seen := map[admission.CandidateID]int{}
		if err := f.l.RefuseDisabled(func(c admission.Candidate, roots func() []admission.Evidence) bool {
			id, err := c.ID()
			if err != nil {
				t.Error(err)
				return true
			}
			for range 2 {
				r := roots()
				if len(r) != 1 || r[0].ID() != want[id] {
					t.Errorf("candidate %s got roots %v, want %s", id, r, want[id])
				}
			}
			seen[id]++
			return id != refuse
		}); err != nil {
			t.Fatal(err)
		}
		wantSeen := map[admission.CandidateID]int{firstID: 1, secondID: 1}
		if !reflect.DeepEqual(seen, wantSeen) {
			t.Fatalf("policy calls = %v, want %v", seen, wantSeen)
		}
	}
	before, notices := f.db.WriteTxID(), f.notices()
	check("")
	if f.db.WriteTxID() != before || f.candidateOf(firstID).State != admission.StateQueued || f.candidateOf(secondID).State != admission.StateQueued {
		t.Fatal("a pass that refused nothing changed the ledger")
	}
	sibling := f.candidateOf(secondID)
	check(firstID)
	if c := f.candidateOf(firstID); c.State != admission.StateRefused || c.Reason != admission.ReasonDisabled {
		t.Fatalf("refused candidate = %+v", c)
	}
	if !reflect.DeepEqual(f.candidateOf(secondID), sibling) || !reflect.DeepEqual(f.notices(), notices) {
		t.Fatal("refusing one candidate changed its sibling or raised a notice")
	}
}

// An unreadable root gives the policy no roots, which alone refuses
// nothing; the queue's own revalidation still reports the damage.
func TestAdmissionLedgerDisabledUnreadableRootIsNotARefusal(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	root := f.published(evidenceSpec{target: "192.0.2.23", cursor: "offset=23"})
	_, id := f.enqueue(f.request("192.0.2.23", root))
	if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(admissionEvidenceBucket)).Put([]byte(root), []byte("damaged"))
	}); err != nil {
		t.Fatal(err)
	}
	var got []admission.Evidence
	calls := 0
	if err := f.l.RefuseDisabled(func(_ admission.Candidate, roots func() []admission.Evidence) bool {
		calls++
		got = roots()
		return true
	}); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("policy calls = %d, want 1", calls)
	}
	if got != nil {
		t.Fatalf("damaged roots handed as %v, want nil", got)
	}
	if c := f.candidateOf(id); c.State != admission.StateQueued {
		t.Fatalf("damaged candidate ended by the refusal pass: %+v", c)
	}
	if err := f.l.Revalidate(); !errors.Is(err, admission.ErrCorruptRecord) {
		t.Fatalf("revalidation of a damaged root = %v, want ErrCorruptRecord", err)
	}
}
