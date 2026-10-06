package store

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

func (f *ledgerFixture) arrival(s evidenceSpec) admission.Arrival {
	f.t.Helper()
	e := f.mint(s)
	target := s.target
	if target == "" {
		target = "192.0.2.10"
	}
	req := f.request(target, e.ID())
	// The ledger assigns arrivals their episode and generation.
	req.Episode, req.Generation = admission.EpisodeID{}, 0
	return admission.Arrival{Request: req, Evidence: e}
}

func (f *ledgerFixture) begin() admission.IngressState {
	f.t.Helper()
	s, err := f.l.BeginIngress()
	if err != nil {
		f.t.Fatal(err)
	}
	return s
}

// An ingress generation left open when the daemon stopped was interrupted:
// its unpersisted items are lost, and the next generation records that.
func TestAdmissionLedgerIngressGenerations(t *testing.T) {
	f := newLedgerFixture(t)
	_, _, err := f.l.EnqueueGroup([]admission.Arrival{f.arrival(evidenceSpec{})}, nil)
	wantLedgerReason(t, "group without a generation", err, admission.ReasonEngineUnavailable)
	if s := f.begin(); s != (admission.IngressState{Generation: 1, Open: true}) {
		t.Fatalf("first generation = %+v", s)
	}
	if _, _, err = f.l.EnqueueGroup([]admission.Arrival{f.arrival(evidenceSpec{})}, nil); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenAdmissionLedger(f.db, f.reg)
	if err != nil {
		t.Fatal(err)
	}
	f.l = reopened
	if s := f.begin(); s != (admission.IngressState{Generation: 2, Open: true, Interrupted: 1, Resumed: 2}) {
		t.Fatalf("after an unclean stop = %+v", s)
	}
	if err = f.l.EndIngress(); err != nil {
		t.Fatal(err)
	}
	if err = f.l.EndIngress(); err != nil {
		t.Fatal(err)
	}
	if s := f.begin(); s != (admission.IngressState{Generation: 3, Open: true, Interrupted: 1}) {
		t.Fatalf("after a clean stop = %+v", s)
	}
}

// One group decides each arrival on its own: new candidates, coalesced
// repeats, a later report of stored evidence, a conflicting record and a
// stale one. Refusals are counted; the rest commits together.
func TestAdmissionLedgerEnqueueGroup(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	first := f.arrival(evidenceSpec{finding: "00000000000000a1"})
	again := first
	again.Reports = []string{"00000000000000a2"}
	remint := f.arrival(evidenceSpec{finding: "00000000000000a3"})
	conflict := f.arrival(evidenceSpec{finding: "00000000000000a4", severity: admission.SeverityCritical})
	stale := f.arrival(evidenceSpec{target: "192.0.2.11", cursor: "old", age: 3 * time.Hour})
	other := f.arrival(evidenceSpec{target: "192.0.2.12", cursor: "other"})
	results, revision, err := f.l.EnqueueGroup([]admission.Arrival{first, again, remint, conflict, stale, other}, nil)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := f.l.QueueSnapshot()
	if err != nil || revision == 0 || snap.Revision != revision {
		t.Fatalf("group revision=%d snapshot=%+v err=%v", revision, snap, err)
	}
	if !results[0].Created || results[1].Created || results[1].Err != nil || results[2].Created || results[2].Err != nil || results[1].Candidate != results[0].Candidate {
		t.Fatalf("new, repeat and later report = %+v", results[:3])
	}
	if !errors.Is(results[3].Err, admission.ErrEvidenceConflict) {
		t.Fatalf("conflicting record = %+v", results[3])
	}
	wantLedgerReason(t, "stale arrival", results[4].Err, admission.ReasonStale)
	if !results[5].Created {
		t.Fatalf("other target = %+v", results[5])
	}
	links, dropped, err := f.l.Reports(first.Evidence.ID())
	if err != nil || !reflect.DeepEqual(links, []string{"00000000000000a2", "00000000000000a3"}) || dropped != 0 {
		t.Fatalf("report links = %v %d, %v", links, dropped, err)
	}
	if f.count(admission.CountKey{Event: admission.EventRefused, Reason: admission.ReasonInvalid, Class: admission.ClassC2, Severity: admission.SeverityCritical}) != 1 ||
		f.count(admission.CountKey{Event: admission.EventRefused, Reason: admission.ReasonStale}) != 1 {
		t.Fatal("refused arrivals were not counted")
	}
	var s admission.IngressState
	if err = f.db.bolt.View(func(tx *bolt.Tx) error {
		s, err = loadIngressState(tx)
		return err
	}); err != nil || s.Persisted != 6 {
		t.Fatalf("persisted = %+v, %v", s, err)
	}
	if _, _, err = f.l.EnqueueGroup(make([]admission.Arrival, admission.MaxArrivalGroup+1), nil); err == nil {
		t.Fatal("an oversized group was accepted")
	}
}

// A failed group changes nothing: no evidence, candidate or count survives.
func TestAdmissionLedgerEnqueueGroupIsAtomic(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	before := f.snapshot()
	f.failNext("group")
	if result, revision, err := f.l.EnqueueGroup([]admission.Arrival{f.arrival(evidenceSpec{}), f.arrival(evidenceSpec{target: "192.0.2.11", cursor: "x", age: 3 * time.Hour})}, nil); err == nil || revision != 0 || result != nil {
		t.Fatalf("failed group exposed acknowledgement: result=%+v revision=%d err=%v", result, revision, err)
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("a failed group changed records")
	}
}

// The snapshot lists every live position as the queue holds it, including
// in-flight work that cannot be displaced, and needs a current reading.
func TestAdmissionLedgerQueueSnapshot(t *testing.T) {
	f := newLedgerFixture(t)
	queued := f.queued()
	f.nextGeneration()
	flight := f.published(evidenceSpec{target: "192.0.2.11", cursor: "flight"})
	_, flightID := f.enqueue(f.request("192.0.2.11", flight))
	if _, _, _, err := f.l.Reserve(flightID, admission.LaneGeneral, ledgerT0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	snap, err := f.l.QueueSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if !snap.Now.Equal(ledgerT0) || snap.Inventory != f.l.Inventory() || len(snap.Items) != 2 {
		t.Fatalf("snapshot = %+v", snap)
	}
	for _, it := range snap.Items {
		want := admission.CandidateID(it.Key) == flightID
		if it.Fixed != want || it.Partition != admission.PartitionGeneral || it.Tier != sshHigh || it.Scope != "host/address" {
			t.Fatalf("item %+v (queued %s)", it, queued)
		}
	}
	reopened, err := OpenAdmissionLedger(f.db, f.reg)
	if err != nil {
		t.Fatal(err)
	}
	_, err = reopened.QueueSnapshot()
	wantLedgerReason(t, "snapshot without a current reading", err, admission.ReasonEngineUnavailable)
}

func (f *ledgerFixture) ingress() *admission.Ingress {
	f.t.Helper()
	in, err := admission.NewIngress(f.reg)
	if err != nil {
		f.t.Fatal(err)
	}
	snap, err := f.l.QueueSnapshot()
	if err != nil {
		f.t.Fatal(err)
	}
	in.Publish(snap)
	return in
}

func (f *ledgerFixture) submission(s evidenceSpec) admission.Submission {
	f.t.Helper()
	a := f.arrival(s)
	return admission.Submission{Kind: a.Request.Kind, Target: a.Request.Target, Evidence: a.Evidence}
}

func (f *ledgerFixture) requestFor(s admission.Submission) (admission.CandidateRequest, error) {
	req := f.request("192.0.2.10", s.Evidence.ID())
	req.Kind, req.Target = s.Kind, s.Target
	req.Episode, req.Generation = admission.EpisodeID{}, 0
	return req, nil
}

// Draining persists held items as one group, forgets them and installs the
// ledger's next snapshot, so the ingress counts them as durable work.
func TestIngressDrainPersistsGroups(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	in := f.ingress()
	for _, target := range []string{"192.0.2.10", "192.0.2.11", "192.0.2.12"} {
		if err := in.Submit(f.submission(evidenceSpec{target: target, cursor: target})); err != nil {
			t.Fatal(err)
		}
	}
	report, err := in.Drain(f.l, 10, f.requestFor)
	if err != nil || report != (admission.DrainReport{Queued: 3}) || in.Len() != 0 {
		t.Fatalf("drain = %+v, %v; %d held", report, err, in.Len())
	}
	if n := f.candidateCount(); n != 3 {
		t.Fatalf("candidates = %d", n)
	}
	if report, err = in.Drain(f.l, 10, f.requestFor); err != nil || report != (admission.DrainReport{}) {
		t.Fatalf("empty drain = %+v, %v", report, err)
	}
}

// When the ledger cannot admit yet the items go back to the ingress, and a
// later drain persists them.
func TestIngressDrainWaitsForTheLedger(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	in := f.ingress()
	if err := in.Submit(f.submission(evidenceSpec{})); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenAdmissionLedger(f.db, f.reg)
	if err != nil {
		t.Fatal(err)
	}
	f.l = reopened
	_, err = in.Drain(f.l, 10, f.requestFor)
	wantLedgerReason(t, "drain before a current reading", err, admission.ReasonEngineUnavailable)
	if in.Len() != 1 || f.candidateCount() != 0 {
		t.Fatalf("items were not returned: %d held", in.Len())
	}
	f.tickAt(f.wall)
	if report, err := in.Drain(f.l, 10, f.requestFor); err != nil || report.Queued != 1 {
		t.Fatalf("drain after a reading = %+v, %v", report, err)
	}
}

// A damaged record fails its group; each arrival is then persisted alone,
// so only the arrival that touches the damage is lost.
func TestIngressDrainIsolatesADamagedArrival(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	// The hit arrival's episode leads to a queued candidate whose queue
	// entry is gone.
	damaged := f.arrive(f.arrival(evidenceSpec{cursor: "damaged"}))[0].Candidate
	if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(admissionQueueBucket)).Delete([]byte(damaged))
	}); err != nil {
		t.Fatal(err)
	}
	in := f.ingress()
	hit := f.submission(evidenceSpec{cursor: "hit"})
	fine := f.submission(evidenceSpec{target: "192.0.2.20", cursor: "fine"})
	for _, s := range []admission.Submission{hit, fine} {
		if err := in.Submit(s); err != nil {
			t.Fatal(err)
		}
	}
	report, err := in.Drain(f.l, 10, f.requestFor)
	if !isCorrupt(err) || report != (admission.DrainReport{Queued: 1, Failed: 1}) || in.Len() != 0 {
		t.Fatalf("drain = %+v, %v; %d held", report, err, in.Len())
	}
	// Only the damaged arrival failed: the rest committed, so admission
	// stays open and the error says the damage was isolated.
	if !errors.Is(err, admission.ErrArrivalsIsolated) || !in.Health().Admitting {
		t.Fatalf("isolated damage: %v, admitting %v", err, in.Health().Admitting)
	}
}

// Damage that every transaction meets belongs to no arrival: the drain
// returns every item to the ingress, counts none lost, and a drain after
// the repair persists them.
func TestIngressDrainReleasesWorkOnSharedDamage(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	in := f.ingress()
	for _, target := range []string{"192.0.2.10", "192.0.2.11"} {
		if err := in.Submit(f.submission(evidenceSpec{target: target, cursor: target})); err != nil {
			t.Fatal(err)
		}
	}
	before, err := in.Stats().Counters.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var good []byte
	setCounters := func(data []byte) {
		t.Helper()
		if updateErr := f.db.bolt.Update(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte(admissionQueueStateBucket))
			if good == nil {
				good = append([]byte(nil), b.Get(queueCountersKey)...)
			}
			return b.Put(queueCountersKey, data)
		}); updateErr != nil {
			t.Fatal(updateErr)
		}
	}
	setCounters([]byte("damaged"))
	report, err := in.Drain(f.l, 10, f.requestFor)
	if !isCorrupt(err) || report != (admission.DrainReport{}) || in.Len() != 2 {
		t.Fatalf("drain = %+v, %v; %d held", report, err, in.Len())
	}
	after, err := in.Stats().Counters.MarshalBinary()
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("shared damage was counted as lost work: %v", err)
	}
	setCounters(good)
	if report, err = in.Drain(f.l, 10, f.requestFor); err != nil || report != (admission.DrainReport{Queued: 2}) || in.Len() != 0 {
		t.Fatalf("drain after repair = %+v, %v; %d held", report, err, in.Len())
	}
}

// Submitting never waits for the ledger: it completes while the owner holds
// the ledger's write lock.
func TestIngressSubmitDoesNotWaitForTheLedger(t *testing.T) {
	f := newLedgerFixture(t)
	in := f.ingress()
	s := f.submission(evidenceSpec{})
	f.l.mu.Lock()
	defer f.l.mu.Unlock()
	done := make(chan error, 1)
	go func() { done <- in.Submit(s) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Submit waited for the ledger")
	}
}

type ingressHandoffHook struct {
	admission.Ledger
	before func()
	after  func()
}

func (h ingressHandoffHook) EnqueueGroup(a []admission.Arrival, cp *admission.IngressCheckpoint) ([]admission.ArrivalResult, int, error) {
	if h.before != nil {
		h.before()
	}
	out, revision, err := h.Ledger.EnqueueGroup(a, cp)
	if err == nil && h.after != nil {
		h.after()
	}
	return out, revision, err
}

// A report submitted after Take survives both rollback and acknowledgement.
// Overflow is persisted exactly once, and the tail never builds a new episode.
func TestIngressDrainRetainsReportTailAndOverflow(t *testing.T) {
	for _, rollback := range []bool{false, true} {
		t.Run(fmt.Sprint(rollback), func(t *testing.T) {
			f := newLedgerFixture(t)
			f.begin()
			in := f.ingress()
			first := f.submission(evidenceSpec{})
			if err := in.Submit(first); err != nil {
				t.Fatal(err)
			}
			before := f.snapshot()
			hook := ingressHandoffHook{Ledger: f.l, before: func() {
				for i := 1; i <= admission.MaxReportLinks+3; i++ {
					sub := f.submission(evidenceSpec{finding: fmt.Sprintf("%016x", i)})
					if err := in.Submit(sub); err != nil {
						t.Fatal(err)
					}
				}
			}}
			if rollback {
				f.failNext("group")
			}
			report, err := in.Drain(hook, 1, f.requestFor)
			if rollback {
				if err == nil || !reflect.DeepEqual(before, f.snapshot()) || in.Len() != 1 {
					t.Fatalf("rollback = %+v %v held=%d", report, err, in.Len())
				}
				report, err = in.Drain(f.l, 1, f.requestFor)
			} else if in.Len() != 1 {
				t.Fatal("acknowledgement erased concurrent reports")
			}
			if err != nil || report.Queued != 1 {
				t.Fatalf("first commit = %+v %v", report, err)
			}
			tail, err := in.Drain(f.l, 1, func(admission.Submission) (admission.CandidateRequest, error) {
				t.Fatal("report tail rebuilt a candidate")
				return admission.CandidateRequest{}, nil
			})
			wantCoalesced := 1
			if rollback {
				wantCoalesced = 0
			}
			if err != nil || in.Len() != 0 || f.candidateCount() != 1 || tail.Coalesced != wantCoalesced || tail.Refused != 0 {
				t.Fatalf("tail commit = %+v %v held=%d", tail, err, in.Len())
			}
			links, dropped, err := f.l.Reports(first.Evidence.ID())
			if err != nil || len(links) != admission.MaxReportLinks || dropped != 3 {
				t.Fatalf("reports=%v dropped=%d err=%v", links, dropped, err)
			}
			if _, err = in.Drain(f.l, 1, f.requestFor); err != nil {
				t.Fatal(err)
			}
			_, again, err := f.l.Reports(first.Evidence.ID())
			if err != nil || again != dropped {
				t.Fatal("overflow checkpoint replayed")
			}
		})
	}
}

func TestIngressCheckpointRollbackAndReopen(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	in := f.ingress()
	for i := 0; i < admission.IngressPositions; i++ {
		if err := in.Submit(f.submission(evidenceSpec{target: fmt.Sprintf("2001:db8::%x", i+1), cursor: fmt.Sprint(i)})); err != nil {
			t.Fatal(err)
		}
	}
	wantLedgerReason(t, "full ingress", in.Submit(f.submission(evidenceSpec{target: "192.0.2.20", cursor: "overflow"})), admission.ReasonQueueOverflow)
	cp := in.Checkpoint()
	if cp.Cursors.General == "" {
		t.Fatal("refused decision lost its cursor")
	}
	before := f.snapshot()
	f.failNext("group")
	if _, err := in.Drain(f.l, 0, f.requestFor); err == nil || !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("failed checkpoint changed durable state")
	}
	snap, err := f.l.QueueSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	in.Publish(snap)
	if got := in.Checkpoint(); !reflect.DeepEqual(got, cp) {
		t.Fatal("failed drain snapshot erased local progress")
	}
	if _, err = in.Drain(f.l, 0, f.requestFor); err != nil {
		t.Fatal(err)
	}
	snap, err = f.l.QueueSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(snap.Checkpoint, &cp) {
		t.Fatalf("checkpoint = %+v, want %+v", snap.Checkpoint, cp)
	}
	committed := f.snapshot()
	if _, _, err = f.l.EnqueueGroup(nil, &cp); err != nil || !reflect.DeepEqual(committed, f.snapshot()) {
		t.Fatal("checkpoint replay changed records")
	}
	bad := cp
	bad.Sequence--
	if _, _, err = f.l.EnqueueGroup(nil, &bad); !errors.Is(err, admission.ErrTransitionConflict) || !reflect.DeepEqual(committed, f.snapshot()) {
		t.Fatal("stale checkpoint committed")
	}
	reopened, err := OpenAdmissionLedger(f.db, f.reg)
	if err != nil {
		t.Fatal(err)
	}
	f.l = reopened
	if _, err = in.Drain(f.l, 0, f.requestFor); err == nil {
		t.Fatal("reopened ledger admitted before Tick")
	}
	f.tickAt(f.wall)
	f.begin()
	recovered := f.ingress().Checkpoint()
	if recovered.Cursors != cp.Cursors || !bytes.Equal(recovered.Counters, cp.Counters) || recovered.Generation != cp.Generation+1 || recovered.Sequence != 0 {
		t.Fatalf("recovered checkpoint = %+v", recovered)
	}
	before = f.snapshot()
	if _, _, err = f.l.EnqueueGroup(nil, &cp); !errors.Is(err, admission.ErrTransitionConflict) || !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("old generation checkpoint committed")
	}
}

func TestIngressDrainBoundsActualPositions(t *testing.T) {
	if admission.MaxArrivalGroup != admission.IngressPositions {
		t.Fatal("transfer space cannot hold one maximum arrival group")
	}
	f := newLedgerFixture(t)
	f.begin()
	general := f.fill(admission.PartitionGeneral.DurableCapacity(), evidenceSpec{owner: f.owner("alice")})
	f.fill(admission.PartitionReserved.DurableCapacity(), evidenceSpec{producer: f.mail, check: "mail_takeover", owner: f.owner("alice"), severity: admission.SeverityCritical})
	in := f.ingress()
	for i := 0; i < admission.IngressPositions; i++ {
		sub := f.submission(evidenceSpec{owner: f.owner("alice"), target: fmt.Sprintf("2001:db8:1::%x", i+1), cursor: fmt.Sprint(i)})
		if err := in.Submit(sub); err != nil {
			t.Fatal(err)
		}
		sub = f.submission(evidenceSpec{producer: f.mail, check: "mail_takeover", owner: f.owner("alice"), severity: admission.SeverityCritical, target: fmt.Sprintf("2001:db8:2::%x", i+1), cursor: fmt.Sprint(i)})
		if err := in.Submit(sub); err != nil {
			t.Fatal(err)
		}
	}
	bound := func() {
		t.Helper()
		snap, err := f.l.QueueSnapshot()
		if err != nil {
			t.Fatal(err)
		}
		if actual := len(snap.Items) + in.Len(); actual > admission.QueueCapacity {
			t.Fatalf("actual combined positions = %d", actual)
		}
		for _, p := range []admission.Partition{admission.PartitionGeneral, admission.PartitionReserved} {
			n := 0
			for _, it := range snap.Items {
				if it.Partition == p {
					n++
				}
			}
			if n != p.DurableCapacity() {
				t.Fatalf("durable %s positions = %d", p, n)
			}
		}
	}
	bound()
	newcomer := f.submission(evidenceSpec{owner: f.owner("bob"), target: "192.0.2.50", cursor: "new"})
	if err := in.Submit(newcomer); err != nil {
		t.Fatal(err)
	}
	if c, err := f.l.Candidate(newest(general)); err != nil || c.State != admission.StateQueued {
		t.Fatal("ingress displaced a durable victim before commit")
	}
	before := f.snapshot()
	f.failNext("group")
	if _, err := in.Drain(f.l, admission.MaxArrivalGroup, f.requestFor); err == nil || !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("failed transfer changed records")
	}
	bound()
	snap, err := f.l.QueueSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	in.Publish(snap)
	bound()
	// Keep draining both partitions; the new scope may be in the second group.
	hook := ingressHandoffHook{Ledger: f.l, after: bound}
	for remaining := in.Len(); remaining > 0; remaining -= admission.MaxArrivalGroup {
		if _, err = in.Drain(hook, admission.MaxArrivalGroup, f.requestFor); err != nil {
			t.Fatal(err)
		}
	}
	if in.Len() != 0 {
		t.Fatal("bounded drains did not complete held work")
	}
	row, _ := f.episodeAt("192.0.2.50")
	line, _ := row.Line(admission.KindBlockIP)
	if c, err := f.l.Candidate(line.Candidate); err != nil || c.State != admission.StateQueued || c.Scope.Owner != f.owner("bob") {
		t.Fatalf("new scope made no progress: %+v %v", c, err)
	}
	bound()
}

func TestIngressRequestFailureRetainsWork(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	in := f.ingress()
	if err := in.Submit(f.submission(evidenceSpec{})); err != nil {
		t.Fatal(err)
	}
	before := f.snapshot()
	_, err := in.Drain(f.l, 1, func(admission.Submission) (admission.CandidateRequest, error) {
		return admission.CandidateRequest{}, errors.New("request unavailable")
	})
	if err == nil || in.Len() != 1 || !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("request failure discarded work")
	}
	if _, err = in.Drain(f.l, 1, f.requestFor); err != nil || in.Len() != 0 {
		t.Fatal("released work could not retry")
	}
}

func TestAdmissionLedgerIngressStateRefusesDamage(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(fmt.Sprint(missing), func(t *testing.T) {
			f := newLedgerFixture(t)
			if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
				b := tx.Bucket([]byte(admissionQueueStateBucket))
				if missing {
					return b.Delete(ingressStateKey)
				}
				return b.Put(ingressStateKey, []byte("damaged"))
			}); err != nil {
				t.Fatal(err)
			}
			before := f.snapshot()
			if _, err := OpenAdmissionLedger(f.db, f.reg); !isCorrupt(err) || !reflect.DeepEqual(before, f.snapshot()) {
				t.Fatal("damaged ingress state opened or was repaired")
			}
		})
	}
}

func TestAdmissionLedgerUpgradeInitializesIngress(t *testing.T) {
	f := newLedgerFixture(t)
	f.queued()
	f.schemaOne()
	db := f.copyDatabase()
	upgraded, err := OpenAdmissionLedger(db, f.reg)
	if err != nil {
		t.Fatal(err)
	}
	f.db, f.l = db, upgraded
	if _, err = f.l.QueueSnapshot(); err == nil {
		t.Fatal("upgrade admitted before Tick")
	}
	f.tickAt(f.wall)
	f.begin()
	if _, err = f.l.Schedule(admission.ScheduleLimits{Members: 1}); err != nil {
		t.Fatal(err)
	}
	in := f.ingress()
	if err = in.Submit(f.submission(evidenceSpec{target: "192.0.2.20", cursor: "upgraded"})); err != nil {
		t.Fatal(err)
	}
	if report, err := in.Drain(f.l, 1, f.requestFor); err != nil || report.Queued != 1 {
		t.Fatalf("upgraded ingress = %+v %v", report, err)
	}
}

func TestAdmissionLedgerIngressGenerationIsAtomic(t *testing.T) {
	f := newLedgerFixture(t)
	for _, op := range []string{"begin", "end"} {
		before := f.snapshot()
		f.failNext("ingress")
		var err error
		if op == "begin" {
			_, err = f.l.BeginIngress()
		} else {
			err = f.l.EndIngress()
		}
		if err == nil || !reflect.DeepEqual(before, f.snapshot()) {
			t.Fatal("failed generation change committed")
		}
		if op == "begin" {
			f.begin()
		} else if err = f.l.EndIngress(); err != nil {
			t.Fatal(err)
		}
	}
}

// A report-only tail must not count the already-acknowledged primary remint
// again when that finding exceeded the stored link bound.
func TestIngressReportTailDoesNotReplayPrimaryOverflow(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	original := f.arrival(evidenceSpec{})
	for i := 1; i <= admission.MaxReportLinks; i++ {
		original.Reports = append(original.Reports, fmt.Sprintf("%016x", i))
	}
	if _, _, err := f.l.EnqueueGroup([]admission.Arrival{original}, nil); err != nil {
		t.Fatal(err)
	}
	in := f.ingress()
	remint := f.submission(evidenceSpec{finding: "ffffffffffffff01"})
	if err := in.Submit(remint); err != nil {
		t.Fatal(err)
	}
	hook := ingressHandoffHook{Ledger: f.l, before: func() {
		if err := in.Submit(f.submission(evidenceSpec{finding: "ffffffffffffff02"})); err != nil {
			t.Fatal(err)
		}
	}}
	if _, err := in.Drain(hook, 1, f.requestFor); err != nil {
		t.Fatal(err)
	}
	_, dropped, err := f.l.Reports(original.Evidence.ID())
	if err != nil || dropped != 1 || in.Len() != 1 {
		t.Fatalf("initial overflow = %d held=%d err=%v", dropped, in.Len(), err)
	}
	if _, err = in.Drain(f.l, 1, f.requestFor); err != nil {
		t.Fatal(err)
	}
	links, dropped, err := f.l.Reports(original.Evidence.ID())
	if err != nil || dropped != 2 || len(links) != admission.MaxReportLinks || in.Len() != 0 {
		t.Fatalf("tail overflow = %d held=%d err=%v", dropped, in.Len(), err)
	}
}

// Refused ingress turns survive publication, a failed drain, a committed
// checkpoint and reopen. Admission eventually reaches a reclaimable scope.
func TestIngressRotatingScopesAcrossDrainAndReopen(t *testing.T) {
	f := newLedgerFixture(t)
	names := make([]string, admission.PartitionGeneral.Capacity())
	for i := range names {
		names[i] = fmt.Sprintf("scope%04d", i)
	}
	f.refresh(names, nil)
	f.begin()
	var group []admission.Arrival
	for i, name := range names[:admission.PartitionGeneral.DurableCapacity()] {
		group = append(group, f.arrival(evidenceSpec{owner: f.owner(name), target: fmt.Sprintf("2001:db8:3::%x", i+1), cursor: name}))
		if len(group) == admission.MaxArrivalGroup || i == admission.PartitionGeneral.DurableCapacity()-1 {
			result, _, err := f.l.EnqueueGroup(group, nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range result {
				if r.Err != nil || !r.Created {
					t.Fatalf("initial durable scope = %+v", r)
				}
			}
			group = nil
		}
	}
	in := f.ingress()
	for i, name := range names[admission.PartitionGeneral.DurableCapacity():] {
		if err := in.Submit(f.submission(evidenceSpec{owner: f.owner(name), target: fmt.Sprintf("2001:db8:4::%x", i+1), cursor: name})); err != nil {
			t.Fatal(err)
		}
	}
	host := f.submission(evidenceSpec{target: "192.0.2.60", cursor: "host"})
	wantLedgerReason(t, "host without a remainder share", in.Submit(host), admission.ReasonQueueOverflow)
	cp := in.Checkpoint()
	before := f.snapshot()
	f.failNext("group")
	if _, err := in.Drain(f.l, 0, f.requestFor); err == nil || !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("failed refused-only drain changed state")
	}
	if _, err := in.Drain(f.l, 0, f.requestFor); err != nil {
		t.Fatal(err)
	}
	snap, err := f.l.QueueSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(snap.Checkpoint, &cp) {
		t.Fatal("refused scope cursor was not durable")
	}
	admitted := false
	for i := 0; i < admission.QueueCapacity*2; i++ {
		in.Publish(snap)
		if err = in.Submit(host); err == nil {
			admitted = true
			break
		}
	}
	if !admitted || in.Len() != admission.IngressPositions {
		t.Fatal("new scope did not reclaim bounded transfer space")
	}
	// Checkpoint the last local decisions, then model loss of the memory
	// generation by reopening; its durable cursor must remain unchanged.
	cp = in.Checkpoint()
	if _, err = in.Drain(f.l, 0, f.requestFor); err != nil {
		t.Fatal(err)
	}
	before = f.snapshot()
	reopened, err := OpenAdmissionLedger(f.db, f.reg)
	if err != nil {
		t.Fatal(err)
	}
	f.l = reopened
	if _, err = f.l.QueueSnapshot(); err == nil || !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("reopen admitted without a reading")
	}
	f.tickAt(f.wall)
	state := f.begin()
	in = f.ingress()
	if got := in.Checkpoint(); got.Cursors != cp.Cursors || !bytes.Equal(got.Counters, cp.Counters) || state.Interrupted != 1 {
		t.Fatal("reopen lost cursor or interruption accounting")
	}
	// Memory loss frees transfer space, but never changes durable occupancy.
	if err = in.Submit(host); err != nil {
		t.Fatal(err)
	}
	for tries := 0; tries < admission.QueueCapacity; tries++ {
		result, err := in.Drain(f.l, 1, f.requestFor)
		if err != nil {
			t.Fatal(err)
		}
		if result.Queued == 1 {
			return
		}
		if err = in.Submit(host); err != nil {
			t.Fatal(err)
		}
	}
	t.Fatal("new scope could not reach durable admission after reopen")
}
func TestAdmissionLedgerReportOnlyRefusalKeepsItsTier(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	original := f.arrival(evidenceSpec{})
	if _, _, err := f.l.EnqueueGroup([]admission.Arrival{original}, nil); err != nil {
		t.Fatal(err)
	}
	conflict := f.arrival(evidenceSpec{severity: admission.SeverityCritical})
	conflict.ReportsOnly = true
	conflict.Request = admission.CandidateRequest{}
	result, _, err := f.l.EnqueueGroup([]admission.Arrival{conflict}, nil)
	if err != nil || len(result) != 1 || !errors.Is(result[0].Err, admission.ErrEvidenceConflict) {
		t.Fatalf("report-only refusal = %+v %v", result, err)
	}
	key := admission.CountKey{Event: admission.EventRefused, Reason: admission.ReasonInvalid, Class: admission.ClassC2, Severity: admission.SeverityCritical}
	if got := f.count(key); got != 1 {
		t.Fatalf("Critical report-only refusals = %d", got)
	}
}

// A closed nonzero generation with a current clock must refuse groups before
// any record write; a fresh-generation codec check cannot mask this guard.
func TestAdmissionLedgerClosedIngressRefusesGroups(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	if err := f.l.EndIngress(); err != nil {
		t.Fatal(err)
	}
	before := f.snapshot()
	_, _, err := f.l.EnqueueGroup([]admission.Arrival{f.arrival(evidenceSpec{})}, nil)
	wantLedgerReason(t, "closed ingress generation", err, admission.ReasonEngineUnavailable)
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("closed generation admitted work")
	}
}

type failingQueueSnapshot struct {
	admission.Ledger
}

func (failingQueueSnapshot) QueueSnapshot() (*admission.QueueSnapshot, error) {
	return nil, errors.New("snapshot unavailable")
}

// A successful commit followed by a snapshot failure is not retried and
// cannot expose the old free positions to a detector.
func TestIngressDrainSnapshotFailureStopsAdmission(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	in := f.ingress()
	if err := in.Submit(f.submission(evidenceSpec{})); err != nil {
		t.Fatal(err)
	}
	report, err := in.Drain(failingQueueSnapshot{f.l}, 1, f.requestFor)
	if err == nil || report != (admission.DrainReport{Queued: 1}) || in.Len() != 0 || f.candidateCount() != 1 {
		t.Fatalf("committed drain = %+v, %v; held=%d", report, err, in.Len())
	}
	next := f.submission(evidenceSpec{target: "192.0.2.11", cursor: "next"})
	wantLedgerReason(t, "stale snapshot", in.Submit(next), admission.ReasonEngineUnavailable)
	snap, err := f.l.QueueSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	in.Publish(snap)
	if err = in.Submit(next); err != nil {
		t.Fatal(err)
	}
}

// A generation that begins after an interrupted one is marked, so doctor
// can warn that the lost arrivals make counts lower bounds; the next clean
// generation clears it.
func TestAdmissionLedgerMarksTheGenerationAfterAnInterruption(t *testing.T) {
	f := newLedgerFixture(t)
	if _, err := f.l.BeginIngress(); err != nil {
		t.Fatal(err)
	}
	s, err := f.l.BeginIngress()
	if err != nil || s.Resumed != 2 || s.Interrupted != 1 {
		t.Fatalf("after an interruption = %+v, %v", s, err)
	}
	if st := f.l.Status(); st.Ingress.Resumed != 2 || st.Ingress.Generation != 2 {
		t.Fatalf("status = %+v", st.Ingress)
	}
	if err = f.l.EndIngress(); err != nil {
		t.Fatal(err)
	}
	if s, err = f.l.BeginIngress(); err != nil || s.Resumed != 0 || s.Generation != 3 {
		t.Fatalf("after a clean close = %+v, %v", s, err)
	}
	if rows := admission.DoctorChecks(ptr(f.l.Status()), &admission.IngressHealth{Admitting: true}, f.wall); rows[1].Status != admission.DoctorOK {
		t.Fatalf("doctor after a clean close = %+v", rows[1])
	}
}

func ptr[T any](v T) *T { return &v }
