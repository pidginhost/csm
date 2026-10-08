package admission

import (
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"
)

type ingressFixture struct {
	t   *testing.T
	tp  testProducers
	in  *Ingress
	n   int
	rev int
}

func newIngressFixture(t *testing.T) *ingressFixture {
	t.Helper()
	tp := newTestProducers(t)
	tp.reg.Seal()
	in, err := NewIngress(tp.reg)
	if err != nil {
		t.Fatal(err)
	}
	return &ingressFixture{t: t, tp: tp, in: in}
}

type subSpec struct {
	p       *Producer
	check   string
	target  string
	cursor  string
	finding string
	sev     Severity
	owner   Owner
	age     time.Duration
}

// sub mints a fresh submission; each call observes a new event unless the
// cursor is given.
func (f *ingressFixture) sub(s subSpec) Submission {
	f.t.Helper()
	if s.p == nil {
		s.p, s.check = f.tp.ssh, "ssh_brute"
	}
	if s.target == "" {
		f.n++
		s.target = fmt.Sprintf("2001:db8::%x", f.n)
	}
	if s.cursor == "" {
		s.cursor = "c-" + s.target
	}
	if s.finding == "" {
		s.finding = "0123456789abcdef"
	}
	if s.sev == 0 {
		s.sev = SeverityHigh
	}
	target := mustAddr(f.t, s.target)
	claims, inv := ownerClaims(f.t, s.owner)
	e, err := s.p.Mint(EvidenceInput{
		Check: s.check, FindingID: s.finding, Severity: s.sev, Target: target, Claims: claims, Inventory: inv,
		Observation: ObservationRef{Stream: string(s.p.ID()), Cursor: s.cursor, Version: 1},
		ObservedAt:  t0.Add(-s.age), Parser: ParserRef{Name: "fixture", Version: 1},
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return Submission{Kind: KindBlockIP, Target: target, Evidence: e}
}

func (f *ingressFixture) publish(items ...QueueItem) {
	f.rev++
	f.in.Publish(&QueueSnapshot{Now: t0, Inventory: testInventory(f.t), Items: items, Revision: f.rev, Generation: 1})
}

func durable(n int, scope string, tier Tier) []QueueItem {
	out := make([]QueueItem, n)
	for i := range out {
		out[i] = QueueItem{Key: fmt.Sprintf("cand_%032x", i+1), Scope: scope, Partition: PartitionGeneral, Tier: tier, Queued: t0.Add(-time.Duration(n-i) * time.Second)}
	}
	return out
}

func (f *ingressFixture) held(s Submission) *pending {
	f.t.Helper()
	p := f.in.byEvidence[heldKeyOf(s)]
	if p == nil {
		f.t.Fatal("submission is not held")
	}
	return p
}

const aliceScope, bobScope = "acct:alice#1/address", "acct:bob#2/address"

func TestIngressWaitsForASnapshot(t *testing.T) {
	f := newIngressFixture(t)
	err := f.in.Submit(f.sub(subSpec{sev: SeverityCritical}))
	wantReason(t, "before a snapshot", err, ReasonEngineUnavailable)
	st := f.in.Stats()
	if st.Counters.Count(CountKey{Event: EventRefused, Reason: ReasonEngineUnavailable}) != 1 || st.CriticalLost != 1 || f.in.Len() != 0 {
		t.Fatalf("stats = %+v", st)
	}
	if _, err = NewIngress(newTestProducers(t).reg); err == nil {
		t.Fatal("an unsealed registry was accepted")
	}
}

// Held items leave in arrival order through Take and stay counted until the
// owner completes them; released ones can be taken again.
func TestIngressTakeReleaseComplete(t *testing.T) {
	f := newIngressFixture(t)
	f.publish()
	var subs []Submission
	for i := 0; i < 3; i++ {
		subs = append(subs, f.sub(subSpec{}))
		if err := f.in.Submit(subs[i]); err != nil {
			t.Fatal(err)
		}
	}
	taken := f.in.Take(2)
	if len(taken) != 2 || !taken[0].Submission.Evidence.Equal(subs[0].Evidence) || !taken[1].Submission.Evidence.Equal(subs[1].Evidence) {
		t.Fatalf("taken = %+v", taken)
	}
	if more := f.in.Take(5); len(more) != 1 || !more[0].Submission.Evidence.Equal(subs[2].Evidence) {
		t.Fatalf("second take = %+v", more)
	}
	f.in.Release(taken[1:])
	if again := f.in.Take(5); len(again) != 1 || !again[0].Submission.Evidence.Equal(subs[1].Evidence) {
		t.Fatalf("released item = %+v", again)
	}
	f.in.Complete(taken, f.rev+1, nil)
	if f.in.Len() != 1 || f.in.Stats().Accepted != 3 {
		t.Fatalf("after completion: %d held, %+v", f.in.Len(), f.in.Stats())
	}
}

func TestIngressRefusesInvalidSubmissions(t *testing.T) {
	f := newIngressFixture(t)
	f.publish()
	other, err := NewRegistry(testLookup)
	if err != nil {
		t.Fatal(err)
	}
	stranger, err := other.Register(ProducerSpec{ID: "stranger", Entry: EntryScan, Observation: ObservationLogCursor, Checks: []string{"ssh_brute"}})
	if err != nil {
		t.Fatal(err)
	}
	foreign := f.sub(subSpec{p: stranger, check: "ssh_brute"})
	wantReason(t, "foreign producer", f.in.Submit(foreign), ReasonPolicy)
	stale := f.sub(subSpec{age: 3 * time.Hour})
	wantReason(t, "stale evidence", f.in.Submit(stale), ReasonStale)
	moved := f.sub(subSpec{})
	moved.Target = mustAddr(t, "2001:db8::ffff")
	wantReason(t, "evidence for another target", f.in.Submit(moved), ReasonInvalid)
	unknown := f.sub(subSpec{})
	unknown.Kind = 0
	wantReason(t, "unknown kind", f.in.Submit(unknown), ReasonInvalid)
	st := f.in.Stats()
	for r, want := range map[Reason]uint64{ReasonPolicy: 1, ReasonStale: 1, ReasonInvalid: 2} {
		if got := st.Counters.Count(CountKey{Event: EventRefused, Reason: r}); got != want {
			t.Errorf("%s refusals = %d, want %d", r, got, want)
		}
	}
	if f.in.Len() != 0 || st.Accepted != 0 {
		t.Fatalf("refused submissions were held: %+v", st)
	}
}

// The same evidence again is merged into the held item; a later report under
// another finding is kept as a report link; a conflicting record is refused.
func TestIngressMergesRepeatedEvidence(t *testing.T) {
	f := newIngressFixture(t)
	f.publish()
	first := f.sub(subSpec{target: "2001:db8::1"})
	for _, s := range []Submission{first, first} {
		if err := f.in.Submit(s); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < MaxReportLinks+2; i++ {
		if err := f.in.Submit(f.sub(subSpec{target: "2001:db8::1", finding: fmt.Sprintf("%016x", i+1)})); err != nil {
			t.Fatal(err)
		}
	}
	p := f.held(first)
	if f.in.Len() != 1 || len(p.item.Reports) != MaxReportLinks || p.item.Dropped != 2 || f.in.Stats().Duplicates != MaxReportLinks+3 {
		t.Fatalf("merged item = %+v, stats %+v", p.item, f.in.Stats())
	}
	conflict := f.sub(subSpec{target: "2001:db8::1", sev: SeverityCritical})
	if err := f.in.Submit(conflict); !errors.Is(err, ErrEvidenceConflict) {
		t.Fatalf("conflicting record: %v", err)
	}
}

// A held record minted again after the inventory recreated its account
// differs from it only in the owner generation: a stale identity, not an
// invalid record.
func TestIngressRefusesARemintUnderAnotherOwnerAsAStaleIdentity(t *testing.T) {
	f := newIngressFixture(t)
	f.publish()
	first := f.sub(subSpec{target: "2001:db8::1", owner: testInventory(t).Resolve(Claim{ClaimAccount, "alice"})})
	if err := f.in.Submit(first); err != nil {
		t.Fatal(err)
	}
	remint := f.sub(subSpec{target: "2001:db8::1", owner: Owner{account: "alice", generation: 3}})
	if remint.Evidence.ID() != first.Evidence.ID() {
		t.Fatal("fixture does not remint the held observation")
	}
	err := f.in.Submit(remint)
	if r, _ := ReasonOf(err); r != ReasonStaleIdentity {
		t.Fatalf("remint under another owner: %v", err)
	}
	if n := f.in.Stats().Counters.Count(CountKey{Event: EventRefused, Reason: ReasonStaleIdentity}); n != 1 {
		t.Fatalf("stale identity refusals = %d", n)
	}
}

// Held items compete like queued ones: a scope below its share displaces the
// newest held item of a flooding scope, which is counted. Taken items hold
// their positions.
func TestIngressDisplacesHeldItems(t *testing.T) {
	f := newIngressFixture(t)
	alice, bob := testInventory(t).Resolve(Claim{ClaimAccount, "alice"}), testInventory(t).Resolve(Claim{ClaimAccount, "bob"})
	f.publish()
	var flood []Submission
	for i := 0; i < IngressPositions; i++ {
		flood = append(flood, f.sub(subSpec{owner: alice}))
		if err := f.in.Submit(flood[i]); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.in.Submit(f.sub(subSpec{owner: bob})); err != nil {
		t.Fatal(err)
	}
	if _, still := f.in.byEvidence[heldKeyOf(flood[len(flood)-1])]; still || f.in.Len() != IngressPositions {
		t.Fatalf("the newest flood item was not displaced: %d held", f.in.Len())
	}
	if n := f.in.Stats().Counters.Count(CountKey{Event: EventEnded, Reason: ReasonQueueOverflow, Class: ClassC2, Severity: SeverityHigh}); n != 1 {
		t.Fatalf("displacements counted = %d", n)
	}
	f.in.Take(IngressPositions)
	carol := f.sub(subSpec{target: "2001:db8::beef"})
	wantReason(t, "only taken items left", f.in.Submit(carol), ReasonQueueOverflow)
}

// An owner the snapshot's inventory cannot verify competes only for the
// host's general share, even with direct compromise evidence.
func TestIngressUnverifiedOwnerUsesHostGeneralShare(t *testing.T) {
	f := newIngressFixture(t)
	f.publish()
	alice := testInventory(t).Resolve(Claim{ClaimAccount, "alice"})
	retired := Owner{account: "alice", generation: 9}
	verified := f.sub(subSpec{p: f.tp.mail, check: "mail_takeover", owner: alice, sev: SeverityCritical})
	unverified := f.sub(subSpec{p: f.tp.mail, check: "mail_takeover", owner: retired, sev: SeverityCritical})
	for _, s := range []Submission{verified, unverified} {
		if err := f.in.Submit(s); err != nil {
			t.Fatal(err)
		}
	}
	if pos := f.held(verified).pos; pos.Partition != PartitionReserved || pos.Scope != aliceScope {
		t.Fatalf("verified direct compromise = %+v", pos)
	}
	if pos := f.held(unverified).pos; pos.Partition != PartitionGeneral || pos.Scope != "host/address" || pos.Eligible {
		t.Fatalf("unverified owner = %+v", pos)
	}
}

// Detectors submit concurrently with the owner taking, completing and
// publishing; every submission is either held, merged or counted.
func TestIngressConcurrentUse(t *testing.T) {
	f := newIngressFixture(t)
	f.publish()
	subs := make([]Submission, 400)
	for i := range subs {
		subs[i] = f.sub(subSpec{})
	}
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := w; i < len(subs); i += 4 {
				_ = f.in.Submit(subs[i])
			}
		}(w)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 50; i++ {
			f.in.Complete(f.in.Take(8), i+2, &QueueSnapshot{Now: t0, Inventory: testInventory(t), Generation: 1, Revision: i + 2})
			_ = f.in.Stats()
		}
	}()
	wg.Wait()
	<-done
	st := f.in.Stats()
	if st.Accepted+st.Counters.Count(CountKey{Event: EventRefused, Reason: ReasonQueueOverflow, Class: ClassC2, Severity: SeverityHigh}) != uint64(len(subs)) {
		t.Fatalf("accepted %d of %d", st.Accepted, len(subs))
	}
}

// Both allocations are full while the owner is stalled. Actual durable and
// held positions, including fixed work, remain within each partition.
func TestIngressTransferCapacityAndFairReclaim(t *testing.T) {
	f := newIngressFixture(t)
	alice, bob := testInventory(t).Resolve(Claim{ClaimAccount, "alice"}), testInventory(t).Resolve(Claim{ClaimAccount, "bob"})
	full := durable(PartitionGeneral.DurableCapacity(), aliceScope, c2h)
	for i := 0; i < PartitionReserved.DurableCapacity(); i++ {
		full = append(full, QueueItem{Key: fmt.Sprintf("reserved-%d", i), Scope: aliceScope, Partition: PartitionReserved, Tier: c3c, Eligible: true, Queued: t0.Add(-time.Hour)})
	}
	f.publish(full...)
	var general, reserved []Submission
	for i := 0; i < IngressPositions; i++ {
		general = append(general, f.sub(subSpec{owner: alice}))
		reserved = append(reserved, f.sub(subSpec{p: f.tp.mail, check: "mail_takeover", owner: alice, sev: SeverityCritical}))
		for _, sub := range []Submission{general[i], reserved[i]} {
			if err := f.in.Submit(sub); err != nil {
				t.Fatal(err)
			}
		}
	}
	assertBound := func() {
		t.Helper()
		if len(full)+f.in.Len() != QueueCapacity {
			t.Fatalf("actual combined positions = %d", len(full)+f.in.Len())
		}
		for p := PartitionGeneral; p < partitionEnd; p++ {
			if f.in.view.Count(p) != p.Capacity() {
				t.Fatalf("%s positions = %d", p, f.in.view.Count(p))
			}
		}
	}
	assertBound()
	for _, it := range full {
		if stored, ok := f.in.view.Item(it.Key); !ok || !stored.Fixed {
			t.Fatal("durable position became an ingress victim")
		}
	}
	wantReason(t, "equal tier kept", f.in.Submit(f.sub(subSpec{owner: alice})), ReasonQueueOverflow)
	fair := f.sub(subSpec{owner: bob})
	if err := f.in.Submit(fair); err != nil {
		t.Fatal(err)
	}
	if f.in.byEvidence[heldKeyOf(general[len(general)-1])] != nil {
		t.Fatal("newest held flood item was not reclaimed")
	}
	for _, it := range full {
		if _, ok := f.in.view.Item(it.Key); !ok {
			t.Fatal("durable victim was hidden before commit")
		}
	}
	for _, sub := range reserved {
		if f.in.byEvidence[heldKeyOf(sub)] == nil {
			t.Fatal("general work took reserved capacity")
		}
	}
	assertBound()
	taken := f.in.Take(QueueCapacity)
	wantReason(t, "taken items hold capacity", f.in.Submit(f.sub(subSpec{})), ReasonQueueOverflow)
	f.publish(full...)
	assertBound()
	f.in.Release(taken)
	assertBound()
	f.in.Complete(f.in.Take(QueueCapacity), f.rev+1, nil)
	if f.in.Len() != 0 {
		t.Fatal("committed items retained")
	}
	f.publish(full...)
	if err := f.in.Submit(f.sub(subSpec{owner: bob})); err != nil {
		t.Fatal(err)
	}
	if len(full)+f.in.Len() > QueueCapacity {
		t.Fatal("completion borrowed transfer capacity")
	}
}

// Publication never resets a locally advanced remainder cursor. Durable
// scopes have fixed positions; only an over-share held scope can lose one.
func TestIngressCursorSurvivesPublication(t *testing.T) {
	f := newIngressFixture(t)
	full := durable(PartitionGeneral.DurableCapacity(), aliceScope, c2h)
	accounts := map[string]uint64{}
	for i := range full {
		name := fmt.Sprintf("a%04d", i)
		accounts[name] = 1
		full[i].Scope = "acct:" + name + "#1/address"
	}
	for i := 0; i < IngressPositions; i++ {
		accounts[fmt.Sprintf("z%04d", i)] = 1
	}
	inv, err := NewInventory(accounts, nil)
	if err != nil {
		t.Fatal(err)
	}
	publish := func() {
		f.rev++
		f.in.Publish(&QueueSnapshot{Now: t0, Inventory: inv, Items: full, Revision: f.rev, Generation: 1})
	}
	publish()
	for i := 0; i < IngressPositions; i++ {
		owner := inv.Resolve(Claim{ClaimAccount, fmt.Sprintf("z%04d", i)})
		if err := f.in.Submit(f.sub(subSpec{owner: owner})); err != nil {
			t.Fatal(err)
		}
	}
	before := f.in.Checkpoint()
	incoming := f.sub(subSpec{})
	if err := f.in.Submit(incoming); err == nil {
		t.Fatal("first host turn unexpectedly had a share")
	}
	after := f.in.Checkpoint()
	if after.Cursors == before.Cursors {
		t.Fatal("refused turn did not advance")
	}
	publish()
	if got := f.in.Checkpoint(); got.Cursors != after.Cursors || got.Sequence != after.Sequence {
		t.Fatal("publication erased local progress")
	}
	admitted := false
	for i := 0; i < QueueCapacity*2; i++ {
		err := f.in.Submit(incoming)
		publish()
		if err == nil {
			admitted = true
			break
		}
	}
	if !admitted {
		t.Fatal("host scope starved across publications")
	}
	if f.in.Len() != IngressPositions {
		t.Fatal("reclaim changed transfer occupancy")
	}
	for _, it := range full {
		if _, ok := f.in.view.Item(it.Key); !ok {
			t.Fatal("protected durable position taken")
		}
	}
}

func TestIngressReportTailSurvivesHandoff(t *testing.T) {
	for _, release := range []bool{false, true} {
		t.Run(fmt.Sprint(release), func(t *testing.T) {
			f := newIngressFixture(t)
			f.publish()
			first := f.sub(subSpec{target: "2001:db8::1"})
			if err := f.in.Submit(first); err != nil {
				t.Fatal(err)
			}
			taken := f.in.Take(1)
			later := f.sub(subSpec{target: "2001:db8::1", finding: "0000000000000001"})
			if err := f.in.Submit(later); err != nil {
				t.Fatal(err)
			}
			if len(taken[0].Reports) != 0 {
				t.Fatal("handed-off report slice mutated")
			}
			if release {
				f.in.Release(taken)
			} else {
				f.in.Complete(taken, f.rev+1, nil)
			}
			if f.in.Len() != 1 {
				t.Fatal("accepted report disappeared")
			}
			again := f.in.Take(1)
			if len(again) != 1 || len(again[0].Reports) != 1 || again[0].Reports[0] != later.Evidence.FindingID() || again[0].ReportsOnly == release {
				t.Fatalf("retained tail = %+v", again)
			}
			f.in.Complete(again, f.rev+1, nil)
			if f.in.Len() != 0 {
				t.Fatal("acknowledged tail stayed held")
			}
		})
	}
}

func TestIngressSnapshotOrderAndEnvelope(t *testing.T) {
	f := newIngressFixture(t)
	f.publish()
	first := f.sub(subSpec{})
	if err := f.in.Submit(first); err != nil {
		t.Fatal(err)
	}
	moved := first
	moved.Target = mustAddr(t, "2001:db8::ffff")
	wantReason(t, "duplicate with another target", f.in.Submit(moved), ReasonInvalid)
	snapshot := *f.in.snap
	f.publish(durable(1, aliceScope, c2h)...)
	revision := f.in.revision
	f.in.Publish(&snapshot)
	if f.in.revision != revision || len(f.in.snap.Items) != 1 {
		t.Fatal("older snapshot replaced current occupancy")
	}
	wrong := *f.in.snap
	wrong.Generation++
	wrong.Revision++
	f.in.Publish(&wrong)
	if f.in.revision != revision || f.in.snap.Generation != 1 {
		t.Fatal("another generation replaced the snapshot")
	}
	tooMany := durable(PartitionGeneral.DurableCapacity()+1, aliceScope, c2h)
	f.publish(tooMany...)
	wantReason(t, "invalid capacity publication", f.in.Submit(f.sub(subSpec{})), ReasonEngineUnavailable)
}

func TestIngressOverflowTailSurvivesHandoff(t *testing.T) {
	f := newIngressFixture(t)
	f.publish()
	first := f.sub(subSpec{target: "2001:db8::1"})
	if err := f.in.Submit(first); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= MaxReportLinks; i++ {
		if err := f.in.Submit(f.sub(subSpec{target: "2001:db8::1", finding: fmt.Sprintf("%016x", i)})); err != nil {
			t.Fatal(err)
		}
	}
	taken := f.in.Take(1)
	if err := f.in.Submit(f.sub(subSpec{target: "2001:db8::1", finding: "ffffffffffffffff"})); err != nil {
		t.Fatal(err)
	}
	f.in.Complete(taken, f.rev+1, nil)
	if f.in.Len() != 1 {
		t.Fatal("accepted overflow disappeared")
	}
	tail := f.in.Take(1)
	if len(tail) != 1 || len(tail[0].Reports) != 0 || tail[0].Dropped != 1 || !tail[0].ReportsOnly {
		t.Fatalf("overflow tail = %+v", tail)
	}
	f.in.Release(tail)
	again := f.in.Take(1)
	if len(again) != 1 || again[0].Dropped != 1 {
		t.Fatal("release acknowledged overflow")
	}
	f.in.Complete(again, f.rev+1, nil)
	if f.in.Len() != 0 {
		t.Fatal("overflow acknowledgement retained work")
	}
}

// A committed drain without its replacement snapshot cannot keep using
// stale free positions. Publication explicitly resumes admission.
func TestIngressCompleteNeedsACurrentSnapshot(t *testing.T) {
	f := newIngressFixture(t)
	f.publish()
	if err := f.in.Submit(f.sub(subSpec{})); err != nil {
		t.Fatal(err)
	}
	old := *f.in.snap
	f.in.Complete(f.in.Take(1), f.rev+1, nil)
	f.in.Publish(&old)
	next := f.sub(subSpec{sev: SeverityCritical})
	wantReason(t, "missing committed snapshot", f.in.Submit(next), ReasonEngineUnavailable)
	if f.in.Len() != 0 || f.in.Stats().CriticalLost != 1 {
		t.Fatal("stale snapshot admitted or failed to count the refusal")
	}
	f.publish()
	if err := f.in.Submit(next); err != nil || f.in.Len() != 1 {
		t.Fatalf("publication did not resume admission: %v", err)
	}
}

func TestIngressPublicationRescopesRetiredHeldOwners(t *testing.T) {
	f := newIngressFixture(t)
	f.publish()
	alice := testInventory(t).Resolve(Claim{ClaimAccount, "alice"})
	first := f.sub(subSpec{owner: alice})
	if err := f.in.Submit(first); err != nil {
		t.Fatal(err)
	}
	taken := f.in.Take(1)
	retired, err := NewInventory(map[string]uint64{"bob": 2}, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.in.Publish(&QueueSnapshot{Now: t0, Inventory: retired, Revision: 2, Generation: 1})
	if got := f.held(first).pos.Scope; got != "host/address" {
		t.Fatalf("retired held owner kept its fairness scope: %s", got)
	}
	pos, ok := f.in.view.Item(taken[0].key)
	if !ok || !pos.Fixed || pos.Scope != "host/address" || f.in.Len() != 1 {
		t.Fatal("rescoping released or exposed a taken position")
	}
	f.in.Release(taken)
	if err = f.in.Submit(f.sub(subSpec{owner: alice})); err != nil {
		t.Fatal(err)
	}
	if len(f.in.view.parts[PartitionGeneral].scopes) != 1 {
		t.Fatal("retired held work and new arrivals split the host share")
	}
}

func TestIngressRestoredCheckpointIncludesPresnapshotRefusals(t *testing.T) {
	f := newIngressFixture(t)
	wantReason(t, "before restored snapshot", f.in.Submit(f.sub(subSpec{})), ReasonEngineUnavailable)
	counters, err := (QueueCounters{}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	previous := IngressCheckpoint{Generation: 1, Sequence: 3, Counters: counters}
	f.in.Publish(&QueueSnapshot{Now: t0, Inventory: testInventory(t), Revision: 1, Generation: 1, Checkpoint: &previous})
	cp := f.in.Checkpoint()
	if err = cp.Validate(&previous, 1); err != nil {
		t.Fatalf("pre-snapshot refusal could not be checkpointed: %v", err)
	}
	if cp.Sequence != previous.Sequence+1 || f.in.Stats().Counters.Count(CountKey{Event: EventRefused, Reason: ReasonEngineUnavailable}) != 1 {
		t.Fatal("restoring a checkpoint erased pre-snapshot decisions")
	}
}

// A snapshot whose checkpoint cannot be decoded changes nothing: no
// generation, cursor or sequence from it, and admission stays closed.
func TestIngressDamagedCheckpointChangesNothing(t *testing.T) {
	f := newIngressFixture(t)
	before := f.in.Checkpoint()
	damaged := IngressCheckpoint{Generation: 1, Sequence: 3, Cursors: QueueCursors{General: "in:00000000000000000001"}, Counters: []byte("damaged")}
	f.in.Publish(&QueueSnapshot{Now: t0, Inventory: testInventory(t), Revision: 1, Generation: 1, Checkpoint: &damaged})
	if got := f.in.Checkpoint(); !reflect.DeepEqual(got, before) {
		t.Fatalf("damaged checkpoint applied: %+v, want %+v", got, before)
	}
	wantReason(t, "damaged checkpoint", f.in.Submit(f.sub(subSpec{})), ReasonEngineUnavailable)
}

// The ingress judges evidence at the snapshot's admission time advanced by
// the monotonic time elapsed since its publication: an idle owner does not
// make fresh evidence look future-dated, and early evidence still is.
func TestIngressAssessesAtElapsedSnapshotTime(t *testing.T) {
	f := newIngressFixture(t)
	mono := time.Unix(1, 0)
	f.in.mono = func() time.Time { return mono }
	f.publish()
	fresh := f.sub(subSpec{age: -2 * time.Second})
	wantReason(t, "evidence ahead of the elapsed admission time", f.in.Submit(fresh), ReasonInvalid)
	mono = mono.Add(2 * time.Second)
	if err := f.in.Submit(fresh); err != nil {
		t.Fatalf("evidence observed after the snapshot was refused: %v", err)
	}
}

// Publishing no snapshot closes admission until a usable one arrives.
func TestIngressPublishNilClosesAdmission(t *testing.T) {
	f := newIngressFixture(t)
	f.publish()
	if err := f.in.Submit(f.sub(subSpec{})); err != nil {
		t.Fatal(err)
	}
	f.in.Publish(nil)
	wantReason(t, "withdrawn snapshot", f.in.Submit(f.sub(subSpec{})), ReasonEngineUnavailable)
	f.publish()
	if err := f.in.Submit(f.sub(subSpec{})); err != nil {
		t.Fatalf("a new snapshot did not reopen admission: %v", err)
	}
}

// A malformed snapshot closes admission rather than widen the transfer
// allocation: a repeated key, an empty key or an empty scope refuses it.
func TestIngressRefusesMalformedSnapshots(t *testing.T) {
	tier := Tier{ClassC2, SeverityHigh}
	item := durable(1, aliceScope, tier)[0]
	noKey, noScope := item, item
	noKey.Key, noScope.Scope = "", ""
	for name, items := range map[string][]QueueItem{
		"repeated key": {item, item},
		"empty key":    {noKey},
		"empty scope":  {noScope},
	} {
		t.Run(name, func(t *testing.T) {
			f := newIngressFixture(t)
			f.publish(items...)
			wantReason(t, name, f.in.Submit(f.sub(subSpec{})), ReasonEngineUnavailable)
		})
	}
}

// Ruling 9: the ingress reports when it stopped admitting and how many
// Critical arrivals it refused since, so a failed snapshot is loud. A
// usable snapshot clears both.
func TestIngressHealthReportsAStoppedIngress(t *testing.T) {
	f := newIngressFixture(t)
	if h := f.in.Health(); h.Admitting || h.StoppedSince.IsZero() || h.CriticalRefused != 0 {
		t.Fatalf("new ingress = %+v", h)
	}
	mono := time.Unix(100, 0)
	f.in.mono = func() time.Time { return mono }
	wantReason(t, "critical", f.in.Submit(f.sub(subSpec{sev: SeverityCritical})), ReasonEngineUnavailable)
	wantReason(t, "high", f.in.Submit(f.sub(subSpec{})), ReasonEngineUnavailable)
	if h := f.in.Health(); h.CriticalRefused != 1 {
		t.Fatalf("after refusals = %+v", h)
	}
	f.publish()
	if h := f.in.Health(); h != (IngressHealth{Admitting: true}) {
		t.Fatalf("after a snapshot = %+v", h)
	}
	if err := f.in.Submit(f.sub(subSpec{sev: SeverityCritical})); err != nil {
		t.Fatal(err)
	}
	mono = mono.Add(time.Minute)
	f.in.Publish(nil)
	mono = mono.Add(time.Minute)
	wantReason(t, "stopped", f.in.Submit(f.sub(subSpec{sev: SeverityCritical})), ReasonEngineUnavailable)
	if h := f.in.Health(); h.Admitting || !h.StoppedSince.Equal(time.Unix(160, 0)) || h.CriticalRefused != 1 {
		t.Fatalf("after withdrawal = %+v", h)
	}
	f.in.Publish(nil)
	if h := f.in.Health(); !h.StoppedSince.Equal(time.Unix(160, 0)) || h.CriticalRefused != 1 {
		t.Fatalf("a second withdrawal restarted the stop: %+v", h)
	}
	f.publish()
	item := durable(1, aliceScope, Tier{ClassC2, SeverityHigh})[0]
	f.in.Publish(&QueueSnapshot{Now: t0, Inventory: testInventory(t), Items: []QueueItem{item, item}, Revision: f.rev + 1, Generation: 1})
	if h := f.in.Health(); h.Admitting || !h.StoppedSince.Equal(mono) {
		t.Fatalf("after a malformed snapshot = %+v", h)
	}
}
