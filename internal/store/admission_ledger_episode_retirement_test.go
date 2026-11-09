package store

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// A wall step cannot make the history paying for a live episode available
// to the scheduler. Its wake must wait for the elapsed boundary too.
func TestAdmissionLedgerRetainedEpisodeHistoryBudget(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	old := f.arrive(f.arrival(evidenceSpec{cursor: "original"}))[0].Candidate
	f.finishArrival(old, f.wall.Add(time.Hour), admission.DispositionApplied)
	f.ackAll()
	row, _ := f.episodeAt("192.0.2.10")
	f.stepWall(admission.HistoryRetention, time.Second)
	f.tickAt(f.wall.Add(time.Second))
	id := f.arrive(f.arrival(evidenceSpec{target: "192.0.2.11", cursor: "waiting"}))[0].Candidate
	general, _ := admission.HistoryLanes()
	f.adjustStorage(func(s *admission.StorageState) { s.General.Used = general })
	want := f.wall.Add(row.EndElapsed - f.ceilingState().Elapsed)
	before := f.snapshot()
	wake, ok, err := f.l.NextWake(nil)
	if err != nil || !ok || !wake.Equal(want) {
		t.Errorf("retained history wake = %v %v %v, want %v", wake, ok, err, want)
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("wake changed retained history")
	}
	if picks := f.schedule(oneEach); len(picks) != 0 {
		t.Errorf("scheduled history that cannot be retired: %+v", picks)
	}
	f.tickAt(want.Add(-time.Nanosecond))
	if picks := f.schedule(oneEach); len(picks) != 0 {
		t.Errorf("scheduled before the elapsed boundary: %+v", picks)
	}
	f.tickAt(want)
	if picks := f.schedule(oneEach); len(picks) != 1 || picks[0].ID != id {
		t.Fatalf("picks at the elapsed boundary: %+v", picks)
	}
	if _, _, _, err = f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, found := f.historyEntry(old); found {
		t.Fatal("reservation did not retire expired history")
	}
}

// A batch of retained episodes must not hide later eligible history from
// every tick. Failed ticks must leave the continuation at its last commit.
func TestAdmissionLedgerRetainedEpisodesDoNotStarveRetirement(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	var retained []admission.CandidateID
	for i := 0; i < retirementsPerTick; i++ {
		ip := fmt.Sprintf("192.0.2.%d", i+1)
		id := f.arrive(f.arrival(evidenceSpec{target: ip, cursor: ip}))[0].Candidate
		f.finishArrival(id, f.wall.Add(time.Hour), admission.DispositionApplied)
		retained = append(retained, id)
		f.tickAt(f.wall.Add(10 * time.Second))
	}
	ended := f.applied(time.Minute)
	f.ackAll()
	f.stepWall(admission.HistoryTarget, time.Second)
	if _, found := f.historyEntry(ended); !found {
		t.Fatal("first batch exceeded its work limit")
	}
	before := f.snapshot()
	f.failNext("tick")
	reading := admission.ClockReading{Wall: f.wall.Add(time.Second), BootID: ledgerBoot, SinceBoot: f.since + time.Second}
	if _, err := f.l.Tick(reading); err == nil {
		t.Fatal("injected tick failure committed")
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("failed tick changed history")
	}
	f.tickAt(reading.Wall)
	if _, found := f.historyEntry(ended); found {
		t.Fatal("retained episodes starved later eligible history")
	}
	for _, id := range retained {
		if _, found := f.historyEntry(id); !found {
			t.Fatalf("retired a live episode's history: %s", id)
		}
	}
	f.tickAt(f.wall.Add(time.Hour))
	f.tickAt(f.wall.Add(time.Second))
	for _, id := range retained {
		if _, found := f.historyEntry(id); found {
			t.Fatalf("expired history was not revisited: %s", id)
		}
	}
}

// Subnet episodes need the same elapsed retention as address episodes.
// Otherwise retirement tries to persist an unsupported unreferenced row
// and aborts every tick that reaches it.
func TestAdmissionLedgerRetainsSubnetHistoryUntilBothClocksPass(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	prefix, err := admission.CanonicalPrefix("192.0.2.0/24", admission.Caps{IPv6: true})
	if err != nil {
		t.Fatal(err)
	}
	e, err := f.ssh.Mint(admission.EvidenceInput{
		Check: "ssh_brute", FindingID: "0123456789abcdef", Severity: admission.SeverityHigh, Attribution: ledgerKind("ssh_brute"),
		Observation: admission.ObservationRef{Stream: "log:sshd_log", Cursor: "subnet", Version: 1},
		ObservedAt:  f.wall, Parser: admission.ParserRef{Name: "fixture", Version: 1}, Target: prefix,
	})
	if err != nil {
		t.Fatal(err)
	}
	arrival := f.arrive(admission.Arrival{Request: admission.CandidateRequest{Kind: admission.KindBlockSubnet, Target: prefix, Primary: e.ID()}, Evidence: e})[0]
	if arrival.Err != nil || !arrival.Created {
		t.Fatalf("subnet arrival: %+v", arrival)
	}
	f.finishArrival(arrival.Candidate, f.wall.Add(time.Hour), admission.DispositionApplied)
	f.ackAll()
	f.stepWall(admission.HistoryTarget, time.Second)
	f.tickAt(f.wall.Add(time.Second))
	if _, found := f.historyEntry(arrival.Candidate); !found {
		t.Fatal("wall expiry discarded live subnet history")
	}
	if _, err = OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatal(err)
	}
	f.tickAt(f.wall.Add(time.Hour))
	if _, found := f.historyEntry(arrival.Candidate); found {
		t.Fatal("expired subnet history was not retired")
	}
	if err = f.db.bolt.View(func(tx *bolt.Tx) error {
		_, found, loadErr := loadEpisode(tx, prefix.Key())
		if found {
			t.Error("expired subnet episode was not retired")
		}
		return loadErr
	}); err != nil {
		t.Fatal(err)
	}
}

// Only an answered address block line can keep a verified episode row
// without candidate references. Forgetting the last candidate of any other
// verified episode, such as a subnet's, before both ends pass removes the
// row as before instead of failing every later write that reaches it.
func TestAdmissionLedgerForgetLineDropsAnUnretainableRow(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	prefix, err := admission.CanonicalPrefix("192.0.2.0/24", admission.Caps{IPv6: true})
	if err != nil {
		t.Fatal(err)
	}
	e, err := f.ssh.Mint(admission.EvidenceInput{
		Check: "ssh_brute", FindingID: "0123456789abcdef", Severity: admission.SeverityHigh, Attribution: ledgerKind("ssh_brute"),
		Observation: admission.ObservationRef{Stream: "log:sshd_log", Cursor: "subnet", Version: 1},
		ObservedAt:  f.wall, Parser: admission.ParserRef{Name: "fixture", Version: 1}, Target: prefix,
	})
	if err != nil {
		t.Fatal(err)
	}
	arrival := f.arrive(admission.Arrival{Request: admission.CandidateRequest{Kind: admission.KindBlockSubnet, Target: prefix, Primary: e.ID()}, Evidence: e})[0]
	if arrival.Err != nil || !arrival.Created {
		t.Fatalf("subnet arrival: %+v", arrival)
	}
	f.finishArrival(arrival.Candidate, f.wall.Add(time.Hour), admission.DispositionApplied)
	verified := f.candidateOf(arrival.Candidate)
	if err = f.db.bolt.Update(func(tx *bolt.Tx) error {
		q, openErr := f.l.openQueue(tx, f.wall)
		if openErr != nil {
			return openErr
		}
		return q.forgetLine(arrival.Candidate, verified)
	}); err != nil {
		t.Fatalf("forgetting the verified subnet block: %v", err)
	}
	if err = f.db.bolt.View(func(tx *bolt.Tx) error {
		_, found, loadErr := loadEpisode(tx, prefix.Key())
		if found {
			t.Error("an unretainable verified row was kept")
		}
		return loadErr
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatal(err)
	}
}
