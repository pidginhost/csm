package store

import (
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// A verified predecessor pays for retained episode proof after an
// unattempted return is forgotten. Schema 15 makes that shape explicit;
// earlier readers must refuse it instead of losing the boundary.
func TestAdmissionLedgerRetainedEpisodeSchema(t *testing.T) {
	f := liveLedgerFixture(t)
	f.begin()
	first := f.arrive(f.arrival(evidenceSpec{cursor: "original"}))[0].Candidate
	_, a, _, err := f.l.Reserve(first, admission.LaneGeneral, f.wall.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = f.l.Execute(a.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.l.Finish(a.Attempt.ID, admission.DispositionApplied); err != nil {
		t.Fatal(err)
	}
	original := f.candidateOf(first)
	row, _ := f.episodeAt("192.0.2.10")
	// Model the later placement task's unattempted generation through
	// existing queue APIs, without depending on that task's behavior.
	f.tickAt(f.wall.Add(time.Minute))
	root := f.published(evidenceSpec{cursor: "return"})
	req := f.request("192.0.2.10", root)
	req.Episode, req.Generation = row.ID, 2
	_, id := f.enqueue(req)
	if _, err = f.l.Terminate(id, admission.ReasonStale); err != nil {
		t.Fatal(err)
	}
	row.Last = f.wall
	row = row.WithLine(admission.EpisodeLine{Kind: admission.KindBlockIP, Generation: 2, Candidate: id, Observed: f.wall})
	if err = f.db.bolt.Update(func(tx *bolt.Tx) error { return putEpisode(tx, f.target("192.0.2.10").Key(), row) }); err != nil {
		t.Fatal(err)
	}
	forget := func(id admission.CandidateID, c admission.Candidate) {
		t.Helper()
		if forgetErr := f.db.bolt.Update(func(tx *bolt.Tx) error {
			q, openErr := f.l.openQueue(tx, f.wall)
			if openErr != nil {
				return openErr
			}
			return q.forgetLine(id, c)
		}); forgetErr != nil {
			t.Fatal(forgetErr)
		}
	}
	forget(id, f.candidateOf(id))
	retained, found := f.episodeAt("192.0.2.10")
	line, _ := retained.Line(admission.KindBlockIP)
	if !found || retained.HasCandidates() || !line.Answered || !retained.Verified.Equal(row.Verified) || retained.EndElapsed != row.EndElapsed || f.schema() != 15 {
		t.Fatalf("retained proof: %+v found %v schema %d", retained, found, f.schema())
	}
	before := f.snapshot()
	if _, err = OpenAdmissionLedger(f.db, f.reg); err != nil || !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatalf("compatible open changed retained proof: %v", err)
	}
	f.setSchema(14)
	if _, err = OpenAdmissionLedger(f.db, f.reg); !isCorrupt(err) {
		t.Fatalf("retained shape below its schema was accepted: %v", err)
	}
	f.setSchema(15)
	if f.l, err = OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatal(err)
	}
	// A reboot advances wall time without granting elapsed credit.
	f.wall, f.since = row.Verified, time.Minute
	if _, err = f.l.Tick(admission.ClockReading{Wall: f.wall, BootID: ledgerRebootID, SinceBoot: f.since}); err != nil {
		t.Fatal(err)
	}
	forget(first, original)
	if _, found = f.episodeAt("192.0.2.10"); !found {
		t.Fatal("wall expiry alone discarded retained proof")
	}
	f.ackAll()
	f.wall = f.wall.Add(admission.HistoryTarget + time.Hour)
	if _, err = f.l.Tick(admission.ClockReading{Wall: f.wall, BootID: ledgerRebootID, SinceBoot: f.since}); err != nil {
		t.Fatal(err)
	}
	if _, found = f.historyEntry(first); !found {
		t.Fatal("wall-only retirement dropped the history paying for retained proof")
	}
	if _, found = f.episodeAt("192.0.2.10"); !found {
		t.Fatal("wall-only retirement dropped retained proof")
	}
	used := f.storageState().General.Used
	if err = f.db.bolt.Update(func(tx *bolt.Tx) error {
		q, openErr := f.l.openQueue(tx, f.wall)
		if openErr != nil {
			return openErr
		}
		if retireErr := q.retireForRoom(admission.LaneGeneral, ^uint64(0)); retireErr != nil {
			return retireErr
		}
		return q.flushStorage()
	}); err != nil {
		t.Fatal(err)
	}
	if _, found = f.historyEntry(first); !found || f.storageState().General.Used != used {
		t.Fatal("pressure retired the live episode's cleanup owner")
	}
	f.wall, f.since = f.wall.Add(time.Hour), f.since+time.Hour
	if _, err = f.l.Tick(admission.ClockReading{Wall: f.wall, BootID: ledgerRebootID, SinceBoot: f.since}); err != nil {
		t.Fatal(err)
	}
	if _, found = f.historyEntry(first); found {
		t.Fatal("expired predecessor history was not retired")
	}
	if _, found = f.episodeAt("192.0.2.10"); found {
		t.Fatal("an expired unreferenced episode leaked")
	}
}
