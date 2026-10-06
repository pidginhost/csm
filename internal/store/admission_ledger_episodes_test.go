package store

import (
	"bytes"
	"crypto/sha256"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// dropEpisodes removes the schema 6 episode bucket and sequence.
func dropEpisodes(tx *bolt.Tx) error {
	if tx.Bucket([]byte(admissionEpisodesBucket)) != nil {
		if err := tx.DeleteBucket([]byte(admissionEpisodesBucket)); err != nil {
			return err
		}
	}
	return tx.Bucket([]byte(admissionQueueStateBucket)).Delete(episodeStateKey)
}

// schemaFive rewrites the fixture's database into the schema 5 layout: the
// same records without episodes.
func (f *ledgerFixture) schemaFive() {
	f.t.Helper()
	if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
		if err := dropEpisodes(tx); err != nil {
			return err
		}
		return tx.Bucket([]byte(admissionMetaBucket)).Put(admissionSchemaKey, []byte{5})
	}); err != nil {
		f.t.Fatal(err)
	}
}

func episodeSequenceIn(t *testing.T, db *DB) admission.EpisodeSequence {
	t.Helper()
	var s admission.EpisodeSequence
	if err := db.bolt.View(func(tx *bolt.Tx) error {
		var err error
		s, err = loadEpisodeSequence(tx)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return s
}

// A new ledger starts with no episodes and a sequence of its own: two
// ledgers never share a nonce, so their episode IDs never meet.
func TestAdmissionLedgerStartsItsOwnEpisodeSequence(t *testing.T) {
	a, b := newLedgerFixture(t), newLedgerFixture(t)
	sa, sb := episodeSequenceIn(t, a.db), episodeSequenceIn(t, b.db)
	if sa.Nonce == ([16]byte{}) || sa.Nonce == sb.Nonce || sa.Next != 0 || sb.Next != 0 {
		t.Fatalf("sequences = %+v, %+v", sa, sb)
	}
	if err := a.db.bolt.View(func(tx *bolt.Tx) error {
		if n := tx.Bucket([]byte(admissionEpisodesBucket)).Stats().KeyN; n != 0 {
			t.Errorf("a new ledger holds %d episodes", n)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// A schema 5 ledger is upgraded once, in the opening transaction: every
// schema 5 record stays byte for byte, and the ledger gains an empty
// episode bucket and its sequence. Candidates queued before keep their
// episodes; no episode row is invented for them. Opening again changes
// nothing.
func TestAdmissionLedgerUpgradesSchemaFive(t *testing.T) {
	f := newLedgerFixture(t)
	f.queued()
	f.schemaFive()
	before := dbSnapshot(t, f.db)
	db := f.copyDatabase()
	if _, err := OpenAdmissionLedger(db, f.reg); err != nil {
		t.Fatal(err)
	}
	after := dbSnapshot(t, db)
	schemaKey := admissionMetaBucket + ":" + string(admissionSchemaKey)
	for k, v := range before {
		if after[k] != v && k != schemaKey {
			t.Fatalf("upgrade changed schema 5 record %s", k)
		}
	}
	if after[schemaKey] != string([]byte{6}) {
		t.Fatalf("upgraded schema = %q", after[schemaKey])
	}
	if s := episodeSequenceIn(t, db); s.Nonce == ([16]byte{}) || s.Next != 0 {
		t.Fatalf("upgraded sequence = %+v", s)
	}
	if _, err := OpenAdmissionLedger(db, f.reg); err != nil {
		t.Fatal(err)
	}
	if again := dbSnapshot(t, db); !reflect.DeepEqual(again, after) {
		t.Fatal("a second open changed the upgraded ledger")
	}
}

// Schema 5 history paid for candidates and attempts, but no episode rows.
// Reserved, verified and unresolved histories keep their charges at upgrade.
func TestAdmissionLedgerUpgradesSchemaFiveHistory(t *testing.T) {
	f := newLedgerFixture(t)
	m := f.mixed()
	f.nextGeneration()
	retry := f.queued()
	_, a, _, err := f.l.Reserve(retry, admission.LaneGeneral, f.wall.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.l.Finish(a.Attempt.ID, admission.DispositionFailed); err != nil {
		t.Fatal(err)
	}
	f.schemaFive()
	if err = f.db.bolt.Update(func(tx *bolt.Tx) error {
		s, txErr := loadStorageState(tx)
		if txErr != nil {
			return txErr
		}
		if txErr = tx.Bucket([]byte(admissionHistoryBucket)).ForEach(func(k, v []byte) error {
			h, decodeErr := admission.UnmarshalHistoryEntry(v)
			if decodeErr != nil {
				return decodeErr
			}
			if h.General >= admission.MaxEpisodeBytes {
				h.General -= admission.MaxEpisodeBytes
				if !h.Pinned {
					s.General.Used -= admission.MaxEpisodeBytes
				}
			} else {
				h.Reserved -= admission.MaxEpisodeBytes
				if !h.Pinned {
					s.Reserved.Used -= admission.MaxEpisodeBytes
				}
			}
			if h.Pinned {
				s.Recovery -= admission.MaxEpisodeBytes
			}
			return putLegacyHistory(tx, admission.CandidateID(k), h)
		}); txErr != nil {
			return txErr
		}
		return putStorageState(tx, s)
	}); err != nil {
		t.Fatal(err)
	}
	before := dbSnapshot(t, f.db)
	db := f.copyDatabase()
	l, err := OpenAdmissionLedger(db, f.reg)
	if err != nil {
		t.Fatalf("valid schema 5 history refused upgrade: %v", err)
	}
	after := dbSnapshot(t, db)
	schemaKey := admissionMetaBucket + ":" + string(admissionSchemaKey)
	for k, v := range before {
		if k != schemaKey && after[k] != v {
			t.Fatalf("upgrade changed schema 5 history record %s", k)
		}
	}
	if _, err = OpenAdmissionLedger(db, f.reg); err != nil {
		t.Fatalf("reopen after upgrading history: %v", err)
	}
	if !reflect.DeepEqual(after, dbSnapshot(t, db)) {
		t.Fatal("reopen changed upgraded history")
	}
	f.l, f.db = l, db
	f.tickAt(f.wall.Add(admission.RetryBackoff(1)))
	h, _ := f.historyEntry(retry)
	used := f.storageState().General.Used
	if _, _, _, err = f.l.Reserve(retry, admission.LaneGeneral, time.Time{}); err != nil {
		t.Fatalf("legacy retry: %v", err)
	}
	if next, _ := f.historyEntry(retry); next.LegacyCost || next.Charged() != h.Charged()+admission.MaxEpisodeBytes || f.storageState().General.Used != used+admission.MaxEpisodeBytes {
		t.Fatalf("retry did not pay the new charge contract: %+v -> %+v", h, next)
	}
	if err = db.bolt.Update(func(tx *bolt.Tx) error {
		damaged, _, txErr := loadHistoryEntry(tx, m.reserved)
		if txErr != nil {
			return txErr
		}
		damaged.General--
		if txErr = putHistoryEntry(tx, m.reserved, damaged); txErr != nil {
			return txErr
		}
		return adjustStorage(tx, func(s *admission.StorageState) { s.General.Used-- })
	}); err != nil {
		t.Fatal(err)
	}
	before = dbSnapshot(t, db)
	if _, err = OpenAdmissionLedger(db, f.reg); !isCorrupt(err) {
		t.Fatalf("undercharged legacy history was accepted: %v", err)
	}
	if !reflect.DeepEqual(before, dbSnapshot(t, db)) {
		t.Fatal("refused legacy proof changed the ledger")
	}
}

func putLegacyHistory(tx *bolt.Tx, id admission.CandidateID, h admission.HistoryEntry) error {
	raw, err := h.MarshalBinary()
	if err != nil {
		return err
	}
	body := bytes.Replace(raw[:len(raw)-8], []byte(`"v":2`), []byte(`"v":1`), 1)
	sum := sha256.Sum256(body)
	return tx.Bucket([]byte(admissionHistoryBucket)).Put([]byte(id), append(body, sum[:8]...))
}

func TestAdmissionLedgerLegacyHistoryWithAnEpisodePaysForTheRow(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	id := f.arrive(f.arrival(evidenceSpec{}))[0].Candidate
	if _, _, _, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	h, _ := f.historyEntry(id)
	if err := f.db.bolt.Update(func(tx *bolt.Tx) error { return putLegacyHistory(tx, id, h) }); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatalf("fully charged version 1 episode history: %v", err)
	}
	if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
		h.General -= admission.MaxEpisodeBytes
		if err := putLegacyHistory(tx, id, h); err != nil {
			return err
		}
		return adjustStorage(tx, func(s *admission.StorageState) { s.General.Used -= admission.MaxEpisodeBytes })
	}); err != nil {
		t.Fatal(err)
	}
	before := dbSnapshot(t, f.db)
	if _, err := OpenAdmissionLedger(f.db, f.reg); !isCorrupt(err) {
		t.Fatalf("episode row without its history charge: %v", err)
	}
	if !reflect.DeepEqual(before, dbSnapshot(t, f.db)) {
		t.Fatal("refused episode charge proof changed the ledger")
	}
}

// A nonce read failure rolls back the entire upgrade chain, including
// earlier buckets and schema writes. Retrying upgrades the intact copy.
func TestAdmissionLedgerEpisodeUpgradeRollsBack(t *testing.T) {
	for name, downgrade := range map[string]func(*ledgerFixture){
		"1": (*ledgerFixture).schemaOne, "2": (*ledgerFixture).schemaTwo,
		"3": (*ledgerFixture).schemaThree, "4": (*ledgerFixture).schemaFour,
		"5": (*ledgerFixture).schemaFive,
	} {
		t.Run(name, func(t *testing.T) {
			f := newLedgerFixture(t)
			f.queued()
			downgrade(f)
			before := dbSnapshot(t, f.db)
			prev := episodeNonce
			t.Cleanup(func() { episodeNonce = prev })
			episodeNonce = strings.NewReader("short")
			if _, err := OpenAdmissionLedger(f.db, f.reg); err == nil {
				t.Fatal("a failed nonce read completed an upgrade")
			}
			if !reflect.DeepEqual(before, dbSnapshot(t, f.db)) {
				t.Fatal("a failed upgrade changed the original ledger")
			}
			episodeNonce = prev
			if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
				t.Fatalf("retry after failed upgrade: %v", err)
			}
		})
	}
}

func putEpisodeRow(tx *bolt.Tx, key string, e admission.Episode) error {
	data, err := e.MarshalBinary()
	if err != nil {
		return err
	}
	return tx.Bucket([]byte(admissionEpisodesBucket)).Put([]byte(key), data)
}

// episodeOf is the row that names id as the latest of its kind.
func (f *ledgerFixture) episodeOf(id admission.CandidateID) admission.Episode {
	f.t.Helper()
	c, err := f.l.Candidate(id)
	if err != nil {
		f.t.Fatal(err)
	}
	return admission.Episode{ID: c.Key.Episode, Last: f.wall, Lines: []admission.EpisodeLine{{Kind: c.Key.Kind, Generation: c.Key.Generation, Candidate: id, Observed: f.wall}}}
}

// Opening proves every episode row: it decodes under its target's key and
// each line names a stored candidate of that target, kind, episode and
// generation. A row naming nothing, or the wrong candidate, is damage.
func TestAdmissionLedgerRefusesDamagedEpisodes(t *testing.T) {
	const key = "ip:192.0.2.10"
	for name, damage := range map[string]func(f *ledgerFixture, e admission.Episode, tx *bolt.Tx) error{
		"undecodable row": func(_ *ledgerFixture, _ admission.Episode, tx *bolt.Tx) error {
			return tx.Bucket([]byte(admissionEpisodesBucket)).Put([]byte(key), []byte("{}"))
		},
		"key that is not a target": func(_ *ledgerFixture, e admission.Episode, tx *bolt.Tx) error {
			return putEpisodeRow(tx, "192.0.2.10", e)
		},
		"non-canonical key of the target": func(_ *ledgerFixture, e admission.Episode, tx *bolt.Tx) error {
			return putEpisodeRow(tx, "ip:::ffff:192.0.2.10", e)
		},
		"key of another target": func(_ *ledgerFixture, e admission.Episode, tx *bolt.Tx) error {
			return putEpisodeRow(tx, "ip:192.0.2.11", e)
		},
		"line naming a missing candidate": func(f *ledgerFixture, e admission.Episode, tx *bolt.Tx) error {
			e.Lines[0].Candidate = "cand_" + "ffffffffffffffffffffffffffffffff"
			return putEpisodeRow(tx, key, e)
		},
		"line of another generation": func(_ *ledgerFixture, e admission.Episode, tx *bolt.Tx) error {
			e.Lines[0].Generation++
			return putEpisodeRow(tx, key, e)
		},
		"line of another kind": func(_ *ledgerFixture, e admission.Episode, tx *bolt.Tx) error {
			e.Lines[0].Kind = admission.KindPromote
			return putEpisodeRow(tx, key, e)
		},
		"row of another episode": func(_ *ledgerFixture, e admission.Episode, tx *bolt.Tx) error {
			e.ID[15] ^= 0xff
			return putEpisodeRow(tx, key, e)
		},
		"missing sequence": func(_ *ledgerFixture, _ admission.Episode, tx *bolt.Tx) error {
			return tx.Bucket([]byte(admissionQueueStateBucket)).Delete(episodeStateKey)
		},
		"damaged sequence": func(_ *ledgerFixture, _ admission.Episode, tx *bolt.Tx) error {
			return tx.Bucket([]byte(admissionQueueStateBucket)).Put(episodeStateKey, []byte("{}"))
		},
		"schema 5 with the episode bucket": func(_ *ledgerFixture, _ admission.Episode, tx *bolt.Tx) error {
			return tx.Bucket([]byte(admissionMetaBucket)).Put(admissionSchemaKey, []byte{5})
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newLedgerFixture(t)
			id := f.queued()
			e := f.episodeOf(id)
			if err := f.db.bolt.Update(func(tx *bolt.Tx) error { return putEpisodeRow(tx, key, e) }); err != nil {
				t.Fatal(err)
			}
			if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
				t.Fatalf("the intact row: %v", err)
			}
			if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
				if err := tx.Bucket([]byte(admissionEpisodesBucket)).Delete([]byte(key)); err != nil {
					return err
				}
				return damage(f, e, tx)
			}); err != nil {
				t.Fatal(err)
			}
			before := dbSnapshot(t, f.db)
			if _, err := OpenAdmissionLedger(f.db, f.reg); !isCorrupt(err) {
				t.Fatalf("err = %v, want a corrupt record", err)
			}
			if !reflect.DeepEqual(before, dbSnapshot(t, f.db)) {
				t.Fatal("a refused open changed the ledger")
			}
		})
	}
}

// arrive persists one group of arrivals and returns their results.
func (f *ledgerFixture) arrive(arrivals ...admission.Arrival) []admission.ArrivalResult {
	f.t.Helper()
	out, _, err := f.l.EnqueueGroup(arrivals, nil)
	if err != nil {
		f.t.Fatal(err)
	}
	return out
}

func (f *ledgerFixture) candidateOf(id admission.CandidateID) admission.Candidate {
	f.t.Helper()
	c, err := f.l.Candidate(id)
	if err != nil {
		f.t.Fatal(err)
	}
	return c
}

func (f *ledgerFixture) episodeAt(addr string) (admission.Episode, bool) {
	f.t.Helper()
	var e admission.Episode
	var found bool
	if err := f.db.bolt.View(func(tx *bolt.Tx) error {
		var err error
		e, found, err = loadEpisode(tx, f.target(addr).Key())
		return err
	}); err != nil {
		f.t.Fatal(err)
	}
	return e, found
}

// refusals counts the refused arrivals of reason, whatever their tier.
func (f *ledgerFixture) refusals(reason admission.Reason) uint64 {
	f.t.Helper()
	var n uint64
	if err := f.db.bolt.View(func(tx *bolt.Tx) error {
		q, err := loadQueueCounters(tx)
		for _, row := range q.Rows() {
			if row.Key.Event == admission.EventRefused && row.Key.Reason == reason {
				n += row.N
			}
		}
		return err
	}); err != nil {
		f.t.Fatal(err)
	}
	return n
}

// The ledger, not the caller, assigns each arrival its episode and
// generation (spec 5.2): a target's first observation opens an episode,
// later ones coalesce into its queued candidate, and another target has
// its own. Arrivals for one target in one group share the candidate.
func TestAdmissionLedgerAssignsEpisodesToArrivals(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	first := f.arrive(f.arrival(evidenceSpec{cursor: "offset=1", age: 10 * time.Minute}))[0]
	if first.Err != nil || !first.Created {
		t.Fatalf("first arrival = %+v", first)
	}
	c := f.candidateOf(first.Candidate)
	if c.Key.Episode.IsZero() || c.Key.Generation != 1 {
		t.Fatalf("first candidate key = %+v", c.Key)
	}
	want := admission.Episode{ID: c.Key.Episode, Last: ledgerT0.Add(-10 * time.Minute), Lines: []admission.EpisodeLine{{Kind: admission.KindBlockIP, Generation: 1, Candidate: first.Candidate, Observed: ledgerT0.Add(-10 * time.Minute)}}}
	if row, ok := f.episodeAt("192.0.2.10"); !ok || !reflect.DeepEqual(row, want) {
		t.Fatalf("episode row = %+v %v, want %+v", row, ok, want)
	}
	again := f.arrive(f.arrival(evidenceSpec{cursor: "offset=2"}))[0]
	if again.Err != nil || again.Created || again.Candidate != first.Candidate {
		t.Fatalf("a later observation must coalesce: %+v", again)
	}
	want.Last, want.Lines[0].Observed = ledgerT0, ledgerT0
	if row, _ := f.episodeAt("192.0.2.10"); !reflect.DeepEqual(row, want) {
		t.Fatalf("after the later observation = %+v", row)
	}
	other := f.arrive(f.arrival(evidenceSpec{target: "192.0.2.11", cursor: "offset=3"}))[0]
	if other.Err != nil || !other.Created || f.candidateOf(other.Candidate).Key.Episode == c.Key.Episode {
		t.Fatalf("another target = %+v", other)
	}
	group := f.arrive(f.arrival(evidenceSpec{target: "192.0.2.12", cursor: "offset=4"}), f.arrival(evidenceSpec{target: "192.0.2.12", cursor: "offset=5"}))
	if group[0].Err != nil || group[1].Err != nil || !group[0].Created || group[1].Created || group[0].Candidate != group[1].Candidate {
		t.Fatalf("one group, one target = %+v", group)
	}
}

// A caller never chooses an episode: an arrival that names one, or aims
// at another target than its evidence, is refused and counted, and opens
// nothing.
func TestAdmissionLedgerRefusesArrivalsNamingAnEpisode(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	prefix, err := admission.CanonicalPrefix("192.0.2.0/24", admission.Caps{IPv6: true})
	if err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*admission.CandidateRequest){
		"episode":    func(r *admission.CandidateRequest) { r.Episode[15] = 1 },
		"generation": func(r *admission.CandidateRequest) { r.Generation = 1 },
		// The episode row is keyed by the request's target, so it must be
		// the evidence's own, even where a prefix would cover it.
		"prefix": func(r *admission.CandidateRequest) { r.Kind, r.Target = admission.KindBlockSubnet, prefix },
	} {
		a := f.arrival(evidenceSpec{cursor: name})
		edit(&a.Request)
		wantLedgerReason(t, name, f.arrive(a)[0].Err, admission.ReasonInvalid)
	}
	if _, ok := f.episodeAt("192.0.2.10"); ok {
		t.Fatal("a refused arrival opened an episode")
	}
	if n := f.refusals(admission.ReasonInvalid); n != 3 {
		t.Fatalf("refusals = %d", n)
	}
}

// Re-reporting an ended generation's old observation cannot start a new
// queue lifetime. Only a later qualifying observation advances it.
func TestAdmissionLedgerRepeatedObservationDoesNotAdvanceEpisodeGeneration(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	old := f.arrival(evidenceSpec{cursor: "offset=1", age: time.Minute})
	first := f.arrive(old)[0].Candidate
	if _, err := f.l.Terminate(first, admission.ReasonPolicy); err != nil {
		t.Fatal(err)
	}
	before, _ := f.episodeAt("192.0.2.10")
	wantLedgerReason(t, "repeated root", f.arrive(old)[0].Err, admission.ReasonStale)
	if after, _ := f.episodeAt("192.0.2.10"); !reflect.DeepEqual(before, after) {
		t.Fatal("a repeated root changed the episode")
	}
	next := f.arrive(f.arrival(evidenceSpec{cursor: "offset=2"}))[0]
	if c := f.candidateOf(next.Candidate); next.Err != nil || !next.Created || c.Key.Episode != before.ID || c.Key.Generation != 2 {
		t.Fatalf("later root: %+v %+v", next, c.Key)
	}
}

// Assignment, sequence advancement and every arrival in a group roll back
// together when the transaction fails after its writes.
func TestAdmissionLedgerEpisodeAssignmentIsAtomic(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	before := dbSnapshot(t, f.db)
	f.failNext("group")
	arrivals := []admission.Arrival{f.arrival(evidenceSpec{cursor: "offset=1"}), f.arrival(evidenceSpec{cursor: "offset=2"})}
	if got, revision, err := f.l.EnqueueGroup(arrivals, nil); err == nil || got != nil || revision != 0 {
		t.Fatalf("failed group: %+v %d %v", got, revision, err)
	}
	if !reflect.DeepEqual(before, dbSnapshot(t, f.db)) {
		t.Fatal("a failed group retained episode, sequence or candidate writes")
	}
	out := f.arrive(arrivals...)
	if !out[0].Created || out[1].Created || out[0].Err != nil || out[1].Err != nil || out[0].Candidate != out[1].Candidate || episodeSequenceIn(t, f.db).Next != 1 {
		t.Fatalf("retry did not commit exactly one episode: %+v", out)
	}
}

// Refusal paths must validate ownership and every supplied root even when
// a prior attempt answers the arrival without calling enqueueTx.
func TestAdmissionLedgerAnsweredEpisodeValidatesEveryRoot(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	first := f.arrive(f.arrival(evidenceSpec{cursor: "offset=1"}))[0].Candidate
	if _, _, _, err := f.l.Reserve(first, admission.LaneGeneral, f.wall.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	before, _ := f.episodeAt("192.0.2.10")
	retired := f.owner("alice")
	f.refresh([]string{"bob"}, nil)
	wantLedgerReason(t, "retired owner", f.arrive(f.arrival(evidenceSpec{cursor: "retired", owner: retired}))[0].Err, admission.ReasonStaleIdentity)
	bad := f.arrival(evidenceSpec{cursor: "unsupported"})
	bad.Request.Support = []admission.EvidenceID{f.published(evidenceSpec{target: "192.0.2.11", cursor: "wrong-target"})}
	wantLedgerReason(t, "wrong-target support", f.arrive(bad)[0].Err, admission.ReasonInvalid)
	if after, _ := f.episodeAt("192.0.2.10"); !reflect.DeepEqual(before, after) {
		t.Fatal("an invalid answered arrival changed the episode")
	}
}

// A row corrupted after open must not answer for another generation.
func TestAdmissionLedgerEpisodePlacementProvesItsLines(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	f.arrive(f.arrival(evidenceSpec{cursor: "offset=1"}))
	e, _ := f.episodeAt("192.0.2.10")
	e.Lines[0].Generation++
	if err := f.db.bolt.Update(func(tx *bolt.Tx) error { return putEpisodeRow(tx, "ip:192.0.2.10", e) }); err != nil {
		t.Fatal(err)
	}
	before := dbSnapshot(t, f.db)
	if out, revision, err := f.l.EnqueueGroup([]admission.Arrival{f.arrival(evidenceSpec{cursor: "offset=2"})}, nil); !isCorrupt(err) || out != nil || revision != 0 {
		t.Fatalf("damaged line was used: %+v %d %v", out, revision, err)
	}
	if !reflect.DeepEqual(before, dbSnapshot(t, f.db)) {
		t.Fatal("damaged placement wrote partial state")
	}
}

// A candidate that ended before any attempt leaves its episode open: a new
// observation queues the next generation.
func TestAdmissionLedgerQueuesTheNextGenerationAfterAnEndedLine(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	first := f.arrive(f.arrival(evidenceSpec{cursor: "offset=1"}))[0]
	if _, err := f.l.Terminate(first.Candidate, admission.ReasonPolicy); err != nil {
		t.Fatal(err)
	}
	f.tickAt(f.wall.Add(time.Second))
	next := f.arrive(f.arrival(evidenceSpec{cursor: "offset=2"}))[0]
	c := f.candidateOf(next.Candidate)
	if next.Err != nil || !next.Created || c.Key.Episode != f.candidateOf(first.Candidate).Key.Episode || c.Key.Generation != 2 {
		t.Fatalf("next generation = %+v %+v", next, c.Key)
	}
	row, _ := f.episodeAt("192.0.2.10")
	if line, ok := row.Line(admission.KindBlockIP); !ok || line != (admission.EpisodeLine{Kind: admission.KindBlockIP, Generation: 2, Candidate: next.Candidate, Observed: f.wall}) {
		t.Fatalf("line = %+v", row.Lines)
	}
}

// Once the episode's candidate has an attempt, later observations queue
// nothing more: they are refused as an existing effect, raise no notice
// and still extend the episode.
func TestAdmissionLedgerAnswersAnAttemptedEpisode(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	critical := admission.SeverityCritical
	first := f.arrive(f.arrival(evidenceSpec{cursor: "offset=1", severity: critical}))[0]
	_, attempt, _, err := f.l.Reserve(first.Candidate, admission.LaneGeneral, f.wall.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	f.tickAt(ledgerT0.Add(10 * time.Minute))
	in := f.arrive(f.arrival(evidenceSpec{cursor: "offset=2", severity: critical}))[0]
	wantLedgerReason(t, "in flight", in.Err, admission.ReasonExistingEffect)
	if in.Candidate != first.Candidate {
		t.Fatalf("the refusal names %s, want the answering candidate", in.Candidate)
	}
	if row, _ := f.episodeAt("192.0.2.10"); !row.Last.Equal(ledgerT0.Add(10 * time.Minute)) {
		t.Fatalf("the refused observation must extend the episode: %+v", row)
	}
	if _, _, _, err = f.l.Execute(attempt.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.l.Finish(attempt.Attempt.ID, admission.DispositionUnknown); err != nil {
		t.Fatal(err)
	}
	after := f.arrive(f.arrival(evidenceSpec{cursor: "offset=3", severity: critical}))[0]
	wantLedgerReason(t, "unknown outcome", after.Err, admission.ReasonExistingEffect)
	for k := range f.notices() {
		if k.Reason == admission.ReasonExistingEffect {
			t.Fatalf("an existing effect raised notice %+v", k)
		}
	}
	if n := f.refusals(admission.ReasonExistingEffect); n != 2 {
		t.Fatalf("refusals = %d", n)
	}
}

func TestAdmissionLedgerExistingEpisodeDrainReport(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	first := f.arrive(f.arrival(evidenceSpec{cursor: "offset=1", severity: admission.SeverityCritical}))[0].Candidate
	if _, _, _, err := f.l.Reserve(first, admission.LaneGeneral, f.wall.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	in, err := admission.NewIngress(f.reg)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := f.l.QueueSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	in.Publish(snap)
	a := f.arrival(evidenceSpec{cursor: "offset=2", severity: admission.SeverityCritical})
	if err = in.Submit(admission.Submission{Kind: a.Request.Kind, Target: a.Request.Target, Evidence: a.Evidence}); err != nil {
		t.Fatal(err)
	}
	report, err := in.Drain(f.l, 1, f.requestFor)
	if err != nil || report != (admission.DrainReport{Refused: 1}) || in.Len() != 0 || f.refusals(admission.ReasonExistingEffect) != 1 {
		t.Fatalf("existing-effect drain: %+v %v, held %d", report, err, in.Len())
	}
	for key := range f.notices() {
		if key.Reason == admission.ReasonExistingEffect {
			t.Fatalf("existing effect raised a notice: %+v", key)
		}
	}
}

// An episode ends an hour after its last observation once nothing of it
// is queued: the next observation opens a new episode, and one older than
// that end belongs to the ended episode and is refused as stale. While its
// candidate waits, no quiet ends it.
func TestAdmissionLedgerOpensTheNextEpisodeAfterTheQuietHour(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	first := f.arrive(f.arrival(evidenceSpec{cursor: "offset=1"}))[0]
	episode := f.candidateOf(first.Candidate).Key.Episode
	f.tickAt(ledgerT0.Add(admission.EpisodeQuiet + time.Minute))
	waiting := f.arrive(f.arrival(evidenceSpec{cursor: "offset=2"}))[0]
	if waiting.Err != nil || waiting.Candidate != first.Candidate {
		t.Fatalf("a queued candidate must keep its episode: %+v", waiting)
	}
	if _, err := f.l.Terminate(first.Candidate, admission.ReasonPolicy); err != nil {
		t.Fatal(err)
	}
	end := ledgerT0.Add(2*admission.EpisodeQuiet + time.Minute)
	f.tickAt(end.Add(time.Minute))
	next := f.arrive(f.arrival(evidenceSpec{cursor: "offset=3"}))[0]
	c := f.candidateOf(next.Candidate)
	if next.Err != nil || !next.Created || c.Key.Episode == episode || c.Key.Generation != 1 {
		t.Fatalf("after the quiet hour = %+v %+v", next, c.Key)
	}
	if row, _ := f.episodeAt("192.0.2.10"); !row.Previous.Equal(end) {
		t.Fatalf("previous end = %v, want %v", row.Previous, end)
	}
	late := f.arrive(f.arrival(evidenceSpec{cursor: "offset=4", age: 2 * time.Minute, severity: admission.SeverityCritical}))[0]
	wantLedgerReason(t, "observation of the ended episode", late.Err, admission.ReasonStale)
	key := admission.NoticeKey{Kind: admission.NoticeWithheld, Reason: admission.ReasonStale, Check: "ssh_brute", Effect: admission.EffectAddress}
	if n := f.refusals(admission.ReasonStale); n != 1 || f.notices()[key].Count != 1 {
		t.Fatalf("Critical earlier-episode refusal: count %d notices %+v", n, f.notices())
	}
}

// An arrival the queue refuses leaves the target's episode as it was: it
// opens no episode and does not extend one.
func TestAdmissionLedgerRefusedArrivalLeavesTheEpisode(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	alice := f.owner("alice")
	f.refresh([]string{"bob"}, nil)
	retired := f.arrive(f.arrival(evidenceSpec{cursor: "offset=1", owner: alice}))[0]
	wantLedgerReason(t, "retired owner", retired.Err, admission.ReasonStaleIdentity)
	if row, ok := f.episodeAt("192.0.2.10"); ok {
		t.Fatalf("a refused arrival opened an episode: %+v", row)
	}
	first := f.arrive(f.arrival(evidenceSpec{cursor: "offset=2", age: time.Minute}))[0]
	before, _ := f.episodeAt("192.0.2.10")
	refused := f.arrive(f.arrival(evidenceSpec{cursor: "offset=3", owner: alice}))[0]
	wantLedgerReason(t, "retired owner joining", refused.Err, admission.ReasonStaleIdentity)
	if after, _ := f.episodeAt("192.0.2.10"); first.Err != nil || !reflect.DeepEqual(after, before) {
		t.Fatalf("a refused arrival changed the episode: %+v -> %+v", before, after)
	}
}

// Queue overflow cannot publish a new episode or advance an existing
// ended generation. The same group may still coalesce an accepted target.
func TestAdmissionLedgerQueueRefusalLeavesEpisodeRows(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	first := f.arrive(f.arrival(evidenceSpec{cursor: "offset=1"}))[0].Candidate
	if _, err := f.l.Terminate(first, admission.ReasonPolicy); err != nil {
		t.Fatal(err)
	}
	before, _ := f.episodeAt("192.0.2.10")
	filled := f.fill(admission.PartitionGeneral.DurableCapacity(), evidenceSpec{})
	sequence := episodeSequenceIn(t, f.db)
	f.tickAt(f.wall.Add(time.Second))
	out := f.arrive(f.arrival(evidenceSpec{cursor: "offset=2"}), f.arrival(evidenceSpec{target: "192.0.2.11", cursor: "offset=3"}))
	for _, r := range out {
		wantLedgerReason(t, "full queue", r.Err, admission.ReasonQueueOverflow)
		if r.Created {
			t.Fatal("a refused arrival reported a created candidate")
		}
	}
	if after, _ := f.episodeAt("192.0.2.10"); !reflect.DeepEqual(before, after) {
		t.Fatal("queue refusal changed an existing episode")
	}
	if _, exists := f.episodeAt("192.0.2.11"); exists {
		t.Fatal("queue refusal stored a new episode")
	}
	if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatalf("refusal left an unprovable row: %v", err)
	}
	if got := episodeSequenceIn(t, f.db); got.Nonce != sequence.Nonce || got.Next != sequence.Next+1 {
		t.Fatalf("the refused new episode did not consume its identity: %+v -> %+v", sequence, got)
	}
	if _, err := f.l.Terminate(filled[0], admission.ReasonPolicy); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenAdmissionLedger(f.db, f.reg)
	if err != nil {
		t.Fatal(err)
	}
	f.l = reopened
	f.tickAt(f.wall.Add(time.Second))
	next := f.arrive(f.arrival(evidenceSpec{target: "192.0.2.11", cursor: "offset=4"}))[0]
	if next.Err != nil || !next.Created || next.Candidate == out[1].Candidate {
		t.Fatalf("reopen reused a refused episode's candidate ID: %+v", next)
	}
}

// Evidence too old to justify a response is no qualifying observation: it
// is refused as stale and leaves the episode as it was, even while the
// episode's attempt is in flight.
func TestAdmissionLedgerStaleObservationLeavesTheEpisode(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	first := f.arrive(f.arrival(evidenceSpec{cursor: "offset=1"}))[0].Candidate
	if _, _, _, err := f.l.Reserve(first, admission.LaneGeneral, f.wall.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	f.tickAt(ledgerT0.Add(3 * time.Hour))
	before, _ := f.episodeAt("192.0.2.10")
	stale := f.arrive(f.arrival(evidenceSpec{cursor: "offset=2", age: admission.RootFreshness + time.Minute}))[0]
	wantLedgerReason(t, "stale observation", stale.Err, admission.ReasonStale)
	withSupport := f.arrival(evidenceSpec{cursor: "stale-primary", age: admission.RootFreshness + time.Minute})
	withSupport.Request.Support = []admission.EvidenceID{f.published(evidenceSpec{cursor: "fresh-support"})}
	wantLedgerReason(t, "stale primary with fresh support", f.arrive(withSupport)[0].Err, admission.ReasonStale)
	if after, _ := f.episodeAt("192.0.2.10"); !reflect.DeepEqual(after, before) {
		t.Fatalf("a stale observation changed the episode: %+v -> %+v", before, after)
	}
}

// Assess tolerates clock skew, but a future observation cannot establish
// an episode boundary or move the frontier ahead of the ledger's clock.
func TestAdmissionLedgerFutureObservationLeavesTheEpisode(t *testing.T) {
	for _, state := range []string{"absent", "queued", "ended", "answered", "verified boundary"} {
		t.Run(state, func(t *testing.T) {
			f := newLedgerFixture(t)
			f.begin()
			if state != "absent" {
				first := f.arrive(f.arrival(evidenceSpec{cursor: "first", age: time.Second}))[0]
				if first.Err != nil {
					t.Fatal(first.Err)
				}
				switch state {
				case "ended":
					if _, err := f.l.Terminate(first.Candidate, admission.ReasonPolicy); err != nil {
						t.Fatal(err)
					}
				case "answered":
					if _, _, _, err := f.l.Reserve(first.Candidate, admission.LaneGeneral, f.wall.Add(time.Hour)); err != nil {
						t.Fatal(err)
					}
				case "verified boundary":
					expiry := f.wall.Add(time.Minute)
					f.finishArrival(first.Candidate, expiry, admission.DispositionApplied)
					f.tickAt(expiry.Add(-time.Second))
				}
			}
			before, existed := f.episodeAt("192.0.2.10")
			sequence := episodeSequenceIn(t, f.db)
			future := f.arrival(evidenceSpec{cursor: "future", age: -time.Second})
			if _, err := admission.Assess(future.Request.Target, []admission.Evidence{future.Evidence}, f.l.now); err != nil {
				t.Fatalf("skew must be inside assessment tolerance: %v", err)
			}
			out := f.arrive(future)[0]
			wantLedgerReason(t, "future observation", out.Err, admission.ReasonInvalid)
			if after, exists := f.episodeAt("192.0.2.10"); existed != exists || !reflect.DeepEqual(before, after) {
				t.Fatalf("future observation changed the row: %+v -> %+v", before, after)
			}
			if out.Created || out.Candidate != "" || episodeSequenceIn(t, f.db) != sequence {
				t.Fatalf("future observation allocated an identity: %+v", out)
			}
			genuine := f.arrive(f.arrival(evidenceSpec{cursor: "genuine"}))[0]
			if state == "answered" || state == "verified boundary" {
				wantLedgerReason(t, "genuine answered observation", genuine.Err, admission.ReasonExistingEffect)
			} else if genuine.Err != nil {
				t.Fatalf("genuine observation was suppressed: %+v", genuine)
			}
			if state == "absent" {
				if _, err := f.l.Terminate(genuine.Candidate, admission.ReasonPolicy); err != nil {
					t.Fatal(err)
				}
				f.tickAt(future.Evidence.ObservedAt())
				accepted := f.arrive(future)[0]
				if accepted.Err != nil || !accepted.Created || f.candidateOf(accepted.Candidate).Key.Generation != 2 {
					t.Fatalf("observation was still refused after the clock caught up: %+v", accepted)
				}
			}
		})
	}
}

// A degraded clock reading cannot end an episode: wall time alone does
// not prove a new one. The next trusted reading can.
func TestAdmissionLedgerKeepsTheEpisodeOnADegradedClock(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	first := f.arrive(f.arrival(evidenceSpec{cursor: "offset=1"}))[0]
	if _, err := f.l.Terminate(first.Candidate, admission.ReasonPolicy); err != nil {
		t.Fatal(err)
	}
	// The wall moves an hour and a minute while an hour elapses.
	f.wall, f.since = ledgerT0.Add(admission.EpisodeQuiet+time.Minute), f.since+admission.EpisodeQuiet
	tick, err := f.l.Tick(admission.ClockReading{Wall: f.wall, BootID: ledgerBoot, SinceBoot: f.since})
	if err != nil || !tick.Degraded {
		t.Fatalf("tick = %+v, %v", tick, err)
	}
	next := f.arrive(f.arrival(evidenceSpec{cursor: "offset=2"}))[0]
	episode := f.candidateOf(first.Candidate).Key.Episode
	if c := f.candidateOf(next.Candidate); next.Err != nil || c.Key.Episode != episode || c.Key.Generation != 2 {
		t.Fatalf("on a degraded clock = %+v %+v", next, c.Key)
	}
	if _, err = f.l.Terminate(next.Candidate, admission.ReasonPolicy); err != nil {
		t.Fatal(err)
	}
	f.tickAt(f.wall.Add(admission.EpisodeQuiet + time.Minute))
	third := f.arrive(f.arrival(evidenceSpec{cursor: "offset=3"}))[0]
	if c := f.candidateOf(third.Candidate); third.Err != nil || c.Key.Episode == episode {
		t.Fatalf("on a trusted clock = %+v %+v", third, c.Key)
	}
}

// Deleting one kind cannot forget its generation while another kind
// retains the episode, including across reopen and repeated eviction.
func TestAdmissionLedgerDeletedEpisodeGenerationNeverRepeats(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	first := f.arrive(f.arrival(evidenceSpec{cursor: "offset=1"}))[0].Candidate
	episode := f.candidateOf(first).Key.Episode
	other := f.arrival(evidenceSpec{cursor: "promotion"})
	other.Request.Kind = admission.KindPromote
	f.arrive(other)
	for generation := uint32(2); generation <= 3; generation++ {
		if _, err := f.l.Terminate(first, admission.ReasonPolicy); err != nil {
			t.Fatal(err)
		}
		f.endMany(admission.MaxEndedCandidates)
		if _, err := f.l.Candidate(first); err != errCandidateMissing {
			t.Fatalf("candidate still retained: %v", err)
		}
		reopened, err := OpenAdmissionLedger(f.db, f.reg)
		if err != nil {
			t.Fatal(err)
		}
		f.l = reopened
		f.tickAt(f.wall.Add(time.Second))
		next := f.arrive(f.arrival(evidenceSpec{cursor: string(first)}))[0]
		c := f.candidateOf(next.Candidate)
		if next.Err != nil || !next.Created || next.Candidate == first || c.Key.Episode != episode || c.Key.Generation != generation {
			t.Fatalf("generation after deletion: %+v %+v, want %d", next, c.Key, generation)
		}
		first = next.Candidate
	}
}

func TestAdmissionLedgerDeletedEpisodeAttemptStillAnswers(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	first := f.arrive(f.arrival(evidenceSpec{cursor: "offset=1"}))[0].Candidate
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
	f.tickAt(f.wall.Add(time.Minute))
	other := f.arrival(evidenceSpec{cursor: "promotion"})
	other.Request.Kind = admission.KindPromote
	kept := f.arrive(other)[0].Candidate
	if _, _, _, err = f.l.Reserve(kept, admission.LaneGeneral, f.wall.Add(2*admission.HistoryTarget)); err != nil {
		t.Fatal(err)
	}
	f.ackAll()
	f.tickAt(f.wall.Add(admission.HistoryTarget + time.Hour))
	if _, err = f.l.Candidate(first); err != errCandidateMissing {
		t.Fatalf("attempted candidate was not retired: %v", err)
	}
	reopened, err := OpenAdmissionLedger(f.db, f.reg)
	if err != nil {
		t.Fatal(err)
	}
	f.l = reopened
	f.tickAt(f.wall.Add(time.Second))
	wantLedgerReason(t, "retired attempt", f.arrive(f.arrival(evidenceSpec{cursor: "new-root"}))[0].Err, admission.ReasonExistingEffect)
	row, ok := f.episodeAt("192.0.2.10")
	if line, found := row.Line(admission.KindBlockIP); !ok || !found || line.Candidate != "" || !line.Answered || line.Generation != 1 {
		t.Fatalf("retired attempt proof: %+v", row)
	}
}

// An episode row lives only while a candidate it names does: deletion
// clears its reference but preserves generation and attempt proof. The
// last retained candidate takes the row. A target whose row is gone opens a new
// episode, so a retired candidate's ID is never minted again.
func TestAdmissionLedgerEpisodeRowsFollowTheirCandidates(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	block := f.arrive(f.arrival(evidenceSpec{cursor: "offset=1"}))[0].Candidate
	promote := f.arrival(evidenceSpec{cursor: "offset=2"})
	promote.Request.Kind = admission.KindPromote
	kept := f.arrive(promote)[0].Candidate
	if _, err := f.l.Terminate(block, admission.ReasonPolicy); err != nil {
		t.Fatal(err)
	}
	f.endMany(admission.MaxEndedCandidates)
	if _, err := f.l.Candidate(block); err != errCandidateMissing {
		t.Fatalf("the ended candidate was not evicted: %v", err)
	}
	if row, ok := f.episodeAt("192.0.2.10"); !ok || len(row.Lines) != 2 || row.Lines[0].Candidate != "" || row.Lines[0].Generation != 1 || row.Lines[1].Candidate != kept {
		t.Fatalf("after eviction = %+v %v", row, ok)
	}
	if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatalf("reopen after eviction: %v", err)
	}

	applied := f.arrive(f.arrival(evidenceSpec{target: "192.0.2.11", cursor: "offset=3"}))[0].Candidate
	_, a, _, err := f.l.Reserve(applied, admission.LaneGeneral, f.wall.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = f.l.Execute(a.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.l.Finish(a.Attempt.ID, admission.DispositionApplied); err != nil {
		t.Fatal(err)
	}
	f.ackAll()
	f.tickAt(f.wall.Add(admission.HistoryTarget + time.Hour))
	if _, err = f.l.Candidate(applied); err != errCandidateMissing {
		t.Fatalf("the applied candidate was not retired: %v", err)
	}
	if row, ok := f.episodeAt("192.0.2.11"); ok {
		t.Fatalf("the row outlived its candidate: %+v", row)
	}
	if _, err = OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatalf("reopen after retirement: %v", err)
	}
	again := f.arrive(f.arrival(evidenceSpec{target: "192.0.2.11", cursor: "offset=4"}))[0]
	if again.Err != nil || !again.Created || again.Candidate == applied {
		t.Fatalf("after retirement = %+v", again)
	}
}

// finishArrival reserves, runs and finishes the candidate an arrival
// queued, with an effect until expires.
func (f *ledgerFixture) finishArrival(id admission.CandidateID, expires time.Time, d admission.Disposition) {
	f.t.Helper()
	_, a, _, err := f.l.Reserve(id, admission.LaneGeneral, expires)
	if err != nil {
		f.t.Fatal(err)
	}
	if _, _, _, err = f.l.Execute(a.Attempt.ID); err != nil {
		f.t.Fatal(err)
	}
	if _, _, err = f.l.Finish(a.Attempt.ID, d); err != nil {
		f.t.Fatal(err)
	}
}

// A verified block ends its episode at its original expiry, not an hour
// after the last observation (spec 5.2): an observation before then is
// refused as an existing effect, and one at the expiry opens the next
// episode.
func TestAdmissionLedgerVerifiedBlockEndsItsEpisodeAtItsExpiry(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	first := f.arrive(f.arrival(evidenceSpec{cursor: "offset=1"}))[0].Candidate
	expiry := ledgerT0.Add(20 * time.Minute)
	f.finishArrival(first, expiry, admission.DispositionApplied)
	if row, _ := f.episodeAt("192.0.2.10"); !row.Verified.Equal(expiry) {
		t.Fatalf("verified end = %v, want %v", row.Verified, expiry)
	}
	f.tickAt(expiry.Add(-time.Second))
	wantLedgerReason(t, "before the expiry", f.arrive(f.arrival(evidenceSpec{cursor: "offset=2"}))[0].Err, admission.ReasonExistingEffect)
	f.tickAt(expiry)
	next := f.arrive(f.arrival(evidenceSpec{cursor: "offset=3"}))[0]
	if c := f.candidateOf(next.Candidate); next.Err != nil || !next.Created || c.Key.Episode == f.candidateOf(first).Key.Episode {
		t.Fatalf("at the expiry = %+v %+v", next, c.Key)
	}
	if row, _ := f.episodeAt("192.0.2.10"); !row.Previous.Equal(expiry) || !row.Verified.IsZero() {
		t.Fatalf("next episode row = %+v", row)
	}
}

// Live work of another kind holds the episode past the block expiry;
// reports it accepted during the hold cannot later become a new episode.
func TestAdmissionLedgerEarlierEpisodeReportsStayEarlier(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	first := f.arrive(f.arrival(evidenceSpec{cursor: "offset=1"}))[0].Candidate
	other := f.arrival(evidenceSpec{cursor: "promotion"})
	other.Request.Kind = admission.KindPromote
	kept := f.arrive(other)[0].Candidate
	expiry := ledgerT0.Add(20 * time.Minute)
	f.finishArrival(first, expiry, admission.DispositionApplied)
	f.tickAt(ledgerT0.Add(25 * time.Minute))
	old := f.arrival(evidenceSpec{cursor: "while-held"})
	wantLedgerReason(t, "held episode", f.arrive(old)[0].Err, admission.ReasonExistingEffect)
	if _, err := f.l.Terminate(kept, admission.ReasonPolicy); err != nil {
		t.Fatal(err)
	}
	wantLedgerReason(t, "report after hold", f.arrive(old)[0].Err, admission.ReasonStale)
	f.tickAt(ledgerT0.Add(26 * time.Minute))
	next := f.arrive(f.arrival(evidenceSpec{cursor: "next-episode"}))[0]
	if next.Err != nil || !next.Created || next.Candidate == first {
		t.Fatalf("new episode: %+v", next)
	}
	row, _ := f.episodeAt("192.0.2.10")
	if !row.Previous.Equal(expiry) || !row.PriorLast.Equal(ledgerT0.Add(25*time.Minute)) {
		t.Fatalf("previous episode proof: %+v", row)
	}
	wantLedgerReason(t, "report after new episode", f.arrive(old)[0].Err, admission.ReasonStale)
}

// Subnet targets use the same transactional assignment and original
// verified boundary as address blocks, with a canonical prefix row key.
func TestAdmissionLedgerVerifiedSubnetEpisodeEndsAtExpiry(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	prefix, err := admission.CanonicalPrefix("192.0.2.0/24", admission.Caps{IPv6: true})
	if err != nil {
		t.Fatal(err)
	}
	e, err := f.ssh.Mint(admission.EvidenceInput{
		Check: "ssh_brute", FindingID: "0123456789abcdef", Severity: admission.SeverityHigh,
		Observation: admission.ObservationRef{Stream: "log:sshd_log", Cursor: "prefix=1", Version: 1},
		ObservedAt:  f.wall, Parser: admission.ParserRef{Name: "fixture", Version: 1}, Target: prefix,
	})
	if err != nil {
		t.Fatal(err)
	}
	first := f.arrive(admission.Arrival{Request: admission.CandidateRequest{Kind: admission.KindBlockSubnet, Target: prefix, Primary: e.ID()}, Evidence: e})[0]
	if first.Err != nil || !first.Created {
		t.Fatalf("subnet arrival: %+v", first)
	}
	expiry := ledgerT0.Add(20 * time.Minute)
	f.finishArrival(first.Candidate, expiry, admission.DispositionApplied)
	episode := f.candidateOf(first.Candidate).Key.Episode
	if err = f.db.bolt.View(func(tx *bolt.Tx) error {
		row, ok, rowErr := loadEpisode(tx, prefix.Key())
		if rowErr != nil || !ok || !row.Verified.Equal(expiry) || row.ID != episode {
			t.Errorf("verified subnet row: %+v %v %v", row, ok, rowErr)
		}
		return rowErr
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatalf("verified subnet open proof: %v", err)
	}
}

// A new threshold must be built entirely from observations after the
// previous verified expiry, including any supplied support.
func TestAdmissionLedgerNextEpisodeRefusesEarlierSupport(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	first := f.arrive(f.arrival(evidenceSpec{cursor: "offset=1"}))[0].Candidate
	expiry := ledgerT0.Add(20 * time.Minute)
	f.finishArrival(first, expiry, admission.DispositionApplied)
	f.tickAt(expiry)
	before, _ := f.episodeAt("192.0.2.10")
	a := f.arrival(evidenceSpec{cursor: "offset=2"})
	a.Request.Support = []admission.EvidenceID{f.published(evidenceSpec{cursor: "before-expiry", age: time.Second})}
	wantLedgerReason(t, "earlier support", f.arrive(a)[0].Err, admission.ReasonStale)
	if after, _ := f.episodeAt("192.0.2.10"); !reflect.DeepEqual(before, after) {
		t.Fatal("earlier support changed the episode")
	}
}

// Only a verified block of the row's episode bounds it by its expiry: an
// unknown outcome cannot (spec 5.2), a verified promotion leaves the
// episode to its quiet hour, and so does a block queued outside it.
func TestAdmissionLedgerOnlyAVerifiedBlockEndsItsEpisode(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	f.arrive(f.arrival(evidenceSpec{target: "192.0.2.12", cursor: "offset=3"}))
	f.nextGeneration()
	outside := f.published(evidenceSpec{target: "192.0.2.12", cursor: "offset=4"})
	_, direct := f.enqueue(f.request("192.0.2.12", outside))
	f.finishArrival(direct, ledgerT0.Add(20*time.Minute), admission.DispositionApplied)
	unknown := f.arrive(f.arrival(evidenceSpec{cursor: "offset=1"}))[0].Candidate
	f.finishArrival(unknown, ledgerT0.Add(20*time.Minute), admission.DispositionUnknown)
	promote := f.arrival(evidenceSpec{target: "192.0.2.11", cursor: "offset=2"})
	promote.Request.Kind = admission.KindPromote
	promoted := f.arrive(promote)[0].Candidate
	f.finishArrival(promoted, ledgerT0.Add(20*time.Minute), admission.DispositionApplied)
	for _, addr := range []string{"192.0.2.10", "192.0.2.11", "192.0.2.12"} {
		if row, ok := f.episodeAt(addr); !ok || !row.Verified.IsZero() || !row.End().Equal(ledgerT0.Add(admission.EpisodeQuiet)) {
			t.Errorf("%s: row = %+v %v", addr, row, ok)
		}
	}
}
