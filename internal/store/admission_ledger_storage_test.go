package store

import (
	"encoding/binary"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

func historyEntryIn(t *testing.T, db *DB, id admission.CandidateID) (admission.HistoryEntry, bool) {
	t.Helper()
	var h admission.HistoryEntry
	var found bool
	if err := db.bolt.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket([]byte(admissionHistoryBucket)).Get([]byte(id))
		if raw == nil {
			return nil
		}
		found = true
		var err error
		h, err = admission.UnmarshalHistoryEntry(raw)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return h, found
}

func refsIn(t *testing.T, db *DB, id admission.EvidenceID) (admission.EvidenceRefs, bool) {
	t.Helper()
	var r admission.EvidenceRefs
	var found bool
	if err := db.bolt.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket([]byte(admissionRefsBucket)).Get([]byte(id))
		if raw == nil {
			return nil
		}
		found = true
		var err error
		r, err = admission.UnmarshalEvidenceRefs(raw)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return r, found
}

func ringIn(t *testing.T, db *DB, kind byte) map[uint64]string {
	t.Helper()
	out := map[uint64]string{}
	if err := db.bolt.View(func(tx *bolt.Tx) error {
		c := tx.Bucket([]byte(admissionRingsBucket)).Cursor()
		for k, v := c.Seek([]byte{kind}); k != nil && k[0] == kind; k, v = c.Next() {
			out[binary.BigEndian.Uint64(k[1:])] = string(v)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func costIn(t *testing.T, db *DB, id admission.CandidateID) uint32 {
	t.Helper()
	var cost uint32
	if err := db.bolt.View(func(tx *bolt.Tx) error {
		c, err := loadCandidate(tx, id)
		if err != nil {
			return err
		}
		cost, err = historyCostOf(tx, c)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return cost
}

// mixedLedger holds one candidate in each storage class: queued without an
// attempt, reserved, ended before any attempt, applied and unresolved, plus
// evidence no candidate names.
type mixedLedger struct {
	queued, reserved, ended, applied, unknown admission.CandidateID
	appliedAt, unknownAt                      time.Time
	loose                                     admission.EvidenceID
}

func (f *ledgerFixture) mixed() mixedLedger {
	f.t.Helper()
	var m mixedLedger
	m.queued = f.queued()
	f.nextGeneration()
	m.reserved = f.queued()
	if _, _, _, err := f.l.Reserve(m.reserved, admission.LaneGeneral, f.wall.Add(time.Hour)); err != nil {
		f.t.Fatal(err)
	}
	f.nextGeneration()
	m.ended = f.queued()
	if _, err := f.l.Terminate(m.ended, admission.ReasonProtected); err != nil {
		f.t.Fatal(err)
	}
	f.nextGeneration()
	m.applied = f.queued()
	_, a, _, err := f.l.Reserve(m.applied, admission.LaneGeneral, f.wall.Add(time.Hour))
	if err != nil {
		f.t.Fatal(err)
	}
	f.tickAt(f.wall.Add(time.Second))
	if _, _, _, err = f.l.Execute(a.Attempt.ID); err != nil {
		f.t.Fatal(err)
	}
	if _, _, err = f.l.Finish(a.Attempt.ID, admission.DispositionApplied); err != nil {
		f.t.Fatal(err)
	}
	m.appliedAt = f.wall
	direct := f.published(evidenceSpec{producer: f.mail, check: "mail_takeover", target: "192.0.2.11", cursor: "direct", severity: admission.SeverityCritical})
	_, m.unknown = f.enqueue(f.request("192.0.2.11", direct))
	if _, a, _, err = f.l.Reserve(m.unknown, admission.LaneDirect, f.wall.Add(time.Hour)); err != nil {
		f.t.Fatal(err)
	}
	f.tickAt(f.wall.Add(time.Second))
	if _, _, _, err = f.l.Execute(a.Attempt.ID); err != nil {
		f.t.Fatal(err)
	}
	if _, _, err = f.l.Finish(a.Attempt.ID, admission.DispositionUnknown); err != nil {
		f.t.Fatal(err)
	}
	m.unknownAt = f.wall
	m.loose = f.published(evidenceSpec{target: "192.0.2.12", cursor: "loose"})
	return m
}

// A schema 3 ledger is upgraded once, in the opening transaction: every
// schema 3 record stays byte for byte, each admitted candidate is charged
// its history cost, an unresolved one is held in the recovery reserve, the
// ended candidate and the loose evidence take the first ring positions,
// and the allowances start without credit. Opening again changes nothing.
func TestAdmissionLedgerUpgradesSchemaThree(t *testing.T) {
	f := newLedgerFixture(t)
	m := f.mixed()
	f.schemaThree()
	before := dbSnapshot(t, f.db)
	db := f.copyDatabase()
	l, err := OpenAdmissionLedger(db, f.reg)
	if err != nil {
		t.Fatal(err)
	}
	after := dbSnapshot(t, db)
	schemaKey := admissionMetaBucket + ":" + string(admissionSchemaKey)
	for k, v := range before {
		if after[k] != v && k != schemaKey {
			t.Fatalf("upgrade changed schema 3 record %s", k)
		}
	}
	if after[schemaKey] != string([]byte{admissionSchemaVersion}) {
		t.Fatalf("upgraded schema = %q", after[schemaKey])
	}
	reserved, applied, unknown := costIn(t, db, m.reserved), costIn(t, db, m.applied), costIn(t, db, m.unknown)
	s, err := l.Storage()
	want := admission.StorageState{
		General:  admission.HistoryMeter{Used: uint64(reserved) + uint64(applied)},
		Recovery: uint64(unknown),
		Ended:    admission.RingState{Count: 1, Last: 1},
		Loose:    admission.RingState{Count: 1, Last: 1},
		// The chain ends at schema 5, whose outbox starts with the fixed
		// notice records.
		NoticeRecords: admission.FixedNotices,
	}
	if err != nil || s != want {
		t.Fatalf("upgraded storage = %+v, %v\nwant %+v", s, err, want)
	}
	for id, wantEntry := range map[admission.CandidateID]admission.HistoryEntry{
		m.reserved: {RootMask: 1, General: reserved},
		m.applied:  {RootMask: 1, General: applied, Ended: m.appliedAt, Eligible: m.appliedAt.Add(admission.HistoryRetention)},
		m.unknown:  {RootMask: 1, Reserved: unknown, Ended: m.unknownAt, Pinned: true},
	} {
		if h, found := historyEntryIn(t, db, id); !found || h != wantEntry {
			t.Errorf("history of %s = %+v (found %t), want %+v", id, h, found, wantEntry)
		}
	}
	for _, id := range []admission.CandidateID{m.queued, m.ended} {
		if _, found := historyEntryIn(t, db, id); found {
			t.Errorf("%s has a history entry without an attempt", id)
		}
	}
	if got := ringIn(t, db, ringEnded); !reflect.DeepEqual(got, map[uint64]string{1: string(m.ended)}) {
		t.Errorf("ended ring = %v", got)
	}
	if got := ringIn(t, db, ringLoose); !reflect.DeepEqual(got, map[uint64]string{1: string(m.loose)}) {
		t.Errorf("loose ring = %v", got)
	}
	if r, found := refsIn(t, db, m.loose); !found || r != (admission.EvidenceRefs{Loose: 1}) {
		t.Errorf("loose evidence refs = %+v (found %t)", r, found)
	}
	for _, id := range []admission.CandidateID{m.queued, m.reserved, m.ended, m.applied, m.unknown} {
		c, loadErr := l.Candidate(id)
		if loadErr != nil {
			t.Fatal(loadErr)
		}
		if r, found := refsIn(t, db, c.Roots[0]); !found || r != (admission.EvidenceRefs{Refs: 1}) {
			t.Errorf("root of %s refs = %+v (found %t)", id, r, found)
		}
	}
	// Only the applied candidate has ended unpinned, so only it is indexed.
	var keys int
	if err = db.bolt.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(admissionRetireBucket)).ForEach(func(k, _ []byte) error {
			if _, _, id, keyErr := admission.ParseRetireKey(k); keyErr != nil || id != m.applied {
				t.Errorf("index key %q: %v", k, keyErr)
			}
			keys++
			return nil
		})
	}); err != nil || keys != 2 {
		t.Fatalf("retirement keys = %d, %v", keys, err)
	}
	if _, err = OpenAdmissionLedger(db, f.reg); err != nil {
		t.Fatal(err)
	}
	if again := dbSnapshot(t, db); !reflect.DeepEqual(again, after) {
		t.Fatal("a second open changed the upgraded ledger")
	}
}

// An upgrade keeps only the newest ring entries. Older candidates that
// ended before any attempt are removed, and their roots lose a reference;
// older loose evidence is removed with its report links.
func TestAdmissionLedgerUpgradeKeepsTheNewestRingEntries(t *testing.T) {
	f := newLedgerFixture(t)
	id := f.queued()
	ended, err := f.l.Terminate(id, admission.ReasonProtected)
	if err != nil {
		t.Fatal(err)
	}
	oldest := f.published(evidenceSpec{target: "192.0.2.12", cursor: "loose-0", age: time.Hour})
	if err = f.l.LinkReport(oldest, "fedcba9876543210"); err != nil {
		t.Fatal(err)
	}
	extra := 2
	var endings []admission.CandidateID
	if err = f.db.bolt.Update(func(tx *bolt.Tx) error {
		for i := 1; i <= admission.MaxEndedCandidates+extra; i++ {
			c := ended
			c.Key.Generation = uint32(100 + i)
			c.FirstQueued = ended.FirstQueued.Add(time.Duration(i) * time.Millisecond)
			c.AgeOut = c.FirstQueued.Add(time.Hour)
			cid, _ := c.ID()
			endings = append(endings, cid)
			if putErr := putCandidate(tx, c); putErr != nil {
				return putErr
			}
		}
		for i := 1; i < admission.MaxLooseEvidence+extra; i++ {
			e := f.mint(evidenceSpec{target: "192.0.2.12", cursor: fmt.Sprintf("loose-%d", i), age: time.Hour - time.Duration(i)*time.Millisecond})
			data, encErr := e.MarshalBinary()
			if encErr != nil {
				return encErr
			}
			if putErr := tx.Bucket([]byte(admissionEvidenceBucket)).Put([]byte(e.ID()), data); putErr != nil {
				return putErr
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	f.schemaThree()
	db := f.copyDatabase()
	l, err := OpenAdmissionLedger(db, f.reg)
	if err != nil {
		t.Fatal(err)
	}
	s, err := l.Storage()
	if err != nil || s.Ended != (admission.RingState{Count: admission.MaxEndedCandidates, Last: admission.MaxEndedCandidates}) ||
		s.Loose != (admission.RingState{Count: admission.MaxLooseEvidence, Last: admission.MaxLooseEvidence}) {
		t.Fatalf("rings = %+v, %+v, %v", s.Ended, s.Loose, err)
	}
	// The original ending and the first extra one are the oldest.
	for _, gone := range []admission.CandidateID{id, endings[0]} {
		if _, err = l.Candidate(gone); err != errCandidateMissing {
			t.Errorf("oldest ending %s: %v", gone, err)
		}
	}
	if c, loadErr := l.Candidate(endings[len(endings)-1]); loadErr != nil || c.State != admission.StateRefused {
		t.Fatalf("newest ending: %+v, %v", c, loadErr)
	}
	if r, found := refsIn(t, db, ended.Roots[0]); !found || r != (admission.EvidenceRefs{Refs: admission.MaxEndedCandidates}) {
		t.Fatalf("shared root refs = %+v (found %t)", r, found)
	}
	if _, err = l.LoadEvidence(oldest); err != admission.ErrEvidenceUnpublished {
		t.Fatalf("oldest loose evidence: %v", err)
	}
	if err = db.bolt.View(func(tx *bolt.Tx) error {
		if tx.Bucket([]byte(admissionReportsBucket)).Get([]byte(oldest)) != nil {
			t.Error("removed evidence kept its report links")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// A failed schema 3 upgrade leaves the ledger exactly as it was.
func TestAdmissionLedgerUpgradeFromThreeRollsBack(t *testing.T) {
	for name, damage := range map[string]func(f *ledgerFixture, m mixedLedger, tx *bolt.Tx) error{
		"a root that was never stored": func(f *ledgerFixture, m mixedLedger, tx *bolt.Tx) error {
			c, err := loadCandidate(tx, m.queued)
			if err != nil {
				return err
			}
			return tx.Bucket([]byte(admissionEvidenceBucket)).Delete([]byte(c.Roots[0]))
		},
		"an attempt of an ended candidate": func(f *ledgerFixture, m mixedLedger, tx *bolt.Tx) error {
			a, err := admission.NewAttempt(m.applied, 1)
			if err != nil {
				return err
			}
			return tx.Bucket([]byte(admissionAttemptsBucket)).Put([]byte(a.ID), []byte("damaged"))
		},
		"a storage record beside schema 3": func(f *ledgerFixture, m mixedLedger, tx *bolt.Tx) error {
			return putStorageState(tx, admission.StorageState{})
		},
		"damaged evidence": func(f *ledgerFixture, m mixedLedger, tx *bolt.Tx) error {
			return tx.Bucket([]byte(admissionEvidenceBucket)).Put([]byte(m.loose), []byte("damaged"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newLedgerFixture(t)
			m := f.mixed()
			f.schemaThree()
			if err := f.db.bolt.Update(func(tx *bolt.Tx) error { return damage(f, m, tx) }); err != nil {
				t.Fatal(err)
			}
			db := f.copyDatabase()
			before := dbSnapshot(t, db)
			if _, err := OpenAdmissionLedger(db, f.reg); !isCorrupt(err) {
				t.Fatalf("err = %v, want a corrupt record", err)
			}
			if !reflect.DeepEqual(before, dbSnapshot(t, db)) {
				t.Fatal("a failed upgrade changed the schema 3 ledger")
			}
		})
	}
}

// The storage state must match what is stored: history entries that do not
// add up to the recorded usage, rings that do not hold what they count, or
// damaged entries refuse the open.
func TestAdmissionLedgerOpenChecksStorage(t *testing.T) {
	for name, damage := range map[string]func(m mixedLedger, tx *bolt.Tx) error{
		"general usage": func(_ mixedLedger, tx *bolt.Tx) error {
			return adjustStorage(tx, func(s *admission.StorageState) { s.General.Used++ })
		},
		"reserved usage": func(_ mixedLedger, tx *bolt.Tx) error {
			return adjustStorage(tx, func(s *admission.StorageState) { s.Reserved.Used++ })
		},
		"recovery": func(_ mixedLedger, tx *bolt.Tx) error {
			return adjustStorage(tx, func(s *admission.StorageState) { s.Recovery-- })
		},
		"ended count": func(_ mixedLedger, tx *bolt.Tx) error {
			return adjustStorage(tx, func(s *admission.StorageState) { s.Ended.Count, s.Ended.Last = 2, 2 })
		},
		"loose position beyond the last": func(_ mixedLedger, tx *bolt.Tx) error {
			rings := tx.Bucket([]byte(admissionRingsBucket))
			v := rings.Get(ringKey(ringLoose, 1))
			if err := rings.Delete(ringKey(ringLoose, 1)); err != nil {
				return err
			}
			data, err := (admission.EvidenceRefs{Loose: 2}).MarshalBinary()
			if err != nil {
				return err
			}
			if err = tx.Bucket([]byte(admissionRefsBucket)).Put(v, data); err != nil {
				return err
			}
			return rings.Put(ringKey(ringLoose, 2), v)
		},
		"position zero": func(_ mixedLedger, tx *bolt.Tx) error {
			rings := tx.Bucket([]byte(admissionRingsBucket))
			v := rings.Get(ringKey(ringEnded, 1))
			if err := rings.Delete(ringKey(ringEnded, 1)); err != nil {
				return err
			}
			return rings.Put(ringKey(ringEnded, 0), v)
		},
		"unknown ring": func(_ mixedLedger, tx *bolt.Tx) error {
			return tx.Bucket([]byte(admissionRingsBucket)).Put(ringKey('x', 1), []byte("x"))
		},
		"damaged history entry": func(m mixedLedger, tx *bolt.Tx) error {
			return tx.Bucket([]byte(admissionHistoryBucket)).Put([]byte(m.reserved), []byte("damaged"))
		},
		"history under another key": func(m mixedLedger, tx *bolt.Tx) error {
			b := tx.Bucket([]byte(admissionHistoryBucket))
			v := b.Get([]byte(m.reserved))
			if err := b.Delete([]byte(m.reserved)); err != nil {
				return err
			}
			return b.Put([]byte("stray"), v)
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newLedgerFixture(t)
			m := f.mixed()
			f.schemaThree()
			l, err := OpenAdmissionLedger(f.db, f.reg)
			if err != nil {
				t.Fatal(err)
			}
			f.l = l
			if err = f.db.bolt.Update(func(tx *bolt.Tx) error { return damage(m, tx) }); err != nil {
				t.Fatal(err)
			}
			before := dbSnapshot(t, f.db)
			if _, err = OpenAdmissionLedger(f.db, f.reg); !isCorrupt(err) {
				t.Fatalf("err = %v, want a corrupt record", err)
			}
			if !reflect.DeepEqual(before, dbSnapshot(t, f.db)) {
				t.Fatal("a refused open changed the ledger")
			}
		})
	}
}

func adjustStorage(tx *bolt.Tx, mutate func(*admission.StorageState)) error {
	s, err := loadStorageState(tx)
	if err != nil {
		return err
	}
	mutate(&s)
	return putStorageState(tx, s)
}

func TestAdmissionLedgerUpgradeRejectsUnownedRows(t *testing.T) {
	for _, schema := range []byte{1, 2, 3} {
		for _, kind := range []string{"report", "nested report", "attempt", "bucket"} {
			t.Run(fmt.Sprintf("%d/%s", schema, kind), func(t *testing.T) {
				f := newLedgerFixture(t)
				id := f.queued()
				_, a, _, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour))
				if err != nil {
					t.Fatal(err)
				}
				if schema < 3 {
					f.schemaTwo()
				} else {
					f.schemaThree()
				}
				if err = f.db.bolt.Update(func(tx *bolt.Tx) error {
					if schema == 1 {
						for _, name := range admissionQueueBuckets {
							if e := tx.DeleteBucket([]byte(name)); e != nil {
								return e
							}
						}
					}
					if e := tx.Bucket([]byte(admissionMetaBucket)).Put(admissionSchemaKey, []byte{schema}); e != nil {
						return e
					}
					switch kind {
					case "report":
						return tx.Bucket([]byte(admissionReportsBucket)).Put([]byte("ev_00000000000000000000000000000000"), []byte("damaged"))
					case "nested report":
						c, loadErr := loadCandidate(tx, id)
						if loadErr != nil {
							return loadErr
						}
						_, createErr := tx.Bucket([]byte(admissionReportsBucket)).CreateBucket([]byte(c.Roots[0]))
						return createErr
					case "attempt":
						a.Attempt, _ = admission.NewAttempt(admission.CandidateID("cand_00000000000000000000000000000000"), 1)
						return putAttempt(tx, a)
					default:
						_, e := tx.CreateBucket([]byte("adm:unknown"))
						return e
					}
				}); err != nil {
					t.Fatal(err)
				}
				before := dbSnapshot(t, f.db)
				if _, err = OpenAdmissionLedger(f.db, f.reg); !isCorrupt(err) {
					t.Fatalf("unowned row opened: %v", err)
				}
				if !reflect.DeepEqual(before, dbSnapshot(t, f.db)) {
					t.Fatal("refused upgrade changed the ledger")
				}
			})
		}
	}
}

// A schema-4 ledger proves the rows no candidate walk reaches at every open,
// not only during an upgrade.
func TestAdmissionLedgerOpenRejectsUnownedRows(t *testing.T) {
	for _, kind := range []string{"report", "nested report", "foreign attempt", "attempt past the count"} {
		t.Run(kind, func(t *testing.T) {
			f := newLedgerFixture(t)
			id := f.queued()
			_, a, _, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			if err = f.db.bolt.Update(func(tx *bolt.Tx) error {
				switch kind {
				case "report":
					return tx.Bucket([]byte(admissionReportsBucket)).Put([]byte("ev_00000000000000000000000000000000"), []byte("damaged"))
				case "nested report":
					c, loadErr := loadCandidate(tx, id)
					if loadErr != nil {
						return loadErr
					}
					_, createErr := tx.Bucket([]byte(admissionReportsBucket)).CreateBucket([]byte(c.Roots[0]))
					return createErr
				case "foreign attempt":
					a.Attempt, _ = admission.NewAttempt(admission.CandidateID("cand_00000000000000000000000000000000"), 1)
				default:
					a.Attempt, _ = admission.NewAttempt(id, 2)
				}
				return putAttempt(tx, a)
			}); err != nil {
				t.Fatal(err)
			}
			before := dbSnapshot(t, f.db)
			if _, err = OpenAdmissionLedger(f.db, f.reg); !isCorrupt(err) {
				t.Fatalf("unowned row opened: %v", err)
			}
			if !reflect.DeepEqual(before, dbSnapshot(t, f.db)) {
				t.Fatal("refused open changed the ledger")
			}
		})
	}
}

// Damage that keeps every total balanced: only the ownership proof can
// refuse it, so each case pins one of its guards.
func TestAdmissionLedgerOpenRefusesBalancedDamage(t *testing.T) {
	for name, damage := range map[string]func(*testing.T, *bolt.Tx, mixedLedger) error{
		"queued root evidence missing": func(_ *testing.T, tx *bolt.Tx, m mixedLedger) error {
			c, err := loadCandidate(tx, m.queued)
			if err != nil {
				return err
			}
			for _, b := range []string{admissionEvidenceBucket, admissionRefsBucket, admissionReportsBucket} {
				if err = tx.Bucket([]byte(b)).Delete([]byte(c.Roots[0])); err != nil {
					return err
				}
			}
			return nil
		},
		"orphan reference row": func(_ *testing.T, tx *bolt.Tx, _ mixedLedger) error {
			return putRefs(tx, admission.EvidenceID("ev_00000000000000000000000000000000"), admission.EvidenceRefs{Refs: 1})
		},
		"unknown outcome unpinned": func(_ *testing.T, tx *bolt.Tx, m mixedLedger) error {
			h, _, err := loadHistoryEntry(tx, m.unknown)
			if err != nil {
				return err
			}
			c, err := loadCandidate(tx, m.unknown)
			if err != nil {
				return err
			}
			h.Pinned = false
			h.Eligible, _ = admission.HistoryTimes(h.Ended, c.ExpiresAt, false)
			if err = putHistoryEntry(tx, m.unknown, h); err != nil {
				return err
			}
			return adjustStorage(tx, func(s *admission.StorageState) {
				s.Recovery -= uint64(h.Charged())
				s.General.Used += uint64(h.General)
				s.Reserved.Used += uint64(h.Reserved)
			})
		},
		"ring position beyond the last": func(t *testing.T, tx *bolt.Tx, _ mixedLedger) error {
			rings := tx.Bucket([]byte(admissionRingsBucket))
			k, v := rings.Cursor().Seek([]byte{ringEnded})
			if k == nil || k[0] != ringEnded {
				t.Fatal("no ended ring entry")
			}
			id := append([]byte(nil), v...)
			if err := rings.Delete(k); err != nil {
				return err
			}
			s, err := loadStorageState(tx)
			if err != nil {
				return err
			}
			// A later push would overwrite this live slot.
			return rings.Put(ringKey(ringEnded, s.Ended.Last+5), id)
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newLedgerFixture(t)
			m := f.mixed()
			if err := f.db.bolt.Update(func(tx *bolt.Tx) error { return damage(t, tx, m) }); err != nil {
				t.Fatal(err)
			}
			before := dbSnapshot(t, f.db)
			if _, err := OpenAdmissionLedger(f.db, f.reg); !isCorrupt(err) {
				t.Fatalf("damage opened: %v", err)
			}
			if !reflect.DeepEqual(before, dbSnapshot(t, f.db)) {
				t.Fatal("refused open changed the ledger")
			}
		})
	}
	// Reservation froze every root: a reserved candidate must still own all of
	// them, though its paid cost would cover a smaller mask.
	t.Run("reserved candidate with a partial root mask", func(t *testing.T) {
		f := newLedgerFixture(t)
		f.fillRoots(1, admission.MaxRoots)
		ids := f.queuedIDs()
		if len(ids) != 1 {
			t.Fatalf("queued %d candidates", len(ids))
		}
		if _, _, _, err := f.l.Reserve(ids[0], admission.LaneGeneral, f.wall.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
			h, _, err := loadHistoryEntry(tx, ids[0])
			if err != nil {
				return err
			}
			h.RootMask = 1
			return putHistoryEntry(tx, ids[0], h)
		}); err != nil {
			t.Fatal(err)
		}
		before := dbSnapshot(t, f.db)
		if _, err := OpenAdmissionLedger(f.db, f.reg); !isCorrupt(err) {
			t.Fatalf("partial mask opened: %v", err)
		}
		if !reflect.DeepEqual(before, dbSnapshot(t, f.db)) {
			t.Fatal("refused open changed the ledger")
		}
	})
}

// Validate missing roots before pruning can erase their last owner. This
// also keeps the upgrade guard observable after the final ownership proof.
func TestAdmissionLedgerUpgradeRejectsPrunedMissingRoot(t *testing.T) {
	f := newLedgerFixture(t)
	id := f.queued()
	ended, err := f.l.Terminate(id, admission.ReasonProtected)
	if err != nil {
		t.Fatal(err)
	}
	kept := f.published(evidenceSpec{cursor: "retained-root"})
	if err = f.db.bolt.Update(func(tx *bolt.Tx) error {
		for i := 1; i <= admission.MaxEndedCandidates+1; i++ {
			c := ended
			c.Key.Generation = uint32(i + 2)
			c.FirstQueued = c.FirstQueued.Add(time.Duration(i) * time.Nanosecond)
			c.AgeOut = c.FirstQueued.Add(time.Hour)
			c.Roots = []admission.EvidenceID{kept}
			if putErr := putCandidate(tx, c); putErr != nil {
				return putErr
			}
		}
		return tx.Bucket([]byte(admissionEvidenceBucket)).Delete([]byte(ended.Roots[0]))
	}); err != nil {
		t.Fatal(err)
	}
	f.schemaThree()
	before := dbSnapshot(t, f.db)
	if _, err = OpenAdmissionLedger(f.db, f.reg); !isCorrupt(err) {
		t.Fatalf("pruning hid a missing root: %v", err)
	}
	if !reflect.DeepEqual(before, dbSnapshot(t, f.db)) {
		t.Fatal("refused upgrade pruned legacy history")
	}
}

func TestAdmissionLedgerRejectsUnknownStateRows(t *testing.T) {
	for _, schema := range []byte{1, 2, 3, 4} {
		names := []string{admissionMetaBucket}
		if schema > 1 {
			names = append(names, admissionQueueStateBucket)
		}
		for _, name := range names {
			for _, nested := range []bool{false, true} {
				t.Run(fmt.Sprintf("%d/%s/%t", schema, name, nested), func(t *testing.T) {
					f := newLedgerFixture(t)
					if schema < 3 {
						f.schemaTwo()
					} else if schema == 3 {
						f.schemaThree()
					}
					if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
						if schema == 1 {
							for _, bucket := range admissionQueueBuckets {
								if err := tx.DeleteBucket([]byte(bucket)); err != nil {
									return err
								}
							}
						}
						if err := tx.Bucket([]byte(admissionMetaBucket)).Put(admissionSchemaKey, []byte{schema}); err != nil {
							return err
						}
						b := tx.Bucket([]byte(name))
						if nested {
							_, err := b.CreateBucket([]byte("unknown"))
							return err
						}
						return b.Put([]byte("unknown"), []byte("row"))
					}); err != nil {
						t.Fatal(err)
					}
					before := dbSnapshot(t, f.db)
					if _, err := OpenAdmissionLedger(f.db, f.reg); !isCorrupt(err) {
						t.Fatalf("unknown state row opened: %v", err)
					}
					if !reflect.DeepEqual(before, dbSnapshot(t, f.db)) {
						t.Fatal("refused open changed state rows")
					}
				})
			}
		}
	}
}
