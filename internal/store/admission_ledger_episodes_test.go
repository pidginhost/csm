package store

import (
	"reflect"
	"strings"
	"testing"

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
