package store

import (
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// dropIntents removes the schema 7 intent bucket, if present, and what each
// unresolved outcome holds for recovery: its intent bytes and the slot of
// its retirement row.
func dropIntents(tx *bolt.Tx) error {
	if tx.Bucket([]byte(admissionIntentsBucket)) == nil {
		return nil
	}
	if tx.Bucket([]byte(admissionQueueStateBucket)).Get(storageStateKey) != nil {
		var pinned uint64
		if err := tx.Bucket([]byte(admissionHistoryBucket)).ForEach(func(_, v []byte) error {
			h, err := admission.UnmarshalHistoryEntry(v)
			if h.Pinned {
				pinned++
			}
			return err
		}); err != nil {
			return err
		}
		if err := adjustStorage(tx, func(s *admission.StorageState) {
			s.Recovery -= pinned * admission.MaxIntentBytes
			if tx.Bucket([]byte(admissionOutboxBucket)) != nil {
				s.AuditSlots -= pinned
			}
		}); err != nil {
			return err
		}
	}
	return tx.DeleteBucket([]byte(admissionIntentsBucket))
}

// schemaSix rewrites the fixture's database into the schema 6 layout: the
// same records without intents.
func (f *ledgerFixture) schemaSix() {
	f.t.Helper()
	if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
		if err := dropIntents(tx); err != nil {
			return err
		}
		return tx.Bucket([]byte(admissionMetaBucket)).Put(admissionSchemaKey, []byte{6})
	}); err != nil {
		f.t.Fatal(err)
	}
}

// intents is every stored intent, by its action.
func (f *ledgerFixture) intents() map[admission.ActionID]admission.Intent {
	f.t.Helper()
	out := map[admission.ActionID]admission.Intent{}
	if err := f.db.bolt.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(admissionIntentsBucket)).ForEach(func(k, v []byte) error {
			in, err := admission.UnmarshalIntent(v)
			if err != nil {
				return err
			}
			out[admission.ActionID(k)] = in
			return nil
		})
	}); err != nil {
		f.t.Fatal(err)
	}
	return out
}

// reservedAt queues a candidate at target from a fresh root and reserves
// its first attempt to expire at expires.
func (f *ledgerFixture) reservedAt(target string, expires time.Time) admission.AttemptRecord {
	f.t.Helper()
	root := f.published(evidenceSpec{target: target, cursor: "offset=" + target})
	_, id := f.enqueue(f.request(target, root))
	_, a, granted, err := f.l.Reserve(id, admission.LaneGeneral, expires)
	if err != nil || !granted {
		f.t.Fatalf("reserve %s: %v %v", target, granted, err)
	}
	return a
}

func batchOf(t *testing.T, ids ...admission.ActionID) admission.BatchID {
	t.Helper()
	b, err := admission.NewBatchID(ids)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Executing records what each member may apply before the caller touches
// the host: one row per member, named by the batch, with the candidate's
// kind and target and the attempt's absolute expiry. Executing the same
// members again is a readback; a member that runs in another batch
// refuses the whole call.
func TestAdmissionLedgerExecuteRecordsTheBatchIntent(t *testing.T) {
	f := newLedgerFixture(t)
	a1 := f.reservedAt("192.0.2.10", ledgerT0.Add(time.Hour))
	a2 := f.reservedAt("192.0.2.11", ledgerT0.Add(2*time.Hour))
	batch := batchOf(t, a1.Attempt.ID, a2.Attempt.ID)
	got, granted, err := f.l.ExecuteBatch([]admission.ActionID{a2.Attempt.ID, a1.Attempt.ID})
	if err != nil || !granted || len(got) != 2 {
		t.Fatalf("execute: %v %v %v", got, granted, err)
	}
	want := map[admission.ActionID]admission.Intent{
		a1.Attempt.ID: {Action: a1.Attempt.ID, Batch: batch, Kind: admission.KindBlockIP, Target: f.target("192.0.2.10"), ExpiresAt: a1.ExpiresAt},
		a2.Attempt.ID: {Action: a2.Attempt.ID, Batch: batch, Kind: admission.KindBlockIP, Target: f.target("192.0.2.11"), ExpiresAt: a2.ExpiresAt},
	}
	if got[0] != want[a2.Attempt.ID] || got[1] != want[a1.Attempt.ID] {
		t.Fatalf("returned intents = %+v", got)
	}
	if stored := f.intents(); !reflect.DeepEqual(stored, want) {
		t.Fatalf("stored intents = %+v", stored)
	}
	for _, a := range []admission.AttemptRecord{a1, a2} {
		running, readErr := f.l.Attempt(a.Attempt.ID)
		c, candErr := f.l.Candidate(a.Attempt.Candidate)
		if readErr != nil || candErr != nil || running.State != admission.StateExecuting || c.State != admission.StateExecuting {
			t.Fatalf("%s: attempt %+v candidate %+v %v %v", a.Attempt.ID, running, c, readErr, candErr)
		}
	}
	before := f.snapshot()
	again, granted, err := f.l.ExecuteBatch([]admission.ActionID{a1.Attempt.ID, a2.Attempt.ID})
	if err != nil || granted || !reflect.DeepEqual(again, []admission.Intent{want[a1.Attempt.ID], want[a2.Attempt.ID]}) {
		t.Fatalf("readback: %+v %v %v", again, granted, err)
	}
	if after := f.snapshot(); !reflect.DeepEqual(after, before) {
		t.Fatal("a readback changed the ledger")
	}
	a3 := f.reservedAt("192.0.2.12", ledgerT0.Add(time.Hour))
	before = f.snapshot()
	for name, ids := range map[string][]admission.ActionID{
		"member of another batch": {a1.Attempt.ID, a3.Attempt.ID},
		"part of a batch":         {a1.Attempt.ID},
	} {
		_, _, err = f.l.ExecuteBatch(ids)
		wantLedgerErr(t, name, err, admission.ErrTransitionConflict)
	}
	if after := f.snapshot(); !reflect.DeepEqual(after, before) {
		t.Fatal("a refused batch changed the ledger")
	}
}

// One member that cannot run refuses the batch: nothing is written for the
// members that could.
func TestAdmissionLedgerExecuteRefusesTheWholeBatch(t *testing.T) {
	f := newLedgerFixture(t)
	a1 := f.reservedAt("192.0.2.10", ledgerT0.Add(time.Hour))
	stale := f.reservedAt("192.0.2.11", ledgerT0.Add(time.Minute))
	ended := f.reservedAt("192.0.2.12", ledgerT0.Add(time.Hour))
	if _, _, err := f.l.Finish(ended.Attempt.ID, admission.DispositionFailed); err != nil {
		t.Fatal(err)
	}
	f.tickAt(ledgerT0.Add(time.Minute))
	before := f.snapshot()
	_, _, err := f.l.ExecuteBatch([]admission.ActionID{a1.Attempt.ID, stale.Attempt.ID})
	wantLedgerReason(t, "expired member", err, admission.ReasonStale)
	_, _, err = f.l.ExecuteBatch([]admission.ActionID{a1.Attempt.ID, ended.Attempt.ID})
	wantLedgerErr(t, "ended member", err, admission.ErrTransitionConflict)
	missing, idErr := admission.NewAttempt(a1.Attempt.Candidate, 3)
	if idErr != nil {
		t.Fatal(idErr)
	}
	for name, ids := range map[string][]admission.ActionID{
		"unrecorded member": {a1.Attempt.ID, missing.ID},
		"repeated member":   {a1.Attempt.ID, a1.Attempt.ID},
		"no member":         nil,
	} {
		_, _, err = f.l.ExecuteBatch(ids)
		wantLedgerReason(t, name, err, admission.ReasonInvalid)
	}
	if after := f.snapshot(); !reflect.DeepEqual(after, before) {
		t.Fatal("a refused batch changed the ledger")
	}
	f.failNext("execute")
	if _, _, err = f.l.ExecuteBatch([]admission.ActionID{a1.Attempt.ID}); err == nil {
		t.Fatal("injected commit failure was ignored")
	}
	if after := f.snapshot(); !reflect.DeepEqual(after, before) {
		t.Fatal("a failed execution left records behind")
	}
}

// A member's intent stays only while its outcome is unresolved: applied and
// failed attempts retire it with the outcome, an unknown one keeps it, and
// an attempt that never ran has none.
func TestAdmissionLedgerOutcomeSettlesTheIntent(t *testing.T) {
	f := newLedgerFixture(t)
	expires := ledgerT0.Add(time.Hour)
	applied, failed, unknown := f.reservedAt("192.0.2.10", expires), f.reservedAt("192.0.2.11", expires), f.reservedAt("192.0.2.12", expires)
	unrun := f.reservedAt("192.0.2.13", expires)
	for _, a := range []admission.AttemptRecord{applied, failed, unknown} {
		if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(f.intents()); n != 3 {
		t.Fatalf("running intents = %d", n)
	}
	for a, d := range map[admission.AttemptRecord]admission.Disposition{
		applied: admission.DispositionApplied, failed: admission.DispositionFailed,
		unknown: admission.DispositionUnknown, unrun: admission.DispositionFailed,
	} {
		if _, _, err := f.l.Finish(a.Attempt.ID, d); err != nil {
			t.Fatalf("finish %s: %v", d, err)
		}
	}
	stored := f.intents()
	if _, kept := stored[unknown.Attempt.ID]; len(stored) != 1 || !kept {
		t.Fatalf("settled intents = %+v", stored)
	}
	if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatalf("reopen: %v", err)
	}
}

// An unknown outcome pins its history and its intent in the recovery
// reserve, and opening proves both.
func TestAdmissionLedgerUnknownPinsItsIntent(t *testing.T) {
	f := newLedgerFixture(t)
	a := f.reservedAt("192.0.2.10", ledgerT0.Add(time.Hour))
	if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	before := f.storageState()
	if _, _, err := f.l.Finish(a.Attempt.ID, admission.DispositionUnknown); err != nil {
		t.Fatal(err)
	}
	after := f.storageState()
	if after.Recovery != before.Recovery+uint64(f.cost(a.Attempt.Candidate))+admission.MaxIntentBytes {
		t.Fatalf("recovery %d -> %d, cost %d", before.Recovery, after.Recovery, f.cost(a.Attempt.Candidate))
	}
	if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatal(err)
	}
	if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
		return adjustStorage(tx, func(s *admission.StorageState) { s.Recovery -= admission.MaxIntentBytes })
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenAdmissionLedger(f.db, f.reg); !isCorrupt(err) {
		t.Fatalf("open without the pinned intent = %v", err)
	}
}

// An outstanding attempt holds room for the intent it may keep: a second
// reservation that would fit beside the first one's history and rows alone
// is refused.
func TestAdmissionLedgerOutstandingAttemptHoldsItsIntent(t *testing.T) {
	f := newLedgerFixture(t)
	ids := f.fill(2, evidenceSpec{})
	need := uint64(f.cost(ids[0])) + admission.AttemptRecoveryBytes
	f.adjustStorage(func(s *admission.StorageState) { leaveRecoveryRoom(s, 2*need-1) })
	if _, _, granted, err := f.l.Reserve(ids[0], admission.LaneGeneral, f.wall.Add(time.Hour)); err != nil || !granted {
		t.Fatalf("first reservation: %v %v", granted, err)
	}
	_, _, _, err := f.l.Reserve(ids[1], admission.LaneGeneral, f.wall.Add(time.Hour))
	wantLedgerReason(t, "second reservation", err, admission.ReasonPendingRecovery)
	if s := f.l.Status(); s.Storage.Outstanding != uint64(f.cost(ids[0]))+admission.UnknownHoldBytes {
		t.Fatalf("outstanding = %d", s.Storage.Outstanding)
	}
}

// Opening proves every intent against its attempt: a running or unknown
// attempt has exactly its own row, and no other attempt has one.
func TestAdmissionLedgerOpenProvesIntents(t *testing.T) {
	expires := ledgerT0.Add(time.Hour)
	setup := func(t *testing.T) (*ledgerFixture, admission.AttemptRecord, admission.AttemptRecord, admission.Intent) {
		f := newLedgerFixture(t)
		running := f.reservedAt("192.0.2.10", expires)
		done := f.reservedAt("192.0.2.11", expires)
		for _, a := range []admission.AttemptRecord{running, done} {
			if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
				t.Fatal(err)
			}
		}
		in := f.intents()[done.Attempt.ID]
		if _, _, err := f.l.Finish(done.Attempt.ID, admission.DispositionApplied); err != nil {
			t.Fatal(err)
		}
		return f, running, done, in
	}
	put := func(tx *bolt.Tx, key admission.ActionID, in admission.Intent) error {
		data, err := in.MarshalBinary()
		if err != nil {
			return err
		}
		return tx.Bucket([]byte(admissionIntentsBucket)).Put([]byte(key), data)
	}
	// change rewrites one field of a stored row and keeps the rest.
	change := func(tx *bolt.Tx, id admission.ActionID, edit func(*admission.Intent)) error {
		in, err := admission.UnmarshalIntent(tx.Bucket([]byte(admissionIntentsBucket)).Get([]byte(id)))
		if err != nil {
			return err
		}
		edit(&in)
		return put(tx, id, in)
	}
	for name, damage := range map[string]func(*bolt.Tx, admission.AttemptRecord, admission.AttemptRecord, admission.Intent) error{
		"running attempt without its row": func(tx *bolt.Tx, running, _ admission.AttemptRecord, _ admission.Intent) error {
			return tx.Bucket([]byte(admissionIntentsBucket)).Delete([]byte(running.Attempt.ID))
		},
		"row of a verified attempt": func(tx *bolt.Tx, _, done admission.AttemptRecord, in admission.Intent) error {
			return put(tx, done.Attempt.ID, in)
		},
		"row under another action": func(tx *bolt.Tx, running, done admission.AttemptRecord, _ admission.Intent) error {
			return change(tx, running.Attempt.ID, func(in *admission.Intent) { in.Action = done.Attempt.ID })
		},
		"row with another expiry": func(tx *bolt.Tx, running, _ admission.AttemptRecord, _ admission.Intent) error {
			return change(tx, running.Attempt.ID, func(in *admission.Intent) { in.ExpiresAt = in.ExpiresAt.Add(time.Second) })
		},
		"row with another target": func(tx *bolt.Tx, running, _ admission.AttemptRecord, other admission.Intent) error {
			return change(tx, running.Attempt.ID, func(in *admission.Intent) { in.Target = other.Target })
		},
		"row with another kind": func(tx *bolt.Tx, running, _ admission.AttemptRecord, _ admission.Intent) error {
			return change(tx, running.Attempt.ID, func(in *admission.Intent) { in.Kind = admission.KindChallenge })
		},
		"row of an unrecorded attempt": func(tx *bolt.Tx, running, _ admission.AttemptRecord, in admission.Intent) error {
			missing, err := admission.NewAttempt(running.Attempt.Candidate, 3)
			if err != nil {
				return err
			}
			in.Action = missing.ID
			return put(tx, missing.ID, in)
		},
		"undecodable row": func(tx *bolt.Tx, running, _ admission.AttemptRecord, _ admission.Intent) error {
			return tx.Bucket([]byte(admissionIntentsBucket)).Put([]byte(running.Attempt.ID), []byte("{}"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			f, running, done, in := setup(t)
			if err := f.db.bolt.Update(func(tx *bolt.Tx) error { return damage(tx, running, done, in) }); err != nil {
				t.Fatal(err)
			}
			if _, err := OpenAdmissionLedger(f.db, f.reg); !isCorrupt(err) {
				t.Fatalf("open = %v", err)
			}
		})
	}
}

// Upgrading a schema 6 ledger records an intent for every attempt that ran
// without an outcome or ended unknown, each a batch of its own; nothing else
// changes, and a second open changes nothing.
func TestAdmissionLedgerUpgradesSchemaSix(t *testing.T) {
	f := newLedgerFixture(t)
	expires := ledgerT0.Add(time.Hour)
	running, unknown := f.reservedAt("192.0.2.10", expires), f.reservedAt("192.0.2.11", expires)
	reserved, applied := f.reservedAt("192.0.2.12", expires), f.reservedAt("192.0.2.13", expires)
	for _, a := range []admission.AttemptRecord{running, unknown, applied} {
		if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
			t.Fatal(err)
		}
	}
	for a, d := range map[admission.AttemptRecord]admission.Disposition{unknown: admission.DispositionUnknown, applied: admission.DispositionApplied} {
		if _, _, err := f.l.Finish(a.Attempt.ID, d); err != nil {
			t.Fatal(err)
		}
	}
	f.schemaSix()
	before := dbSnapshot(t, f.db)
	schema6 := f.storageState()
	damaged := f.copyDatabase()
	if err := damaged.bolt.Update(func(tx *bolt.Tx) error {
		return adjustStorage(tx, func(s *admission.StorageState) { s.Recovery++ })
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenAdmissionLedger(damaged, f.reg); !isCorrupt(err) {
		t.Fatalf("upgrade over a damaged reserve = %v", err)
	}
	db := f.copyDatabase()
	if _, err := OpenAdmissionLedger(db, f.reg); err != nil {
		t.Fatal(err)
	}
	after := dbSnapshot(t, db)
	schemaKey := admissionMetaBucket + ":" + string(admissionSchemaKey)
	storageKey := admissionQueueStateBucket + ":" + string(storageStateKey)
	for k, v := range before {
		if after[k] != v && k != schemaKey && k != storageKey {
			t.Fatalf("upgrade changed schema 6 record %s", k)
		}
	}
	if after[schemaKey] != string([]byte{7}) {
		t.Fatalf("upgraded schema = %q", after[schemaKey])
	}
	if err := db.bolt.View(func(tx *bolt.Tx) error {
		s, err := loadStorageState(tx)
		want := schema6
		want.Recovery += admission.MaxIntentBytes
		want.AuditSlots++
		if err != nil || s != want {
			t.Errorf("upgraded storage = %+v, %v; want %+v", s, err, want)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	got := map[admission.ActionID]admission.Intent{}
	if err := db.bolt.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(admissionIntentsBucket)).ForEach(func(k, v []byte) error {
			in, err := admission.UnmarshalIntent(v)
			got[admission.ActionID(k)] = in
			return err
		})
	}); err != nil {
		t.Fatal(err)
	}
	want := map[admission.ActionID]admission.Intent{
		running.Attempt.ID: {Action: running.Attempt.ID, Batch: batchOf(t, running.Attempt.ID), Kind: admission.KindBlockIP, Target: f.target("192.0.2.10"), ExpiresAt: expires},
		unknown.Attempt.ID: {Action: unknown.Attempt.ID, Batch: batchOf(t, unknown.Attempt.ID), Kind: admission.KindBlockIP, Target: f.target("192.0.2.11"), ExpiresAt: expires},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("upgraded intents = %+v, reserved %s", got, reserved.Attempt.ID)
	}
	if _, err := OpenAdmissionLedger(db, f.reg); err != nil {
		t.Fatal(err)
	}
	if again := dbSnapshot(t, db); !reflect.DeepEqual(again, after) {
		t.Fatal("a second open changed the upgraded ledger")
	}
}

// The startup read needs no ledger handle: it returns every unresolved
// intent in action order, nothing for a database without a ledger or
// whose ledger predates intents, and refuses a ledger it cannot read.
func TestReadUnresolvedIntents(t *testing.T) {
	f := newLedgerFixture(t)
	expires := ledgerT0.Add(time.Hour)
	running, unknown := f.reservedAt("192.0.2.10", expires), f.reservedAt("192.0.2.11", expires)
	applied := f.reservedAt("192.0.2.12", expires)
	f.reservedAt("192.0.2.13", expires)
	for _, a := range []admission.AttemptRecord{running, unknown, applied} {
		if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
			t.Fatal(err)
		}
	}
	for a, d := range map[admission.AttemptRecord]admission.Disposition{unknown: admission.DispositionUnknown, applied: admission.DispositionApplied} {
		if _, _, err := f.l.Finish(a.Attempt.ID, d); err != nil {
			t.Fatal(err)
		}
	}
	got, err := ReadUnresolvedIntents(f.db)
	stored := f.intents()
	want := []admission.Intent{stored[running.Attempt.ID], stored[unknown.Attempt.ID]}
	if want[1].Action < want[0].Action {
		want[0], want[1] = want[1], want[0]
	}
	if err != nil || len(stored) != 2 || !reflect.DeepEqual(got, want) {
		t.Fatalf("unresolved = %+v, %v; want %+v", got, err, want)
	}

	empty, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = empty.Close() })
	if got, err = ReadUnresolvedIntents(empty); err != nil || got != nil {
		t.Fatalf("no ledger: %+v, %v", got, err)
	}
	older := f.copyDatabase()
	if err = older.bolt.Update(func(tx *bolt.Tx) error {
		if dropErr := dropIntents(tx); dropErr != nil {
			return dropErr
		}
		return tx.Bucket([]byte(admissionMetaBucket)).Put(admissionSchemaKey, []byte{6})
	}); err != nil {
		t.Fatal(err)
	}
	if got, err = ReadUnresolvedIntents(older); err != nil || got != nil {
		t.Fatalf("schema 6 ledger: %+v, %v", got, err)
	}
	for name, damage := range map[string]func(*bolt.Tx) error{
		"future schema": func(tx *bolt.Tx) error {
			return tx.Bucket([]byte(admissionMetaBucket)).Put(admissionSchemaKey, []byte{admissionSchemaVersion + 1})
		},
		"no schema":  func(tx *bolt.Tx) error { return tx.Bucket([]byte(admissionMetaBucket)).Delete(admissionSchemaKey) },
		"no intents": func(tx *bolt.Tx) error { return tx.DeleteBucket([]byte(admissionIntentsBucket)) },
		"undecodable row": func(tx *bolt.Tx) error {
			return tx.Bucket([]byte(admissionIntentsBucket)).Put([]byte(running.Attempt.ID), []byte("{}"))
		},
		"row under another action": func(tx *bolt.Tx) error {
			data, encodeErr := stored[unknown.Attempt.ID].MarshalBinary()
			if encodeErr != nil {
				return encodeErr
			}
			return tx.Bucket([]byte(admissionIntentsBucket)).Put([]byte(running.Attempt.ID), data)
		},
		"malformed key": func(tx *bolt.Tx) error {
			data, encodeErr := stored[running.Attempt.ID].MarshalBinary()
			if encodeErr != nil {
				return encodeErr
			}
			return tx.Bucket([]byte(admissionIntentsBucket)).Put([]byte("act_x"), data)
		},
		"intents without a ledger": func(tx *bolt.Tx) error { return tx.DeleteBucket([]byte(admissionMetaBucket)) },
		"older schema with intents": func(tx *bolt.Tx) error {
			return tx.Bucket([]byte(admissionMetaBucket)).Put(admissionSchemaKey, []byte{6})
		},
		"nested bucket": func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte(admissionIntentsBucket))
			if deleteErr := b.Delete([]byte(running.Attempt.ID)); deleteErr != nil {
				return deleteErr
			}
			_, createErr := b.CreateBucket([]byte(running.Attempt.ID))
			return createErr
		},
		"other ledger buckets without meta": func(tx *bolt.Tx) error {
			if deleteErr := tx.DeleteBucket([]byte(admissionIntentsBucket)); deleteErr != nil {
				return deleteErr
			}
			return tx.DeleteBucket([]byte(admissionMetaBucket))
		},
	} {
		db := f.copyDatabase()
		if err = db.bolt.Update(damage); err != nil {
			t.Fatal(err)
		}
		if got, err = ReadUnresolvedIntents(db); err == nil || got != nil {
			t.Errorf("%s: %+v, %v", name, got, err)
		}
	}
	// A failed owner-open proof must not prevent the independent startup read.
	unopenable := f.copyDatabase()
	if err = unopenable.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(admissionCandidatesBucket)).Put([]byte(running.Attempt.Candidate), []byte("{}"))
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = OpenAdmissionLedger(unopenable, f.reg); !isCorrupt(err) {
		t.Fatalf("owner open = %v", err)
	}
	if got, err = ReadUnresolvedIntents(unopenable); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("independent read = %+v, %v", got, err)
	}
	closed := f.copyDatabase()
	if err = closed.Close(); err != nil {
		t.Fatal(err)
	}
	if got, err = ReadUnresolvedIntents(closed); err == nil || got != nil {
		t.Fatalf("closed database = %+v, %v", got, err)
	}
}
