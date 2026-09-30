package store

import (
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// noticeRecordsIn reads every notice record of the outbox.
func noticeRecordsIn(t *testing.T, tx *bolt.Tx) map[admission.NoticeKey]admission.NoticeRecord {
	t.Helper()
	out := map[admission.NoticeKey]admission.NoticeRecord{}
	if err := tx.Bucket([]byte(admissionOutboxBucket)).ForEach(func(k, v []byte) error {
		if k[0] != 'n' {
			return nil
		}
		r, err := admission.UnmarshalNoticeRecord(v)
		out[r.Key] = r
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func emptyFixedNotices(t *testing.T) map[admission.NoticeKey]admission.NoticeRecord {
	t.Helper()
	out := map[admission.NoticeKey]admission.NoticeRecord{}
	for _, k := range admission.FixedNoticeKeys() {
		out[k] = admission.NewNoticeRecord(k)
	}
	return out
}

func putOutboxRaw(tx *bolt.Tx, key, value []byte) error {
	return tx.Bucket([]byte(admissionOutboxBucket)).Put(key, value)
}

// A schema 4 ledger is upgraded once, in the opening transaction: every
// schema 4 record stays byte for byte except the storage record, which
// only gains the fixed notice records the outbox now holds. Opening again
// changes nothing.
func TestAdmissionLedgerUpgradesSchemaFour(t *testing.T) {
	f := newLedgerFixture(t)
	f.queued()
	f.nextGeneration()
	reserved := f.queued()
	if _, _, _, err := f.l.Reserve(reserved, admission.LaneGeneral, f.wall.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	f.schemaFour()
	schema4 := f.storageState()
	before := dbSnapshot(t, f.db)
	db := f.copyDatabase()
	if _, err := OpenAdmissionLedger(db, f.reg); err != nil {
		t.Fatal(err)
	}
	after := dbSnapshot(t, db)
	schemaKey := admissionMetaBucket + ":" + string(admissionSchemaKey)
	storageKey := admissionQueueStateBucket + ":" + string(storageStateKey)
	for k, v := range before {
		if after[k] != v && k != schemaKey && k != storageKey {
			t.Fatalf("upgrade changed schema 4 record %s", k)
		}
	}
	if after[schemaKey] != string([]byte{5}) {
		t.Fatalf("upgraded schema = %q", after[schemaKey])
	}
	if err := db.bolt.View(func(tx *bolt.Tx) error {
		s, err := loadStorage(tx)
		want := schema4
		// The reserved attempt still owes the rows of its execution and
		// outcome.
		want.NoticeRecords, want.AuditSlots = admission.FixedNotices, 2
		if err != nil || s != want {
			t.Errorf("upgraded storage = %+v, %v; want %+v", s, err, want)
		}
		if got := noticeRecordsIn(t, tx); !reflect.DeepEqual(got, emptyFixedNotices(t)) {
			t.Errorf("upgraded outbox = %+v", got)
		}
		if n := tx.Bucket([]byte(admissionWindowsBucket)).Stats().KeyN; n != 0 {
			t.Errorf("upgrade invented %d outcome buckets", n)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenAdmissionLedger(db, f.reg); err != nil {
		t.Fatal(err)
	}
	if again := dbSnapshot(t, db); !reflect.DeepEqual(again, after) {
		t.Fatal("a second open changed the upgraded ledger")
	}
}

// Every upgrade path ends at schema 5 with the fixed notice records.
func TestAdmissionLedgerUpgradeChainsReachSchemaFive(t *testing.T) {
	for name, downgrade := range map[string]func(*ledgerFixture){
		"1": (*ledgerFixture).schemaOne, "2": (*ledgerFixture).schemaTwo,
		"3": (*ledgerFixture).schemaThree, "4": (*ledgerFixture).schemaFour,
	} {
		t.Run(name, func(t *testing.T) {
			f := newLedgerFixture(t)
			f.queued()
			downgrade(f)
			db := f.copyDatabase()
			if _, err := OpenAdmissionLedger(db, f.reg); err != nil {
				t.Fatal(err)
			}
			if err := db.bolt.View(func(tx *bolt.Tx) error {
				if schema := tx.Bucket([]byte(admissionMetaBucket)).Get(admissionSchemaKey); string(schema) != string([]byte{5}) {
					t.Errorf("schema %v", schema)
				}
				if got := noticeRecordsIn(t, tx); !reflect.DeepEqual(got, emptyFixedNotices(t)) {
					t.Errorf("outbox = %+v", got)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// outboxDamage is what a damage case may reference: a queued candidate
// and a reserved one with its attempt.
type outboxDamage struct {
	queued   admission.CandidateID
	reserved admission.Candidate
	attempt  admission.AttemptRecord
}

// Opening proves the outbox and the outcome buckets row by row: every
// record decodes under its own key, the fixed records exist, the storage
// record counts exactly what is stored, and every bucket lies inside its
// span's window at the stored clock.
func TestAdmissionLedgerRefusesADamagedOutbox(t *testing.T) {
	now := ledgerT0
	putRow := func(tx *bolt.Tx, key []byte, row admission.AuditRow) error {
		v, err := row.MarshalBinary()
		if err != nil {
			return err
		}
		if err = putOutboxRaw(tx, key, v); err != nil {
			return err
		}
		return adjustStorage(tx, func(s *admission.StorageState) { s.AuditSlots++ })
	}
	for name, damage := range map[string]func(t *testing.T, d outboxDamage, tx *bolt.Tx) error{
		"missing fixed record": func(t *testing.T, _ outboxDamage, tx *bolt.Tx) error {
			k, _ := admission.FixedNoticeKeys()[0].Bytes()
			return tx.Bucket([]byte(admissionOutboxBucket)).Delete(k)
		},
		"missing fixed record, uncounted": func(t *testing.T, _ outboxDamage, tx *bolt.Tx) error {
			k, _ := admission.FixedNoticeKeys()[0].Bytes()
			if err := tx.Bucket([]byte(admissionOutboxBucket)).Delete(k); err != nil {
				return err
			}
			return adjustStorage(tx, func(s *admission.StorageState) { s.NoticeRecords-- })
		},
		"unknown outbox key": func(t *testing.T, _ outboxDamage, tx *bolt.Tx) error {
			return putOutboxRaw(tx, []byte("x"), []byte("1"))
		},
		"damaged notice": func(t *testing.T, _ outboxDamage, tx *bolt.Tx) error {
			k, _ := admission.OverflowKey(admission.NoticeWithheld).Bytes()
			return putOutboxRaw(tx, k, []byte("{}"))
		},
		"notice under another key": func(t *testing.T, _ outboxDamage, tx *bolt.Tx) error {
			k, _ := admission.OverflowKey(admission.NoticeWithheld).Bytes()
			v, _ := admission.NewNoticeRecord(admission.OverflowKey(admission.NoticeCapacity)).MarshalBinary()
			return putOutboxRaw(tx, k, v)
		},
		"uncounted notice": func(t *testing.T, _ outboxDamage, tx *bolt.Tx) error {
			key := admission.NoticeKey{Kind: admission.NoticeWithheld, Reason: admission.ReasonStale, Check: "ssh_brute", Effect: admission.EffectAddress}
			r, _ := admission.NewNoticeRecord(key).Add(now, "", 0)
			k, _ := key.Bytes()
			v, _ := r.MarshalBinary()
			return putOutboxRaw(tx, k, v)
		},
		"counted notice missing": func(t *testing.T, _ outboxDamage, tx *bolt.Tx) error {
			return adjustStorage(tx, func(s *admission.StorageState) { s.NoticeRecords++ })
		},
		"counted audit row missing": func(t *testing.T, _ outboxDamage, tx *bolt.Tx) error {
			return adjustStorage(tx, func(s *admission.StorageState) { s.AuditSlots++ })
		},
		"audit row without its attempt": func(t *testing.T, d outboxDamage, tx *bolt.Tx) error {
			c, err := loadCandidate(tx, d.queued)
			if err != nil {
				return err
			}
			// Only the attempt is missing: the row names no later
			// transition than the candidate made.
			first, _ := admission.NewAttempt(d.queued, 1)
			c.State, c.Attempts, c.ExpiresAt = admission.StateReserved, 1, now.Add(time.Hour)
			row, err := admission.NewAuditRow(c, admission.AttemptRecord{Attempt: first, State: admission.StateReserved, ExpiresAt: c.ExpiresAt, Reserved: now}, admission.Tier{}, now)
			if err != nil {
				return err
			}
			return putRow(tx, row.Key(), row)
		},
		"audit row under another key": func(t *testing.T, d outboxDamage, tx *bolt.Tx) error {
			// Move the reserved attempt's row, writing it first where
			// reservations write none, so only its key is wrong.
			row, err := admission.NewAuditRow(d.reserved, d.attempt, admission.Tier{}, now)
			if err != nil {
				return err
			}
			outbox := tx.Bucket([]byte(admissionOutboxBucket))
			if raw := outbox.Get(row.Key()); raw != nil {
				if row, err = admission.UnmarshalAuditRow(raw); err != nil {
					return err
				}
				if err = outbox.Delete(row.Key()); err != nil {
					return err
				}
				if err = adjustStorage(tx, func(s *admission.StorageState) { s.AuditSlots-- }); err != nil {
					return err
				}
			}
			other := row
			other.Transition--
			return putRow(tx, other.Key(), row)
		},
		"damaged outcome bucket": func(t *testing.T, _ outboxDamage, tx *bolt.Tx) error {
			return tx.Bucket([]byte(admissionWindowsBucket)).Put(admission.SpanHour.Key(admission.SpanHour.Start(now)), []byte("{}"))
		},
		"future outcome bucket": func(t *testing.T, _ outboxDamage, tx *bolt.Tx) error {
			return putBucket(tx, admission.SpanHour, admission.SpanHour.Start(now).Add(time.Hour))
		},
		"stale outcome bucket": func(t *testing.T, _ outboxDamage, tx *bolt.Tx) error {
			return putBucket(tx, admission.SpanFiveMinutes, admission.SpanFiveMinutes.Oldest(now).Add(-5*time.Minute))
		},
		"unaligned outcome key": func(t *testing.T, _ outboxDamage, tx *bolt.Tx) error {
			k := admission.SpanDay.Key(admission.SpanDay.Start(now))
			k[len(k)-1]++
			v, _ := bucketWith(t).MarshalBinary()
			return tx.Bucket([]byte(admissionWindowsBucket)).Put(k, v)
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newLedgerFixture(t)
			d := outboxDamage{queued: f.queued()}
			// A deferral is the queued candidate's second transition, so a
			// reservation row can name it with no attempt behind it.
			if _, err := f.l.Defer(d.queued, admission.ReasonCeiling); err != nil {
				t.Fatal(err)
			}
			f.nextGeneration()
			var err error
			if d.reserved, d.attempt, _, err = f.l.Reserve(f.queued(), admission.LaneGeneral, f.wall.Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
			if err = f.db.bolt.Update(func(tx *bolt.Tx) error { return damage(t, d, tx) }); err != nil {
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
	f := newLedgerFixture(t)
	if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
		for _, s := range admission.Spans() {
			if err := putBucket(tx, s, s.Oldest(now)); err != nil {
				return err
			}
			if err := putBucket(tx, s, s.Start(now)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatalf("buckets at both window edges refused: %v", err)
	}
}

func bucketWith(t *testing.T) admission.OutcomeCounts {
	t.Helper()
	var c admission.OutcomeCounts
	if err := c.Add(admission.AttemptOutcome(admission.DispositionApplied, admission.Tier{})); err != nil {
		t.Fatal(err)
	}
	return c
}

func putBucket(tx *bolt.Tx, s admission.Span, start time.Time) error {
	var c admission.OutcomeCounts
	if err := c.Add(admission.AttemptOutcome(admission.DispositionApplied, admission.Tier{})); err != nil {
		return err
	}
	v, err := c.MarshalBinary()
	if err != nil {
		return err
	}
	return tx.Bucket([]byte(admissionWindowsBucket)).Put(s.Key(start), v)
}

// Tick drops the outcome buckets that have left their span's window in the
// clock's own transaction, so an idle ledger still opens; a bucket at the
// window's oldest start stays.
func TestAdmissionLedgerTickDropsExpiredOutcomeBuckets(t *testing.T) {
	f := newLedgerFixture(t)
	later := f.wall.Add(2 * time.Hour)
	type bucket struct {
		span  admission.Span
		start time.Time
	}
	var kept, dropped []bucket
	for _, s := range admission.Spans() {
		kept = append(kept, bucket{s, s.Oldest(later)})
		dropped = append(dropped, bucket{s, s.Oldest(later).Add(-s.Width())})
	}
	if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
		for _, b := range append(append([]bucket(nil), kept...), dropped...) {
			if err := putBucket(tx, b.span, b.start); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	present := func() map[string]bool {
		out := map[string]bool{}
		if err := f.db.bolt.View(func(tx *bolt.Tx) error {
			return tx.Bucket([]byte(admissionWindowsBucket)).ForEach(func(k, _ []byte) error {
				out[string(k)] = true
				return nil
			})
		}); err != nil {
			t.Fatal(err)
		}
		return out
	}
	f.tickAt(later)
	after := present()
	for _, b := range dropped {
		if after[string(b.span.Key(b.start))] {
			t.Errorf("%v bucket at %v outlived its window", b.span, b.start)
		}
	}
	for _, b := range kept {
		if !after[string(b.span.Key(b.start))] {
			t.Errorf("%v bucket at the window's edge %v was dropped", b.span, b.start)
		}
	}
	f.tickAt(f.wall.Add(31 * 24 * time.Hour))
	if got := present(); len(got) != 0 {
		t.Fatalf("after a month: %v", got)
	}
	if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatal(err)
	}
}

// The outbox shares the recovery reserve: a reservation needs its room
// after the outbox's records, not only after pinned outcomes.
func TestAdmissionLedgerOutboxSharesTheRecoveryReserve(t *testing.T) {
	f := newLedgerFixture(t)
	id := f.queued()
	cost := uint64(f.cost(id))
	s := f.storageState()
	if s.OutboxBytes() != admission.FixedNotices*admission.NoticeSlotBytes {
		t.Fatalf("a new outbox holds %d bytes", s.OutboxBytes())
	}
	f.adjustStorage(func(s *admission.StorageState) { s.Recovery = admission.RecoveryReserveBytes - cost })
	_, _, _, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour))
	wantLedgerReason(t, "room taken by the outbox", err, admission.ReasonPendingRecovery)
	f.adjustStorage(func(s *admission.StorageState) { leaveRecoveryRoom(s, cost+admission.AttemptAuditBytes) })
	if _, _, granted, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour)); err != nil || !granted {
		t.Fatalf("room after the outbox: %v %v", granted, err)
	}
}

// leaveRecoveryRoom sets the pinned history so the reserve has room bytes
// left after the outbox.
func leaveRecoveryRoom(s *admission.StorageState, room uint64) {
	s.Recovery = admission.RecoveryReserveBytes - s.OutboxBytes() - room
}
