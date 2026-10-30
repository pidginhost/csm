package store

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// liveLedgerFixture is a ledger fixture after its live start: only a live
// owner executes, so only a live ledger's reservations hold slots.
func liveLedgerFixture(t *testing.T) *ledgerFixture {
	t.Helper()
	f := newLedgerFixture(t)
	if err := f.l.StartLive(admission.LegacyHandover{}); err != nil {
		t.Fatal(err)
	}
	return f
}

// effectRecords reads the stored effect records in key order and the tally;
// nil records when the bucket does not exist.
func (f *ledgerFixture) effectRecords() ([]admission.EffectRecord, admission.EffectTally, byte) {
	f.t.Helper()
	var out []admission.EffectRecord
	var tally admission.EffectTally
	var schema byte
	if err := f.db.bolt.View(func(tx *bolt.Tx) error {
		schema = tx.Bucket([]byte(admissionMetaBucket)).Get(admissionSchemaKey)[0]
		var err error
		if tally, err = loadEffectTally(tx); err != nil {
			return err
		}
		b := tx.Bucket([]byte(admissionEffectsBucket))
		if b == nil {
			return nil
		}
		out = []admission.EffectRecord{}
		return b.ForEach(func(k, v []byte) error {
			e, decodeErr := admission.UnmarshalEffectRecord(k, v)
			out = append(out, e)
			return decodeErr
		})
	}); err != nil {
		f.t.Fatal(err)
	}
	return out, tally, schema
}

// A reservation holds its slot from the start, the verified outcome records
// when the block was applied, and the record leaves once its expiry passes.
func TestAdmissionLedgerEffectRecordFollowsTheAttempt(t *testing.T) {
	f := liveLedgerFixture(t)
	id := f.queued()
	entry, err := f.entry(id)
	if err != nil {
		t.Fatal(err)
	}
	expires := f.wall.Add(24 * time.Hour)
	c, a, _, err := f.l.Reserve(id, admission.LaneGeneral, expires)
	if err != nil {
		t.Fatal(err)
	}
	records, tally, schema := f.effectRecords()
	want := admission.EffectRecord{
		Action: a.Attempt.ID, Target: c.Key.Target, Partition: admission.PartitionGeneral, Lane: admission.LaneGeneral,
		Tier: entry.Tier, Scope: c.Scope.Key(), Direct: entry.Direct, Corroborated: entry.Corroborated, ExpiresAt: expires,
	}
	if len(records) != 1 || records[0] != want || tally != (admission.EffectTally{General: 1}) || schema != admissionSchemaEffects {
		t.Fatalf("after the reservation: %+v %+v schema %d, want %+v", records, tally, schema, want)
	}
	if _, _, _, err = f.l.Execute(a.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	f.tickAt(f.wall.Add(time.Minute))
	if _, _, err = f.l.Finish(a.Attempt.ID, admission.DispositionApplied); err != nil {
		t.Fatal(err)
	}
	want.Applied, want.Elapsed = f.wall, f.ceilingState().Elapsed
	if records, tally, _ = f.effectRecords(); len(records) != 1 || records[0] != want || !records[0].Verified() || tally != (admission.EffectTally{General: 1}) {
		t.Fatalf("after the verified outcome: %+v %+v, want %+v", records, tally, want)
	}
	f.tickAt(expires.Add(-time.Nanosecond))
	if records, _, _ = f.effectRecords(); len(records) != 1 {
		t.Fatalf("an effect left before its expiry: %+v", records)
	}
	f.tickAt(expires)
	if records, tally, schema = f.effectRecords(); len(records) != 0 || tally != (admission.EffectTally{}) || schema != admissionSchemaEffects {
		t.Fatalf("after the expiry: %+v %+v schema %d", records, tally, schema)
	}
}

// A failed attempt gives its slot back and a retry takes a new one; an
// unknown outcome keeps it until its expiry.
func TestAdmissionLedgerEffectRecordLeavesWithAFailure(t *testing.T) {
	f := liveLedgerFixture(t)
	id := f.queued()
	expires := f.wall.Add(time.Hour)
	_, first, _, err := f.l.Reserve(id, admission.LaneGeneral, expires)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.l.Finish(first.Attempt.ID, admission.DispositionFailed); err != nil {
		t.Fatal(err)
	}
	if records, tally, _ := f.effectRecords(); len(records) != 0 || tally != (admission.EffectTally{}) {
		t.Fatalf("after a failure: %+v %+v", records, tally)
	}
	f.tickAt(f.wall.Add(admission.RetryBackoff(1)))
	_, second, _, err := f.l.Reserve(id, admission.LaneGeneral, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = f.l.Execute(second.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.l.Finish(second.Attempt.ID, admission.DispositionUnknown); err != nil {
		t.Fatal(err)
	}
	records, tally, _ := f.effectRecords()
	if len(records) != 1 || records[0].Action != second.Attempt.ID || records[0].Verified() || tally != (admission.EffectTally{General: 1}) {
		t.Fatalf("after an unknown outcome: %+v %+v", records, tally)
	}
	f.tickAt(expires)
	if records, tally, _ = f.effectRecords(); len(records) != 0 || tally != (admission.EffectTally{}) {
		t.Fatalf("an unknown outcome kept its slot past its expiry: %+v %+v", records, tally)
	}
}

// A reservation on the reserved lane holds a reserved slot; recovery's
// settlement of a reservation that never ran gives it back.
func TestAdmissionLedgerEffectRecordTakesTheLanePartition(t *testing.T) {
	f := liveLedgerFixture(t)
	direct := f.published(evidenceSpec{producer: f.mail, check: "mail_takeover", target: "192.0.2.11", cursor: "direct", severity: admission.SeverityCritical})
	_, id := f.enqueue(f.request("192.0.2.11", direct))
	_, a, _, err := f.l.Reserve(id, admission.LaneDirect, f.wall.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	records, tally, _ := f.effectRecords()
	if len(records) != 1 || records[0].Partition != admission.PartitionReserved || records[0].Lane != admission.LaneDirect || !records[0].Direct || tally != (admission.EffectTally{Reserved: 1}) {
		t.Fatalf("reserved lane: %+v %+v", records, tally)
	}
	l, err := OpenAdmissionLedger(f.db, f.reg)
	if err != nil {
		t.Fatal(err)
	}
	f.l = l
	if _, _, err = l.Settle(); err != nil {
		t.Fatal(err)
	}
	if records, tally, _ = f.effectRecords(); len(records) != 0 || tally != (admission.EffectTally{}) {
		t.Fatalf("after settling %s: %+v %+v", a.Attempt.ID, records, tally)
	}
}

// An observe preview never runs and a reservation before the live start
// never executes, so neither holds a slot or moves the schema older builds
// read.
func TestAdmissionLedgerPreviewHoldsNoSlot(t *testing.T) {
	f := newLedgerFixture(t)
	_, _, before := f.effectRecords()
	if _, _, _, err := f.l.Reserve(f.queued(), admission.LaneGeneral, f.wall.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if records, tally, schema := f.effectRecords(); records != nil || tally != (admission.EffectTally{}) || schema != before {
		t.Fatalf("before the live start: %+v %+v schema %d, was %d", records, tally, schema, before)
	}
	f = liveLedgerFixture(t)
	_, _, before = f.effectRecords()
	if _, _, _, err := f.l.Observe(f.queued(), admission.LaneGeneral, f.wall.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if records, tally, schema := f.effectRecords(); records != nil || tally != (admission.EffectTally{}) || schema != before {
		t.Fatalf("after a preview: %+v %+v schema %d, was %d", records, tally, schema, before)
	}
}

// A degraded reading cannot prove an expiry, so the slot stays until a
// trusted reading does.
func TestAdmissionLedgerEffectSweepWaitsForATrustedClock(t *testing.T) {
	f := liveLedgerFixture(t)
	expires := f.wall.Add(time.Hour)
	if _, _, _, err := f.l.Reserve(f.queued(), admission.LaneGeneral, expires); err != nil {
		t.Fatal(err)
	}
	step := expires.Add(time.Minute)
	tick, err := f.l.Tick(admission.ClockReading{Wall: step, BootID: ledgerBoot, SinceBoot: f.since})
	if err != nil || !tick.Degraded || !tick.Now.Equal(step) {
		t.Fatalf("forward step: %+v %v", tick, err)
	}
	if records, _, _ := f.effectRecords(); len(records) != 1 {
		t.Fatalf("a degraded reading released a slot: %+v", records)
	}
	f.since += time.Second
	if tick, err = f.l.Tick(admission.ClockReading{Wall: step.Add(time.Second), BootID: ledgerBoot, SinceBoot: f.since}); err != nil || tick.Degraded {
		t.Fatalf("trusted reading: %+v %v", tick, err)
	}
	if records, tally, _ := f.effectRecords(); len(records) != 0 || tally != (admission.EffectTally{}) {
		t.Fatalf("a trusted reading kept an expired slot: %+v %+v", records, tally)
	}
}

// Opening proves the records, their tally and the schema that announces
// them, so a damaged or foreign layout never feeds the slot budgets.
func TestAdmissionLedgerOpenProvesEffectRecords(t *testing.T) {
	for name, damage := range map[string]func(tx *bolt.Tx) error{
		"a tally that disagrees": func(tx *bolt.Tx) error {
			data, err := admission.EffectTally{General: 2}.MarshalBinary()
			if err != nil {
				return err
			}
			return tx.Bucket([]byte(admissionQueueStateBucket)).Put(effectTallyKey, data)
		},
		"no tally": func(tx *bolt.Tx) error {
			return tx.Bucket([]byte(admissionQueueStateBucket)).Delete(effectTallyKey)
		},
		"no bucket at schema 12": func(tx *bolt.Tx) error {
			return tx.DeleteBucket([]byte(admissionEffectsBucket))
		},
		"records below schema 12": func(tx *bolt.Tx) error {
			return tx.Bucket([]byte(admissionMetaBucket)).Put(admissionSchemaKey, []byte{admissionSchemaLive})
		},
		"a damaged record": func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte(admissionEffectsBucket))
			k, v := b.Cursor().First()
			return b.Put(k, append(append([]byte(nil), v[:len(v)-1]...), v[len(v)-1]^1))
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := liveLedgerFixture(t)
			if _, _, _, err := f.l.Reserve(f.queued(), admission.LaneGeneral, f.wall.Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
			if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
				t.Fatalf("intact ledger: %v", err)
			}
			// Reads without a handle, as startup's, take the new schema.
			if _, err := ReadUnresolvedIntents(f.db); err != nil {
				t.Fatalf("read without a handle: %v", err)
			}
			if err := f.db.bolt.Update(damage); err != nil {
				t.Fatal(err)
			}
			if _, err := OpenAdmissionLedger(f.db, f.reg); !isCorrupt(err) {
				t.Fatalf("opened: %v", err)
			}
		})
	}
}

// Status reads the slots the records hold and when the first of them ends.
func TestAdmissionLedgerStatusCountsEffectRecords(t *testing.T) {
	f := liveLedgerFixture(t)
	if s := f.l.Status().Effects; s != (admission.EffectsStatus{}) {
		t.Fatalf("before any record: %+v", s)
	}
	soon := f.wall.Add(time.Hour)
	if _, _, _, err := f.l.Reserve(f.queued(), admission.LaneGeneral, soon); err != nil {
		t.Fatal(err)
	}
	direct := f.published(evidenceSpec{producer: f.mail, check: "mail_takeover", target: "192.0.2.11", cursor: "direct", severity: admission.SeverityCritical})
	_, id := f.enqueue(f.request("192.0.2.11", direct))
	if _, _, _, err := f.l.Reserve(id, admission.LaneDirect, soon.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if s := f.l.Status().Effects; s != (admission.EffectsStatus{General: 1, Reserved: 1, Next: soon}) {
		t.Fatalf("status %+v", s)
	}
	raw, err := json.Marshal(f.l.Status())
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Effects map[string]json.RawMessage `json:"effects"`
	}
	if err = json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"general": "1", "reserved": "1", "next": `"` + soon.Format(time.RFC3339Nano) + `"`}
	if len(wire.Effects) != len(want) {
		t.Fatalf("effects wire fields: %s", raw)
	}
	for key, value := range want {
		if string(wire.Effects[key]) != value {
			t.Errorf("effects.%s = %s, want %s", key, wire.Effects[key], value)
		}
	}
}

// Supported layouts remain lazy across reopening and observation. Schema 12
// requires a live marker, bucket and tally; schemas 7 to 11 have no effects.
func TestAdmissionLedgerEffectSchemaMatrix(t *testing.T) {
	for schema := byte(7); schema <= 12; schema++ {
		t.Run(fmt.Sprint(schema), func(t *testing.T) {
			f := newLedgerFixture(t)
			if schema >= admissionSchemaLive {
				if err := f.l.StartLive(admission.LegacyHandover{}); err != nil {
					t.Fatal(err)
				}
			}
			if schema == admissionSchemaEffects {
				if _, _, _, err := f.l.Reserve(f.queued(), admission.LaneGeneral, f.wall.Add(time.Hour)); err != nil {
					t.Fatal(err)
				}
			} else if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
				return tx.Bucket([]byte(admissionMetaBucket)).Put(admissionSchemaKey, []byte{schema})
			}); err != nil {
				t.Fatal(err)
			}
			before := f.snapshot()
			l, err := OpenAdmissionLedger(f.db, f.reg)
			if err != nil || l.LiveStarted() != (schema >= admissionSchemaLive) {
				t.Fatalf("schema %d: %v", schema, err)
			}
			if _, err = ReadUnresolvedIntents(f.db); err != nil {
				t.Fatalf("schema %d startup read: %v", schema, err)
			}
			if !reflect.DeepEqual(before, f.snapshot()) {
				t.Fatal("opening or startup reads changed the layout")
			}
			if schema < admissionSchemaLive {
				f.l = l
				f.tickAt(f.wall)
				if _, _, _, err = f.l.Observe(f.queued(), admission.LaneGeneral, f.wall.Add(time.Hour)); err != nil {
					t.Fatal(err)
				}
				if records, tally, got := f.effectRecords(); records != nil || tally != (admission.EffectTally{}) || got != schema {
					t.Fatalf("preview changed schema %d: records=%v tally=%+v schema=%d", schema, records, tally, got)
				}
			}
		})
	}
	for _, schema := range []byte{7, 8, 9, 10, 11, 12} {
		for _, damage := range []string{"effects bucket", "effects tally", "live marker", "unknown bucket", "unknown state key"} {
			t.Run(fmt.Sprintf("%d/%s", schema, damage), func(t *testing.T) {
				f := liveLedgerFixture(t)
				if _, _, _, err := f.l.Reserve(f.queued(), admission.LaneGeneral, f.wall.Add(time.Hour)); err != nil {
					t.Fatal(err)
				}
				if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
					state := tx.Bucket([]byte(admissionQueueStateBucket))
					if schema < 12 {
						if err := tx.DeleteBucket([]byte(admissionEffectsBucket)); err != nil {
							return err
						}
						if err := state.Delete(effectTallyKey); err != nil {
							return err
						}
					}
					if schema < 11 {
						if err := state.Delete(liveStartKey); err != nil {
							return err
						}
					}
					if err := tx.Bucket([]byte(admissionMetaBucket)).Put(admissionSchemaKey, []byte{schema}); err != nil {
						return err
					}
					switch damage {
					case "effects bucket":
						if schema == 12 {
							return tx.DeleteBucket([]byte(admissionEffectsBucket))
						}
						_, err := tx.CreateBucket([]byte(admissionEffectsBucket))
						return err
					case "effects tally":
						if schema == 12 {
							return state.Delete(effectTallyKey)
						}
						data, err := (admission.EffectTally{}).MarshalBinary()
						if err != nil {
							return err
						}
						return state.Put(effectTallyKey, data)
					case "live marker":
						if schema >= 11 {
							return state.Delete(liveStartKey)
						}
						data, err := (admission.LiveStart{At: f.wall}).MarshalBinary()
						if err != nil {
							return err
						}
						return state.Put(liveStartKey, data)
					case "unknown bucket":
						_, err := tx.CreateBucket([]byte("adm:unexpected"))
						return err
					default:
						return state.Put([]byte("unexpected"), []byte("value"))
					}
				}); err != nil {
					t.Fatal(err)
				}
				before := f.snapshot()
				if _, err := OpenAdmissionLedger(f.db, f.reg); !isCorrupt(err) {
					t.Fatalf("opened inconsistent schema %d (%s): %v", schema, damage, err)
				}
				if !reflect.DeepEqual(before, f.snapshot()) {
					t.Fatal("refused opening changed the ledger")
				}
			})
		}
	}
}

// Reservation, outcome and sweep failures must roll back the record, tally,
// schema, charge and audit together, including the first bucket creation.
func TestAdmissionLedgerEffectWritesAreAtomic(t *testing.T) {
	f := liveLedgerFixture(t)
	id := f.queued()
	expires := f.wall.Add(time.Hour)
	before := f.snapshot()
	f.failNext("reserve")
	if _, _, _, err := f.l.Reserve(id, admission.LaneGeneral, expires); err == nil {
		t.Fatal("injected reservation failure committed")
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("failed reservation changed the effect layout or ledger")
	}
	_, a, _, err := f.l.Reserve(id, admission.LaneGeneral, expires)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = f.l.Execute(a.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	for _, d := range []admission.Disposition{admission.DispositionApplied, admission.DispositionFailed, admission.DispositionUnknown} {
		before = f.snapshot()
		f.failNext("finish")
		if _, _, err = f.l.Finish(a.Attempt.ID, d); err == nil {
			t.Fatal("injected outcome failure committed")
		}
		if !reflect.DeepEqual(before, f.snapshot()) {
			t.Fatalf("failed %s outcome changed the record or ledger", d)
		}
	}
	before = f.snapshot()
	f.failNext("tick")
	if _, err = f.l.Tick(admission.ClockReading{Wall: expires, BootID: ledgerBoot, SinceBoot: f.since + time.Hour}); err == nil {
		t.Fatal("injected sweep failure committed")
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("failed sweep changed the record or ledger")
	}
	f.tickAt(expires)
	if records, tally, _ := f.effectRecords(); len(records) != 0 || tally != (admission.EffectTally{}) {
		t.Fatalf("successful sweep left %+v %+v", records, tally)
	}
}

// An already reserved attempt is read back by Observe without releasing
// its live slot; FinishExisting releases it once, with its failed charge kept.
func TestAdmissionLedgerEffectExistingAndObserveReadback(t *testing.T) {
	f := liveLedgerFixture(t)
	id := f.queued()
	_, a, _, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	before := f.snapshot()
	if _, got, granted, observeErr := f.l.Observe(id, 0, time.Time{}); observeErr != nil || granted || got != a {
		t.Fatalf("observe readback: %+v %v %v", got, granted, observeErr)
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("observe readback changed the held slot")
	}
	link := testLink("act_", f.wall.Add(2*time.Hour))
	if _, _, err = f.l.FinishExisting(a.Attempt.ID, link); err != nil {
		t.Fatal(err)
	}
	if records, tally, _ := f.effectRecords(); len(records) != 0 || tally != (admission.EffectTally{}) || f.ceilingState().General.Used != 1 {
		t.Fatalf("existing effect retained a slot or refunded its charge: %+v %+v", records, tally)
	}
	before = f.snapshot()
	if _, _, err = f.l.FinishExisting(a.Attempt.ID, link); err != nil || !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatalf("repeated existing outcome changed the ledger: %v", err)
	}
}

// Recovery keeps a running attempt's unverified slot. Expiry frees it even
// while audit delivery blocks retirement; later retirement cannot free it twice.
func TestAdmissionLedgerEffectRecoveryAndRetention(t *testing.T) {
	f := liveLedgerFixture(t)
	id := f.queued()
	expires := f.wall.Add(time.Hour)
	_, a, _, err := f.l.Reserve(id, admission.LaneGeneral, expires)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = f.l.Execute(a.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	if f.l, err = OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatal(err)
	}
	if failed, unknown, settleErr := f.l.Settle(); settleErr != nil || failed != 0 || unknown != 1 {
		t.Fatalf("settle: failed=%d unknown=%d error=%v", failed, unknown, settleErr)
	}
	if records, tally, _ := f.effectRecords(); len(records) != 1 || records[0].Verified() || tally != (admission.EffectTally{General: 1}) {
		t.Fatalf("settled running attempt lost its slot: %+v %+v", records, tally)
	}
	f.tickAt(expires)
	if records, tally, _ := f.effectRecords(); len(records) != 0 || tally != (admission.EffectTally{}) {
		t.Fatalf("audit-pending unknown retained an expired slot: %+v %+v", records, tally)
	}
	if _, _, _, err = f.l.RetireUnproven(a.Attempt.ID); err != admission.ErrNotReady {
		t.Fatalf("retirement before audit delivery: %v", err)
	}
	f.ackAll()
	if _, _, changed, retireErr := f.l.RetireUnproven(a.Attempt.ID); retireErr != nil || !changed {
		t.Fatalf("retire unknown: %v %v", changed, retireErr)
	}
	f.ackAll()
	f.tickAt(f.wall.Add(admission.HistoryTarget + time.Hour))
	if _, err = f.l.Candidate(id); err != errCandidateMissing {
		t.Fatalf("history not retired: %v", err)
	}
	if records, tally, schema := f.effectRecords(); len(records) != 0 || tally != (admission.EffectTally{}) || schema != 12 {
		t.Fatalf("retained history leaked slots or lowered schema: %+v %+v %d", records, tally, schema)
	}
	if _, err = OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatal(err)
	}
}

// A lease lead changes the episode boundary, not the slot's absolute expiry.
// Readback, a refused second live start, and audit delivery keep its first stamp.
func TestAdmissionLedgerEffectLeaseAndLiveStart(t *testing.T) {
	f := liveLedgerFixture(t)
	id := f.queued()
	expires := f.wall.Add(time.Hour)
	_, a, _, err := f.l.Reserve(id, admission.LaneGeneral, expires)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = f.l.Execute(a.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.l.FinishOnLease(a.Attempt.ID, admission.DispositionApplied, 30*time.Minute); err != nil {
		t.Fatal(err)
	}
	records, tally, _ := f.effectRecords()
	if len(records) != 1 || !records[0].Verified() || records[0].ExpiresAt != expires || tally != (admission.EffectTally{General: 1}) {
		t.Fatalf("verified lease: %+v %+v", records, tally)
	}
	f.tickAt(f.wall.Add(30 * time.Minute))
	before := f.snapshot()
	if _, _, err = f.l.FinishOnLease(a.Attempt.ID, admission.DispositionApplied, 30*time.Minute); err != nil {
		t.Fatal(err)
	}
	if err = f.l.StartLive(admission.LegacyHandover{}); err != admission.ErrTransitionConflict {
		t.Fatalf("second live start: %v", err)
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("readback or second live start rewrote the first stamp")
	}
	f.ackAll()
	if got, _, _ := f.effectRecords(); !reflect.DeepEqual(got, records) {
		t.Fatal("episode boundary or audit delivery released a live effect")
	}
	f.tickAt(expires)
	if got, tally, _ := f.effectRecords(); len(got) != 0 || tally != (admission.EffectTally{}) {
		t.Fatalf("verified effect survived expiry: %+v %+v", got, tally)
	}
}

func TestAdmissionLedgerEffectStartStaysLazy(t *testing.T) {
	f := newLedgerFixture(t)
	if _, _, _, err := f.l.Observe(f.queued(), admission.LaneGeneral, f.wall.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := f.l.StartLive(admission.LegacyHandover{}); err != nil {
		t.Fatal(err)
	}
	root := f.published(evidenceSpec{target: "192.0.2.11", cursor: "challenge"})
	req := f.request("192.0.2.11", root)
	req.Kind = admission.KindChallenge
	_, id := f.enqueue(req)
	if _, _, _, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if records, tally, schema := f.effectRecords(); records != nil || tally != (admission.EffectTally{}) || schema != 11 {
		t.Fatalf("live start or a challenge allocated effects: %+v %+v %d", records, tally, schema)
	}
}
