package store

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// notices reads the outbox's notice records.
func (f *ledgerFixture) notices() map[admission.NoticeKey]admission.NoticeRecord {
	f.t.Helper()
	var out map[admission.NoticeKey]admission.NoticeRecord
	if err := f.db.bolt.View(func(tx *bolt.Tx) error {
		out = noticeRecordsIn(f.t.(*testing.T), tx)
		return nil
	}); err != nil {
		f.t.Fatal(err)
	}
	return out
}

// criticalQueued queues a Critical C2 candidate at 192.0.2.10.
func (f *ledgerFixture) criticalQueued() admission.CandidateID {
	f.t.Helper()
	f.nextGeneration()
	root := f.published(evidenceSpec{cursor: fmt.Sprintf("critical=%d", f.generation), severity: admission.SeverityCritical})
	_, id := f.enqueue(f.request("192.0.2.10", root))
	return id
}

func sshKey(kind admission.NoticeKind, r admission.Reason) admission.NoticeKey {
	return admission.NoticeKey{Kind: kind, Reason: r, Check: "ssh_brute", Effect: admission.EffectAddress}
}

var criticalSummary = admission.NoticeKey{Kind: admission.NoticeCriticalSummary}

// A deferral of Critical work raises its notice in the deferral's own
// transaction, with the candidate and its transition count as the example;
// a capacity reason raises the capacity notice. The same reason again is
// no transition and raises nothing; non-Critical work raises nothing.
func TestAdmissionLedgerDeferralsRaiseNotices(t *testing.T) {
	f := newLedgerFixture(t)
	id := f.criticalQueued()
	base := f.storageState().NoticeRecords
	c, err := f.l.Defer(id, admission.ReasonCeiling)
	if err != nil {
		t.Fatal(err)
	}
	got := f.notices()
	want := admission.NoticeExample{Candidate: id, Transitions: c.Transitions, Ordinal: 1}
	r := got[sshKey(admission.NoticeCapacity, admission.ReasonCeiling)]
	if r.Count != 1 || len(r.Examples) != 1 || r.Examples[0] != want || !r.First.Equal(f.wall) {
		t.Fatalf("capacity record = %+v", r)
	}
	if s := got[criticalSummary]; s.Count != 1 || s.Examples[0] != want {
		t.Fatalf("critical summary = %+v", s)
	}
	before := f.snapshot()
	if _, err = f.l.Defer(id, admission.ReasonCeiling); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("an unchanged deferral raised a notice")
	}
	if _, err = f.l.Defer(id, admission.ReasonEngineUnavailable); err != nil {
		t.Fatal(err)
	}
	if r = f.notices()[sshKey(admission.NoticeWithheld, admission.ReasonEngineUnavailable)]; r.Count != 1 {
		t.Fatalf("withheld record = %+v", r)
	}
	if n := f.storageState().NoticeRecords; n != base+2 {
		t.Fatalf("records = %d, want two new keys", n)
	}
	f.nextGeneration()
	high := f.queued()
	before = f.snapshot()
	if _, err = f.l.Defer(high, admission.ReasonCeiling); err != nil {
		t.Fatal(err)
	}
	after := f.snapshot()
	if s := f.notices()[criticalSummary]; s.Count != 2 {
		t.Fatalf("summary after non-Critical work = %+v", s)
	}
	for k := range after {
		if strings.HasPrefix(k, admissionOutboxBucket) && before[k] != after[k] {
			t.Fatalf("non-Critical deferral changed %s", k)
		}
	}
	f.failNext("defer")
	before = f.snapshot()
	if _, err = f.l.Defer(id, admission.ReasonStorageShare); err == nil {
		t.Fatal("injected failure")
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("a failed deferral left a notice")
	}
}

// Endings of Critical work raise the withheld notice, except an existing
// verified effect; a displacement is a capacity loss. C3 work below
// Critical raises the Warning form without touching the Critical summary.
func TestAdmissionLedgerEndingsRaiseNotices(t *testing.T) {
	f := newLedgerFixture(t)
	collateral := f.criticalQueued()
	if _, err := f.l.Terminate(collateral, admission.ReasonCollateral); err != nil {
		t.Fatal(err)
	}
	existing := f.criticalQueued()
	if _, err := f.l.Terminate(existing, admission.ReasonExistingEffect); err != nil {
		t.Fatal(err)
	}
	got := f.notices()
	if r := got[sshKey(admission.NoticeWithheld, admission.ReasonCollateral)]; r.Count != 1 || r.Examples[0].Candidate != collateral {
		t.Fatalf("collateral record = %+v", r)
	}
	if _, ok := got[sshKey(admission.NoticeWithheld, admission.ReasonExistingEffect)]; ok {
		t.Fatal("an existing effect raised a notice")
	}
	if got[criticalSummary].Count != 1 {
		t.Fatalf("summary = %+v", got[criticalSummary])
	}
	aged := f.criticalQueued()
	f.tickAt(f.wall.Add(admission.QueueAgeLimit))
	f.schedule(admission.ScheduleLimits{General: 1, Members: 1})
	agedC, _ := f.l.Candidate(aged)
	if r := f.notices()[sshKey(admission.NoticeWithheld, admission.ReasonStale)]; r.Count != 1 ||
		r.Examples[0] != (admission.NoticeExample{Candidate: aged, Transitions: agedC.Transitions, Ordinal: 1}) {
		t.Fatalf("aged-out record = %+v", r)
	}
	// The tie on severity goes to the lexically first check even when its
	// root sorts first by evidence ID.
	f.nextGeneration()
	own := f.published(evidenceSpec{cursor: "corroborated"})
	intel := f.published(evidenceSpec{producer: f.rep, check: "reputation", cursor: cursorFor(t, f, own)})
	_, c3 := f.enqueue(f.request("192.0.2.10", own, intel))
	if _, err := f.l.Terminate(c3, admission.ReasonPolicy); err != nil {
		t.Fatal(err)
	}
	got = f.notices()
	// Both roots are High: the lexically first check names the record.
	warning := admission.NoticeKey{Kind: admission.NoticeWithheldWarning, Reason: admission.ReasonPolicy, Check: "reputation", Effect: admission.EffectAddress}
	if r := got[warning]; r.Count != 1 {
		t.Fatalf("warning record = %+v", r)
	}
	if got[criticalSummary].Count != 2 {
		t.Fatalf("a Warning notice counted as Critical: %+v", got[criticalSummary])
	}
}

// A final failure or an unknown outcome of Critical work is a gap keyed by
// its outcome; a failure with attempts left is not. A verified outcome
// counts in the applied summary.
func TestAdmissionLedgerOutcomesRaiseNotices(t *testing.T) {
	f := newLedgerFixture(t)
	id := f.criticalQueued()
	_, a, _, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.l.Finish(a.Attempt.ID, admission.DispositionFailed); err != nil {
		t.Fatal(err)
	}
	if got := f.notices(); got[criticalSummary].Count != 0 {
		t.Fatalf("a retried failure raised a notice: %+v", got[criticalSummary])
	}
	f.tickAt(f.wall.Add(admission.RetryBackoff(1)))
	if _, a, _, err = f.l.Reserve(id, admission.LaneGeneral, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = f.l.Execute(a.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	c, _, err := f.l.Finish(a.Attempt.ID, admission.DispositionUnknown)
	if err != nil {
		t.Fatal(err)
	}
	key := admission.NoticeKey{Kind: admission.NoticeWithheld, Outcome: admission.DispositionUnknown, Check: "ssh_brute", Effect: admission.EffectAddress}
	r := f.notices()[key]
	if r.Count != 1 || r.Examples[0] != (admission.NoticeExample{Candidate: id, Transitions: c.Transitions, Ordinal: 1}) {
		t.Fatalf("unknown outcome record = %+v", r)
	}
	applied := f.applied(time.Hour)
	s := f.notices()[admission.NoticeKey{Kind: admission.NoticeAppliedSummary}]
	if s.Count != 1 || s.Examples[0].Candidate != applied {
		t.Fatalf("applied summary = %+v", s)
	}
}

// A refused Critical arrival raises its notice under the arrival's own
// check and family, with no example: it names no stored candidate.
func TestAdmissionLedgerArrivalRefusalsRaiseNotices(t *testing.T) {
	f := newLedgerFixture(t)
	if _, err := f.l.BeginIngress(); err != nil {
		t.Fatal(err)
	}
	a := f.arrival(evidenceSpec{severity: admission.SeverityCritical, cursor: "refused"})
	a.Request.Primary = f.published(evidenceSpec{cursor: "other"})
	res, _, err := f.l.EnqueueGroup([]admission.Arrival{a}, nil)
	if err != nil || res[0].Err == nil {
		t.Fatalf("arrival = %+v, %v", res, err)
	}
	r := f.notices()[sshKey(admission.NoticeWithheld, admission.ReasonInvalid)]
	if r.Count != 1 || len(r.Examples) != 0 {
		t.Fatalf("arrival record = %+v", r)
	}
}

// The notice record's check is its candidate's highest-severity root.
func TestAdmissionLedgerNoticeNamesTheCriticalRoot(t *testing.T) {
	f := newLedgerFixture(t)
	f.nextGeneration()
	own := f.published(evidenceSpec{cursor: "high"})
	direct := f.published(evidenceSpec{producer: f.mail, check: "mail_takeover", cursor: "direct", severity: admission.SeverityCritical})
	_, id := f.enqueue(f.request("192.0.2.10", own, direct))
	if _, err := f.l.Defer(id, admission.ReasonCeiling); err != nil {
		t.Fatal(err)
	}
	key := admission.NoticeKey{Kind: admission.NoticeCapacity, Reason: admission.ReasonCeiling, Check: "mail_takeover", Effect: admission.EffectAddress}
	if r := f.notices()[key]; r.Count != 1 {
		t.Fatalf("records = %+v", f.notices())
	}
}

// A new key without room in the notice share counts in its kind's
// overflow record; the Critical summary still counts the event.
func TestAdmissionLedgerNoticeOverflow(t *testing.T) {
	f := newLedgerFixture(t)
	id := f.criticalQueued()
	f.adjustStorage(func(s *admission.StorageState) { s.NoticeRecords = admission.MaxNoticeRecords })
	if _, err := f.l.Defer(id, admission.ReasonCeiling); err != nil {
		t.Fatal(err)
	}
	got := f.notices()
	if _, ok := got[sshKey(admission.NoticeCapacity, admission.ReasonCeiling)]; ok {
		t.Fatal("a key was stored beyond the share")
	}
	if r := got[admission.OverflowKey(admission.NoticeCapacity)]; r.Count != 1 || r.Examples[0].Candidate != id {
		t.Fatalf("overflow = %+v", r)
	}
	if got[criticalSummary].Count != 1 || f.storageState().NoticeRecords != admission.MaxNoticeRecords {
		t.Fatal("overflow changed the summary or the count")
	}
}

// PendingNotices returns the records due at the stored clock: a key at
// most once an hour, a summary once a minute. AckNotices covers a count,
// in one transaction; a repeated acknowledgement changes nothing.
func TestAdmissionLedgerNoticeDelivery(t *testing.T) {
	f := newLedgerFixture(t)
	id := f.criticalQueued()
	if _, err := f.l.Defer(id, admission.ReasonCeiling); err != nil {
		t.Fatal(err)
	}
	due, err := f.l.PendingNotices()
	if err != nil || len(due) != 2 {
		t.Fatalf("due = %+v, %v", due, err)
	}
	var acks []admission.NoticeAck
	for _, r := range due {
		acks = append(acks, admission.NoticeAck{Key: r.Key, First: r.First, Count: r.Count})
	}
	if err = f.l.AckNotices(acks); err != nil {
		t.Fatal(err)
	}
	before := f.snapshot()
	if err = f.l.AckNotices(acks); err != nil || !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatalf("a repeated acknowledgement changed the ledger: %v", err)
	}
	if due, _ = f.l.PendingNotices(); len(due) != 0 {
		t.Fatalf("due after delivery = %+v", due)
	}
	if _, err = f.l.Defer(id, admission.ReasonStorageShare); err != nil {
		t.Fatal(err)
	}
	if _, err = f.l.Defer(id, admission.ReasonCeiling); err != nil {
		t.Fatal(err)
	}
	if due, _ = f.l.PendingNotices(); len(due) != 1 || due[0].Key != sshKey(admission.NoticeCapacity, admission.ReasonStorageShare) {
		t.Fatalf("due before the intervals = %+v", due)
	}
	f.tickAt(f.wall.Add(time.Minute))
	if due, _ = f.l.PendingNotices(); len(due) != 2 {
		t.Fatalf("due after a minute = %+v", due)
	}
	f.tickAt(f.wall.Add(time.Hour))
	if due, _ = f.l.PendingNotices(); len(due) != 3 {
		t.Fatalf("due after an hour = %+v", due)
	}
	over := admission.NoticeAck{Key: criticalSummary, First: f.notices()[criticalSummary].First, Count: 99}
	before = f.snapshot()
	if err = f.l.AckNotices([]admission.NoticeAck{acks[0], over}); err == nil || !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatalf("an acknowledgement beyond the count: %v", err)
	}
	gone := admission.NoticeAck{Key: sshKey(admission.NoticeWithheld, admission.ReasonStale), Count: 1}
	if err = f.l.AckNotices([]admission.NoticeAck{gone}); err != nil || !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatalf("an acknowledgement of a missing record: %v", err)
	}
	f.failNext("notices")
	if err = f.l.AckNotices(acks); err == nil || !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("a failed acknowledgement changed the ledger")
	}
}

// A missing fixed summary is corruption, not a new key to allocate. The
// causing transition and its keyed notice must both roll back.
func TestAdmissionLedgerMissingSummaryRollsBackNotice(t *testing.T) {
	f := newLedgerFixture(t)
	id := f.criticalQueued()
	key, err := criticalSummary.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if err = f.db.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(admissionOutboxBucket)).Delete(key)
	}); err != nil {
		t.Fatal(err)
	}
	before := f.snapshot()
	if _, err = f.l.Defer(id, admission.ReasonCeiling); !isCorrupt(err) {
		t.Fatalf("missing summary was repaired: %v", err)
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("failed notice changed the transition, slots or outbox")
	}
}

// The notice share is a cap, not additional reserve capacity. A new key
// must not spend bytes already held for outstanding history or audit rows.
func TestAdmissionLedgerNoticesRespectRecoveryHolds(t *testing.T) {
	for _, room := range []uint64{admission.NoticeSlotBytes - 1, admission.NoticeSlotBytes} {
		t.Run(fmt.Sprint(room), func(t *testing.T) {
			f := newLedgerFixture(t)
			id := f.criticalQueued()
			reserved, _ := f.admitted(time.Hour)
			hold := uint64(f.cost(reserved))
			f.adjustStorage(func(s *admission.StorageState) { leaveRecoveryRoom(s, hold+room) })
			before := f.storageState()
			if _, err := f.l.Defer(id, admission.ReasonCeiling); err != nil {
				t.Fatal(err)
			}
			notices := f.notices()
			key := sshKey(admission.NoticeCapacity, admission.ReasonCeiling)
			_, allocated := notices[key]
			want := room == admission.NoticeSlotBytes
			if allocated != want || notices[criticalSummary].Count != 1 {
				t.Fatalf("allocated = %v, summary = %+v", allocated, notices[criticalSummary])
			}
			after := f.storageState()
			if !want {
				if after.NoticeRecords != before.NoticeRecords || notices[admission.OverflowKey(admission.NoticeCapacity)].Count != 1 {
					t.Fatal("refused key grew records or lost its overflow count")
				}
			} else if after.NoticeRecords != before.NoticeRecords+1 || notices[key].Count != 1 || notices[admission.OverflowKey(admission.NoticeCapacity)].Count != 0 {
				t.Fatal("exact room did not fund exactly one notice")
			}
			if after.AuditSlots != before.AuditSlots || after.Recovery+after.OutboxBytes()+hold > admission.RecoveryReserveBytes {
				t.Fatal("notice allocation overbooked the recovery reserve")
			}
		})
	}
}

// Finishing unknown transfers an outstanding history hold to pinned
// recovery. A notice cannot spend that hold between release and pinning.
func TestAdmissionLedgerOutcomeNoticeKeepsItsRecoveryHold(t *testing.T) {
	f := newLedgerFixture(t)
	id := f.criticalQueued()
	_, a, granted, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour))
	if err != nil || !granted {
		t.Fatalf("reserve: %v %v", granted, err)
	}
	if _, _, granted, err = f.l.Execute(a.Attempt.ID); err != nil || !granted {
		t.Fatalf("execute: %v %v", granted, err)
	}
	hold := uint64(f.cost(id))
	f.adjustStorage(func(s *admission.StorageState) { leaveRecoveryRoom(s, hold) })
	before := f.storageState()
	if _, _, err = f.l.Finish(a.Attempt.ID, admission.DispositionUnknown); err != nil {
		t.Fatal(err)
	}
	after := f.storageState()
	if after.Recovery != before.Recovery+hold || after.AuditSlots != before.AuditSlots || after.NoticeRecords != before.NoticeRecords || after.Recovery+after.OutboxBytes() > admission.RecoveryReserveBytes {
		t.Fatal("the outcome notice spent its own history hold")
	}
	notices := f.notices()
	if notices[admission.OverflowKey(admission.NoticeWithheld)].Count != 1 || notices[criticalSummary].Count != 1 {
		t.Fatal("the outcome gap was not recorded in overflow and the summary")
	}
	rows := f.pendingAudit()
	if len(rows) != 3 || rows[2].Disposition != admission.DispositionUnknown {
		t.Fatalf("outcome audit rows = %+v", rows)
	}
}

// Reusing a quiet key must not let a delayed acknowledgement cover the
// new record's events, even when their counts coincide.
func TestAdmissionLedgerNoticeAckFencesReusedKey(t *testing.T) {
	f := newLedgerFixture(t)
	id := f.criticalQueued()
	key := sshKey(admission.NoticeCapacity, admission.ReasonCeiling)
	if _, err := f.l.Defer(id, admission.ReasonCeiling); err != nil {
		t.Fatal(err)
	}
	r := f.notices()[key]
	old := admission.NoticeAck{Key: key, First: r.First, Count: r.Count}
	if err := f.l.AckNotices([]admission.NoticeAck{old}); err != nil {
		t.Fatal(err)
	}
	f.tickAt(f.wall.Add(time.Hour))
	if _, found := f.notices()[key]; found {
		t.Fatal("quiet key was not removed")
	}
	id = f.criticalQueued()
	if _, err := f.l.Defer(id, admission.ReasonCeiling); err != nil {
		t.Fatal(err)
	}
	r = f.notices()[key]
	if r.First.Equal(old.First) || r.Count != old.Count || r.Unsent() != 1 || len(r.Examples) != 1 {
		t.Fatalf("new record = %+v", r)
	}
	before := f.snapshot()
	if err := f.l.AckNotices([]admission.NoticeAck{old}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("a stale acknowledgement consumed the reused key")
	}
	current := admission.NoticeAck{Key: key, First: r.First, Count: r.Count}
	if err := f.l.AckNotices([]admission.NoticeAck{current}); err != nil {
		t.Fatal(err)
	}
	if got := f.notices()[key]; got.Unsent() != 0 || len(got.Examples) != 0 || got.QuietAt().IsZero() {
		t.Fatalf("current acknowledgement did not cover the record: %+v", got)
	}
}

// A keyed record whose events were all delivered is removed by Tick once
// its interval has passed, freeing its slot; a new event before then keeps
// it. Opening proves the quiet index against the records.
func TestAdmissionLedgerTickRemovesQuietNotices(t *testing.T) {
	f := newLedgerFixture(t)
	id := f.criticalQueued()
	if _, err := f.l.Defer(id, admission.ReasonCeiling); err != nil {
		t.Fatal(err)
	}
	base := f.storageState().NoticeRecords
	due, _ := f.l.PendingNotices()
	var acks []admission.NoticeAck
	for _, r := range due {
		acks = append(acks, admission.NoticeAck{Key: r.Key, First: r.First, Count: r.Count})
	}
	if err := f.l.AckNotices(acks); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatalf("reopen with a quiet record: %v", err)
	}
	f.tickAt(f.wall.Add(time.Hour - time.Nanosecond))
	if f.storageState().NoticeRecords != base {
		t.Fatal("removed inside its interval")
	}
	f.tickAt(f.wall.Add(time.Nanosecond))
	got := f.notices()
	if _, ok := got[sshKey(admission.NoticeCapacity, admission.ReasonCeiling)]; ok || f.storageState().NoticeRecords != base-1 {
		t.Fatalf("quiet record kept: %+v", got)
	}
	if _, ok := got[criticalSummary]; !ok {
		t.Fatal("a fixed record was removed")
	}
	if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatalf("reopen: %v", err)
	}
	// A new event after delivery takes the record out of the index.
	g := newLedgerFixture(t)
	id = g.criticalQueued()
	if _, err := g.l.Defer(id, admission.ReasonCeiling); err != nil {
		t.Fatal(err)
	}
	due, _ = g.l.PendingNotices()
	acks = acks[:0]
	for _, r := range due {
		acks = append(acks, admission.NoticeAck{Key: r.Key, First: r.First, Count: r.Count})
	}
	if err := g.l.AckNotices(acks); err != nil {
		t.Fatal(err)
	}
	g.nextGeneration()
	other := g.criticalQueued()
	if _, err := g.l.Defer(other, admission.ReasonCeiling); err != nil {
		t.Fatal(err)
	}
	g.tickAt(g.wall.Add(2 * time.Hour))
	if r := g.notices()[sshKey(admission.NoticeCapacity, admission.ReasonCeiling)]; r.Count != 2 {
		t.Fatalf("a record with a pending event was removed: %+v", r)
	}
	if _, err := OpenAdmissionLedger(g.db, g.reg); err != nil {
		t.Fatalf("reopen: %v", err)
	}
}

// Opening refuses a quiet index that disagrees with its records.
func TestAdmissionLedgerRefusesADamagedQuietIndex(t *testing.T) {
	for name, damage := range map[string]func(tx *bolt.Tx, k admission.NoticeKey, at time.Time) error{
		"missing index": func(tx *bolt.Tx, k admission.NoticeKey, at time.Time) error {
			q, _ := admission.QuietKey(at, k)
			return tx.Bucket([]byte(admissionOutboxBucket)).Delete(q)
		},
		"index of another time": func(tx *bolt.Tx, k admission.NoticeKey, at time.Time) error {
			q, _ := admission.QuietKey(at, k)
			if err := tx.Bucket([]byte(admissionOutboxBucket)).Delete(q); err != nil {
				return err
			}
			q, _ = admission.QuietKey(at.Add(time.Second), k)
			return tx.Bucket([]byte(admissionOutboxBucket)).Put(q, nil)
		},
		"index without its record": func(tx *bolt.Tx, k admission.NoticeKey, at time.Time) error {
			q, _ := admission.QuietKey(at, sshKey(admission.NoticeCapacity, admission.ReasonSetFull))
			return tx.Bucket([]byte(admissionOutboxBucket)).Put(q, nil)
		},
		"index with a value": func(tx *bolt.Tx, k admission.NoticeKey, at time.Time) error {
			q, _ := admission.QuietKey(at, k)
			return tx.Bucket([]byte(admissionOutboxBucket)).Put(q, []byte("x"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newLedgerFixture(t)
			id := f.criticalQueued()
			if _, err := f.l.Defer(id, admission.ReasonCeiling); err != nil {
				t.Fatal(err)
			}
			key := sshKey(admission.NoticeCapacity, admission.ReasonCeiling)
			if err := f.l.AckNotices([]admission.NoticeAck{{Key: key, First: f.notices()[key].First, Count: 1}}); err != nil {
				t.Fatal(err)
			}
			at := f.notices()[key].QuietAt()
			if err := f.db.bolt.Update(func(tx *bolt.Tx) error { return damage(tx, key, at) }); err != nil {
				t.Fatal(err)
			}
			if _, err := OpenAdmissionLedger(f.db, f.reg); !isCorrupt(err) {
				t.Fatalf("err = %v, want a corrupt record", err)
			}
		})
	}
}

// cursorFor finds a reputation cursor whose evidence sorts before own.
func cursorFor(t *testing.T, f *ledgerFixture, own admission.EvidenceID) string {
	t.Helper()
	for i := 0; i < 64; i++ {
		c := fmt.Sprintf("corroborating-%d", i)
		if f.mint(evidenceSpec{producer: f.rep, check: "reputation", cursor: c}).ID() < own {
			return c
		}
	}
	t.Fatal("no cursor sorts first")
	return ""
}

// The family is the kind's action family: a promotion is address work.
func TestAdmissionLedgerNoticeNamesTheActionFamily(t *testing.T) {
	f := newLedgerFixture(t)
	f.nextGeneration()
	root := f.published(evidenceSpec{cursor: "promote", severity: admission.SeverityCritical})
	req := f.request("192.0.2.10", root)
	req.Kind = admission.KindPromote
	_, id := f.enqueue(req)
	if _, err := f.l.Defer(id, admission.ReasonCeiling); err != nil {
		t.Fatal(err)
	}
	if r := f.notices()[sshKey(admission.NoticeCapacity, admission.ReasonCeiling)]; r.Count != 1 {
		t.Fatalf("records = %+v", f.notices())
	}
}
