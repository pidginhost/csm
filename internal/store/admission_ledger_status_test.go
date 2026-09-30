package store

import (
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// Status reads every section in one read transaction at the stored
// admission time, without changing the ledger.
func TestAdmissionLedgerStatusReportsEverySection(t *testing.T) {
	f := newLedgerFixture(t)
	if _, err := f.l.BeginIngress(); err != nil {
		t.Fatal(err)
	}
	// Two hours before the rest: outside the last hour, inside the day.
	f.applied(time.Hour)
	appliedAt := f.wall
	f.tickAt(f.wall.Add(2 * time.Hour))
	f.nextGeneration()
	queued := f.queued()
	direct := f.published(evidenceSpec{producer: f.mail, check: "mail_takeover", target: "192.0.2.11", cursor: "direct", severity: admission.SeverityCritical})
	f.enqueue(f.request("192.0.2.11", direct))
	crit := f.criticalQueued()
	if _, err := f.l.Defer(crit, admission.ReasonCeiling); err != nil {
		t.Fatal(err)
	}
	deferredAt := f.wall
	f.tickAt(f.wall.Add(time.Minute))
	f.applied(time.Hour)
	reserved, _ := f.admitted(time.Hour)
	_, a := f.admitted(time.Hour)
	if _, _, err := f.l.Finish(a.Attempt.ID, admission.DispositionFailed); err != nil {
		t.Fatal(err)
	}
	unknown, a := f.admitted(time.Hour)
	if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.l.Finish(a.Attempt.ID, admission.DispositionUnknown); err != nil {
		t.Fatal(err)
	}
	if err := f.l.AckNotices([]admission.NoticeAck{{Key: criticalSummary, First: f.notices()[criticalSummary].First, Count: 1}}); err != nil {
		t.Fatal(err)
	}
	before := f.snapshot()
	s := f.l.Status()
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("status changed the ledger")
	}
	for name, err := range map[string]string{
		"clock": s.Clock.Error, "queue": s.Queue.Error, "counters": s.Counters.Error, "outcomes": s.Outcomes.Error,
		"ingress": s.Ingress.Error, "ceiling": s.Ceiling.Error, "storage": s.Storage.Error, "outbox": s.Outbox.Error, "notices": s.Notices.Error,
	} {
		if err != "" {
			t.Errorf("%s: %s", name, err)
		}
	}
	if !s.Clock.Now.Equal(f.wall) {
		t.Errorf("clock %v", s.Clock.Now)
	}
	c, _ := f.l.Candidate(queued)
	if s.Queue.Queued != 4 || s.Queue.Reserved != 1 || s.Queue.Executing != 0 || s.Queue.Retrying != 1 || !s.Queue.Oldest.Equal(c.FirstQueued) {
		t.Errorf("queue = %+v", s.Queue)
	}
	if want := []admission.QueueOccupancy{{Kind: "block_ip", Partition: "general", Count: 4}, {Kind: "block_ip", Partition: "reserved", Count: 1}}; !reflect.DeepEqual(s.Queue.Occupancy, want) {
		t.Errorf("occupancy = %+v", s.Queue.Occupancy)
	}
	var deferred bool
	for _, r := range s.Counters.Rows {
		if r.Event == "deferred" && r.Reason == "ceiling" && r.Severity == "critical" && r.Class == "c2" && r.N == 1 {
			deferred = true
		}
	}
	if !deferred {
		t.Errorf("counters = %+v", s.Counters.Rows)
	}
	count := func(rows []admission.OutcomeStatusRow, outcome string) uint64 {
		var n uint64
		for _, r := range rows {
			if r.Outcome == outcome {
				n += r.N
			}
		}
		return n
	}
	if count(s.Outcomes.Hour, "applied") != 1 || count(s.Outcomes.Day, "applied") != 2 || count(s.Outcomes.Day, "failed") != 1 || count(s.Outcomes.Month, "unknown") != 1 {
		t.Errorf("outcomes = %+v", s.Outcomes)
	}
	var deferredRow bool
	for _, r := range s.Outcomes.Hour {
		if r.Event == "deferred" && r.Reason == "ceiling" && r.Class == "c2" && r.Severity == "critical" && r.N == 1 {
			deferredRow = true
		}
	}
	if !deferredRow {
		t.Errorf("hour = %+v", s.Outcomes.Hour)
	}
	if s.Ingress.Generation != 1 || !s.Ingress.Open {
		t.Errorf("ingress = %+v", s.Ingress)
	}
	// The first reservation's charge has left the ceiling's hour.
	general, reservedLane := admission.CeilingLanes(fixtureCeiling)
	if s.Ceiling.Limit != fixtureCeiling || s.Ceiling.General.Size != general || s.Ceiling.Reserved.Size != reservedLane ||
		s.Ceiling.General.Used != 4 || s.Ceiling.General.Next != 0 {
		t.Errorf("ceiling = %+v", s.Ceiling)
	}
	st := f.storageState()
	outstanding := uint64(f.cost(reserved))
	if s.Storage.Pinned != st.Recovery || s.Storage.Pinned != uint64(f.cost(unknown)) || s.Storage.Outstanding != outstanding ||
		s.Storage.RecoveryRoom != admission.RecoveryReserveBytes-st.Recovery-st.OutboxBytes()-outstanding {
		t.Errorf("storage = %+v", s.Storage)
	}
	if s.Storage.General.Used != st.General.Used || s.Storage.General.Credit != st.General.Bytes() || s.Storage.General.Room != st.HistoryRoom(admission.LaneGeneral) {
		t.Errorf("general allowance = %+v", s.Storage.General)
	}
	if !s.Storage.ReviewHorizon.Equal(appliedAt) {
		t.Errorf("review horizon %v, want %v", s.Storage.ReviewHorizon, appliedAt)
	}
	if s.Outbox.AuditRows != uint64(len(f.pendingAudit())) || s.Outbox.AuditBytes != s.Outbox.AuditRows*admission.AuditSlotBytes ||
		s.Outbox.NoticeRecords != st.NoticeRecords || s.Outbox.NoticeBytes != st.NoticeRecords*admission.NoticeSlotBytes {
		t.Errorf("outbox = %+v", s.Outbox)
	}
	if !s.Notices.LastCriticalGap.Equal(deferredAt) {
		t.Errorf("last critical gap %v", s.Notices.LastCriticalGap)
	}
	var capacity, summary bool
	for _, r := range s.Notices.Records {
		if r.Kind == "critical_summary" && r.Count == 1 && r.Unsent == 0 {
			summary = true
		}
		if r.Kind == "capacity" && r.Reason == "ceiling" && r.Check == "ssh_brute" && r.Effect == "address" && r.Count == 1 && r.Unsent == 1 && r.Last.Equal(deferredAt) {
			capacity = true
		}
		if r.Count == 0 {
			t.Errorf("an empty record is listed: %+v", r)
		}
	}
	if !capacity || !summary {
		t.Errorf("notices = %+v", s.Notices.Records)
	}
}

// One damaged record fails only its own section: the others still report.
func TestAdmissionLedgerStatusIsolatesDamage(t *testing.T) {
	for section, damage := range map[string]func(tx *bolt.Tx) error{
		"queue": func(tx *bolt.Tx) error {
			return tx.Bucket([]byte(admissionQueueBucket)).ForEach(func(k, _ []byte) error {
				return tx.Bucket([]byte(admissionQueueBucket)).Put(k, []byte("damaged"))
			})
		},
		"counters": func(tx *bolt.Tx) error {
			return tx.Bucket([]byte(admissionQueueStateBucket)).Put(queueCountersKey, []byte("damaged"))
		},
		"outcomes": func(tx *bolt.Tx) error {
			return tx.Bucket([]byte(admissionWindowsBucket)).ForEach(func(k, _ []byte) error {
				return tx.Bucket([]byte(admissionWindowsBucket)).Put(k, []byte("damaged"))
			})
		},
		"ingress": func(tx *bolt.Tx) error {
			return tx.Bucket([]byte(admissionQueueStateBucket)).Put(ingressStateKey, []byte("damaged"))
		},
		"ceiling": func(tx *bolt.Tx) error {
			return tx.Bucket([]byte(admissionQueueStateBucket)).Put(ceilingStateKey, []byte("damaged"))
		},
		"storage": func(tx *bolt.Tx) error {
			return tx.Bucket([]byte(admissionQueueStateBucket)).Put(storageStateKey, []byte("damaged"))
		},
		"outbox": func(tx *bolt.Tx) error {
			return tx.Bucket([]byte(admissionOutboxBucket)).Put([]byte("a-damaged"), []byte("damaged"))
		},
		"notices": func(tx *bolt.Tx) error {
			k, _ := admission.OverflowKey(admission.NoticeWithheld).Bytes()
			return tx.Bucket([]byte(admissionOutboxBucket)).Put(k, []byte("damaged"))
		},
		"clock": func(tx *bolt.Tx) error {
			return tx.Bucket([]byte(admissionMetaBucket)).Put(admissionClockKey, []byte("damaged"))
		},
	} {
		t.Run(section, func(t *testing.T) {
			f := newLedgerFixture(t)
			if _, err := f.l.BeginIngress(); err != nil {
				t.Fatal(err)
			}
			f.queued()
			f.applied(time.Hour)
			if err := f.db.bolt.Update(damage); err != nil {
				t.Fatal(err)
			}
			s := f.l.Status()
			errs := map[string]string{
				"clock": s.Clock.Error, "queue": s.Queue.Error, "counters": s.Counters.Error, "outcomes": s.Outcomes.Error,
				"ingress": s.Ingress.Error, "ceiling": s.Ceiling.Error, "storage": s.Storage.Error, "outbox": s.Outbox.Error, "notices": s.Notices.Error,
			}
			for name, err := range errs {
				// The outcome windows and the ceiling's next unit are
				// read at the stored clock.
				dependent := section == "clock" && name == "outcomes"
				if (name == section || dependent) != (err != "") {
					t.Errorf("damaged %s: section %s error %q", section, name, err)
				}
			}
			rows := admission.DoctorChecks(&s, nil, f.wall)
			if rows[0].Name != "admission ledger" || rows[0].Status != admission.DoctorFail {
				t.Fatalf("doctor = %+v", rows[0])
			}
		})
	}
}

// A lane without ceiling budget reports when it can charge again.
func TestAdmissionLedgerStatusReportsTheNextUnit(t *testing.T) {
	f := newLedgerFixture(t)
	if err := f.l.SetCeiling(5); err != nil {
		t.Fatal(err)
	}
	for i := 0; ; i++ {
		f.nextGeneration()
		id := f.queued()
		_, _, _, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour))
		if reason, ok := admission.ReasonOf(err); ok && reason == admission.ReasonCeiling {
			break
		}
		if err != nil || i > 10 {
			t.Fatalf("reservation %d: %v", i, err)
		}
	}
	s := f.l.Status()
	if s.Ceiling.General.Next <= 0 || s.Ceiling.General.Next > time.Hour || s.Ceiling.Reserved.Next != 0 {
		t.Fatalf("ceiling = %+v", s.Ceiling)
	}
}

// Canonical but misplaced rows and missing required records are damage
// too. Each fault affects only the section that owns that record.
func TestAdmissionLedgerStatusRejectsMisplacedRecords(t *testing.T) {
	for _, section := range []string{"outbox", "outcomes", "notices"} {
		t.Run(section, func(t *testing.T) {
			f := newLedgerFixture(t)
			f.applied(time.Hour)
			if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
				switch section {
				case "outbox":
					row := f.pendingAuditIn(t, tx)[0]
					outbox := tx.Bucket([]byte(admissionOutboxBucket))
					data := append([]byte(nil), outbox.Get(row.Key())...)
					if err := outbox.Delete(row.Key()); err != nil {
						return err
					}
					row.Transition += 100
					return outbox.Put(row.Key(), data)
				case "outcomes":
					span := admission.SpanFiveMinutes
					windows := tx.Bucket([]byte(admissionWindowsBucket))
					data := append([]byte(nil), windows.Get(span.Key(span.Start(f.wall)))...)
					return windows.Put(span.Key(span.Start(f.wall).Add(span.Width())), data)
				default:
					key, err := criticalSummary.Bytes()
					if err != nil {
						return err
					}
					return tx.Bucket([]byte(admissionOutboxBucket)).Delete(key)
				}
			}); err != nil {
				t.Fatal(err)
			}
			before := f.snapshot()
			s := f.l.Status()
			for name, err := range map[string]string{
				"clock": s.Clock.Error, "queue": s.Queue.Error, "counters": s.Counters.Error,
				"outcomes": s.Outcomes.Error, "ingress": s.Ingress.Error, "ceiling": s.Ceiling.Error,
				"storage": s.Storage.Error, "outbox": s.Outbox.Error, "notices": s.Notices.Error,
			} {
				if (err != "") != (name == section) {
					t.Errorf("%s damage, %s error = %q", section, name, err)
				}
			}
			if !reflect.DeepEqual(before, f.snapshot()) {
				t.Fatal("status changed the ledger")
			}
		})
	}
}

// With no outcome buckets, their validation cannot mask the independent
// requirement for a readable clock before reporting any outcome window.
func TestAdmissionLedgerStatusNeedsClockWithoutOutcomes(t *testing.T) {
	f := newLedgerFixture(t)
	if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
		if tx.Bucket([]byte(admissionWindowsBucket)).Stats().KeyN != 0 {
			t.Fatal("fixture unexpectedly has outcome buckets")
		}
		return tx.Bucket([]byte(admissionMetaBucket)).Put(admissionClockKey, []byte("damaged"))
	}); err != nil {
		t.Fatal(err)
	}
	s := f.l.Status()
	if s.Clock.Error == "" || s.Outcomes.Error == "" {
		t.Fatalf("missing clock did not fail both sections: clock=%q outcomes=%q", s.Clock.Error, s.Outcomes.Error)
	}
	if s.Queue.Error != "" || s.Counters.Error != "" || s.Ingress.Error != "" || s.Ceiling.Error != "" || s.Storage.Error != "" || s.Outbox.Error != "" || s.Notices.Error != "" {
		t.Fatal("missing clock failed an independent section")
	}
}

func TestAdmissionLedgerStatusIsolatesMissingBuckets(t *testing.T) {
	for bucket, affected := range map[string][]string{
		admissionMetaBucket:       {"clock", "outcomes"},
		admissionQueueBucket:      {"queue"},
		admissionCandidatesBucket: {"queue"},
		admissionQueueStateBucket: {"counters", "ingress", "ceiling", "storage"},
		admissionWindowsBucket:    {"outcomes"},
		admissionChargesBucket:    {"ceiling"},
		admissionAttemptsBucket:   {"storage"},
		admissionHistoryBucket:    {"storage"},
		admissionOutboxBucket:     {"outbox", "notices"},
	} {
		t.Run(bucket, func(t *testing.T) {
			f := newLedgerFixture(t)
			f.applied(time.Hour)
			if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
				return tx.DeleteBucket([]byte(bucket))
			}); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if p := recover(); p != nil {
					t.Errorf("status panicked after losing a bucket: %v", p)
				}
			}()
			s := f.l.Status()
			for name, err := range map[string]string{
				"clock": s.Clock.Error, "queue": s.Queue.Error, "counters": s.Counters.Error,
				"outcomes": s.Outcomes.Error, "ingress": s.Ingress.Error, "ceiling": s.Ceiling.Error,
				"storage": s.Storage.Error, "outbox": s.Outbox.Error, "notices": s.Notices.Error,
			} {
				want := false
				for _, section := range affected {
					want = want || name == section
				}
				if (err != "") != want {
					t.Errorf("%s error = %q, want damaged = %v", name, err, want)
				}
			}
		})
	}
}

func TestAdmissionLedgerStatusRejectsMisplacedAttempts(t *testing.T) {
	f := newLedgerFixture(t)
	f.admitted(time.Hour)
	before := f.l.Status()
	f.l.mu.Lock()
	defer f.l.mu.Unlock()
	tx, err := f.db.bolt.Begin(true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	attempts := tx.Bucket([]byte(admissionAttemptsBucket))
	_, v := attempts.Cursor().First()
	if err = attempts.Put([]byte("misplaced"), append([]byte(nil), v...)); err != nil {
		t.Fatal(err)
	}
	read := make(chan admission.LedgerStatus, 1)
	go func() { read <- f.l.Status() }()
	select {
	case during := <-read:
		if !reflect.DeepEqual(during, before) {
			t.Fatalf("status observed an uncommitted write: before=%+v during=%+v", before, during)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("status waited for the ledger writer")
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	s := f.l.Status()
	if s.Storage.Error == "" {
		t.Fatalf("duplicate attempt hid reserve damage: %+v", s.Storage)
	}
	if s.Queue.Error != "" || s.Outbox.Error != "" || s.Notices.Error != "" {
		t.Fatalf("misplaced attempt failed another section: %+v", s)
	}
}

func TestAdmissionLedgerStatusReportsUnreadableDatabase(t *testing.T) {
	f := newLedgerFixture(t)
	if err := f.db.Close(); err != nil {
		t.Fatal(err)
	}
	s := f.l.Status()
	for name, err := range map[string]string{
		"clock": s.Clock.Error, "queue": s.Queue.Error, "counters": s.Counters.Error,
		"outcomes": s.Outcomes.Error, "ingress": s.Ingress.Error, "ceiling": s.Ceiling.Error,
		"storage": s.Storage.Error, "outbox": s.Outbox.Error, "notices": s.Notices.Error,
	} {
		if err == "" {
			t.Errorf("unreadable database reported a healthy %s section", name)
		}
	}
}

func TestAdmissionLedgerStatusRejectsUnrecognizedRecordKeys(t *testing.T) {
	for _, section := range []string{"storage", "outbox"} {
		t.Run(section, func(t *testing.T) {
			f := newLedgerFixture(t)
			f.applied(time.Hour)
			if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
				if section == "storage" {
					history := tx.Bucket([]byte(admissionHistoryBucket))
					_, v := history.Cursor().First()
					return history.Put([]byte("misplaced"), append([]byte(nil), v...))
				}
				outbox := tx.Bucket([]byte(admissionOutboxBucket))
				k, v := outbox.Cursor().Seek([]byte{'a'})
				data := append([]byte(nil), v...)
				if err := outbox.Delete(k); err != nil {
					return err
				}
				return outbox.Put([]byte("misplaced"), data)
			}); err != nil {
				t.Fatal(err)
			}
			s := f.l.Status()
			for name, err := range map[string]string{
				"clock": s.Clock.Error, "queue": s.Queue.Error, "counters": s.Counters.Error,
				"outcomes": s.Outcomes.Error, "ingress": s.Ingress.Error, "ceiling": s.Ceiling.Error,
				"storage": s.Storage.Error, "outbox": s.Outbox.Error, "notices": s.Notices.Error,
			} {
				if (err != "") != (name == section) {
					t.Errorf("misplaced %s record: %s error = %q", section, name, err)
				}
			}
		})
	}
}

func TestAdmissionLedgerStatusRejectsDamagedQuietIndexes(t *testing.T) {
	for _, damage := range []string{"malformed", "missing", "unexpected value"} {
		t.Run(damage, func(t *testing.T) {
			f := newLedgerFixture(t)
			id := f.criticalQueued()
			if _, err := f.l.Defer(id, admission.ReasonCeiling); err != nil {
				t.Fatal(err)
			}
			for key, r := range f.notices() {
				if err := f.l.AckNotices([]admission.NoticeAck{{Key: key, First: r.First, Count: r.Count}}); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
				outbox := tx.Bucket([]byte(admissionOutboxBucket))
				k, _ := outbox.Cursor().Seek([]byte{'q'})
				if k == nil || k[0] != 'q' {
					t.Fatal("fixture has no quiet index")
				}
				switch damage {
				case "malformed":
					return outbox.Put([]byte("q-damaged"), nil)
				case "missing":
					return outbox.Delete(k)
				default:
					return outbox.Put(k, []byte("damaged"))
				}
			}); err != nil {
				t.Fatal(err)
			}
			s := f.l.Status()
			if s.Notices.Error == "" || s.Outbox.Error != "" || s.Storage.Error != "" {
				t.Fatalf("quiet index damage escaped its section: notices=%q outbox=%q storage=%q", s.Notices.Error, s.Outbox.Error, s.Storage.Error)
			}
		})
	}
}
