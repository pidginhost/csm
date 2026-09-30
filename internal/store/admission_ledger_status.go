package store

import (
	"errors"
	"sort"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// Status reads the ledger for status and doctor (ruling 8): one read
// transaction, without the mutex or a current clock, so it answers while
// another call runs and while the ledger cannot be written. Each section
// is read on its own; a damaged record fails only its own section.
func (l *AdmissionLedger) Status() admission.LedgerStatus {
	var s admission.LedgerStatus
	err := l.db.bolt.View(func(tx *bolt.Tx) error {
		section := func(read func() error, buckets ...string) string {
			for _, name := range buckets {
				if tx.Bucket([]byte(name)) == nil {
					return admission.ErrCorruptRecord.Error()
				}
			}
			if err := read(); err != nil {
				return err.Error()
			}
			return ""
		}
		var now time.Time
		s.Clock.Error = section(func() error {
			clock, err := loadLedgerClock(tx.Bucket([]byte(admissionMetaBucket)))
			if err != nil {
				return err
			}
			now = clock.Now()
			s.Clock.Now = now
			return nil
		}, admissionMetaBucket)
		s.Queue.Error = section(func() error { return queueStatus(tx, &s.Queue) }, admissionQueueBucket, admissionCandidatesBucket)
		s.Counters.Error = section(func() error {
			counters, loadErr := loadQueueCounters(tx)
			s.Counters.Rows = admission.CountRows(counters.Rows())
			return loadErr
		}, admissionQueueStateBucket)
		s.Outcomes.Error = section(func() error {
			if s.Clock.Error != "" {
				return errors.New("the admission clock is unreadable")
			}
			return outcomesStatus(tx, now, &s.Outcomes)
		}, admissionWindowsBucket)
		s.Ingress.Error = section(func() error {
			in, loadErr := loadIngressState(tx)
			s.Ingress = admission.IngressSection{Generation: in.Generation, Open: in.Open, Persisted: in.Persisted, Interrupted: in.Interrupted, Resumed: in.Resumed}
			return loadErr
		}, admissionQueueStateBucket)
		s.Ceiling.Error = section(func() error { return ceilingStatus(tx, now, &s.Ceiling) }, admissionQueueStateBucket, admissionChargesBucket)
		s.Storage.Error = section(func() error { return storageStatus(tx, &s.Storage) }, admissionQueueStateBucket, admissionAttemptsBucket, admissionHistoryBucket)
		s.Outbox.Error = section(func() error { return outboxStatus(tx, &s.Outbox) }, admissionOutboxBucket)
		s.Notices.Error = section(func() error { return noticesStatus(tx, &s.Notices) }, admissionOutboxBucket)
		return nil
	})
	if err != nil {
		for _, section := range []*string{
			&s.Clock.Error, &s.Queue.Error, &s.Counters.Error, &s.Outcomes.Error, &s.Ingress.Error,
			&s.Ceiling.Error, &s.Storage.Error, &s.Outbox.Error, &s.Notices.Error,
		} {
			*section = err.Error()
		}
	}
	return s
}

func queueStatus(tx *bolt.Tx, out *admission.QueueStatus) error {
	occupancy := map[admission.QueueOccupancy]int{}
	err := tx.Bucket([]byte(admissionQueueBucket)).ForEach(func(k, v []byte) error {
		e, err := admission.UnmarshalQueueEntry(v)
		if err != nil {
			return err
		}
		c, err := loadCandidate(tx, admission.CandidateID(k))
		if err != nil {
			return corruptRecord(err)
		}
		switch c.State {
		case admission.StateQueued:
			out.Queued++
			if c.Attempts > 0 {
				out.Retrying++
			}
			if out.Oldest.IsZero() || c.FirstQueued.Before(out.Oldest) {
				out.Oldest = c.FirstQueued
			}
		case admission.StateReserved:
			out.Reserved++
		case admission.StateExecuting:
			out.Executing++
		default:
			return admission.ErrCorruptRecord
		}
		occupancy[admission.QueueOccupancy{Kind: c.Key.Kind.String(), Partition: e.Partition.String()}]++
		return nil
	})
	for o, n := range occupancy {
		o.Count = n
		out.Occupancy = append(out.Occupancy, o)
	}
	sort.Slice(out.Occupancy, func(i, j int) bool {
		a, b := out.Occupancy[i], out.Occupancy[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Partition < b.Partition
	})
	return err
}

// outcomesStatus sums each span's buckets inside its window at now.
func outcomesStatus(tx *bolt.Tx, now time.Time, out *admission.OutcomesStatus) error {
	if err := proveOutcomes(tx, now); err != nil {
		return err
	}
	windows := tx.Bucket([]byte(admissionWindowsBucket))
	for _, w := range []struct {
		span admission.Span
		rows *[]admission.OutcomeStatusRow
	}{{admission.SpanFiveMinutes, &out.Hour}, {admission.SpanHour, &out.Day}, {admission.SpanDay, &out.Month}} {
		var sum admission.OutcomeCounts
		cur := windows.Cursor()
		oldest := w.span.Key(w.span.Oldest(now))
		for k, v := cur.Seek(oldest); k != nil && k[0] == oldest[0] && k[1] == oldest[1]; k, v = cur.Next() {
			if _, _, err := admission.ParseSpanKey(k); err != nil {
				return err
			}
			c, err := admission.UnmarshalOutcomeCounts(v)
			if err != nil {
				return err
			}
			sum.Merge(c)
		}
		*w.rows = admission.OutcomeRows(sum)
	}
	return nil
}

func ceilingStatus(tx *bolt.Tx, now time.Time, out *admission.CeilingStatus) error {
	c, err := loadCeiling(tx)
	if err != nil {
		return err
	}
	general, reserved := admission.CeilingLanes(c.Limit)
	out.Limit = c.Limit
	out.General = admission.LaneStatus{Size: general, Used: c.General.Used, Credit: c.General.Units()}
	out.Reserved = admission.LaneStatus{Size: reserved, Used: c.Reserved.Used, Credit: c.Reserved.Units()}
	var charges []admission.Charge
	for _, lane := range []struct {
		lane admission.Lane
		out  *admission.LaneStatus
	}{{admission.LaneGeneral, &out.General}, {admission.LaneDirect, &out.Reserved}} {
		if c.Budget(lane.lane) > 0 || now.IsZero() {
			continue
		}
		if charges == nil {
			if charges, err = loadCharges(tx); err != nil {
				return err
			}
		}
		if d, ok := c.UntilBudget(lane.lane, charges, now); ok {
			lane.out.Next = d
		}
	}
	return nil
}

// storageStatus reads the storage record, the outstanding attempts'
// holds and the retained review horizon.
func storageStatus(tx *bolt.Tx, out *admission.StorageStatus) error {
	s, err := loadStorageState(tx)
	if err != nil {
		return err
	}
	allowance := func(l admission.Lane, m admission.HistoryMeter, size uint64) admission.AllowanceStatus {
		return admission.AllowanceStatus{Size: size, Used: m.Used, Credit: m.Bytes(), Room: s.HistoryRoom(l)}
	}
	general, reserved := admission.HistoryLanes()
	out.General = allowance(admission.LaneGeneral, s.General, general)
	out.Reserved = allowance(admission.LaneDirect, s.Reserved, reserved)
	out.Pinned, out.Ended, out.Loose = s.Recovery, s.Ended.Count, s.Loose.Count
	// Outstanding attempts are read from the attempts, not the queue, so
	// a damaged queue record cannot hide the reserve.
	err = tx.Bucket([]byte(admissionAttemptsBucket)).ForEach(func(k, v []byte) error {
		a, decodeErr := admission.UnmarshalAttempt(v)
		if decodeErr != nil {
			return decodeErr
		}
		if string(k) != string(a.Attempt.ID) {
			return admission.ErrCorruptRecord
		}
		if a.State != admission.StateReserved && a.State != admission.StateExecuting {
			return nil
		}
		h, found, loadErr := loadHistoryEntry(tx, a.Attempt.Candidate)
		if loadErr != nil || !found {
			return admission.ErrCorruptRecord
		}
		out.Outstanding += uint64(h.Charged())
		return nil
	})
	if err != nil {
		return err
	}
	if held := s.Recovery + s.OutboxBytes() + out.Outstanding; s.Recovery < admission.RecoveryReserveBytes && held < admission.RecoveryReserveBytes {
		out.RecoveryRoom = admission.RecoveryReserveBytes - held
	}
	return tx.Bucket([]byte(admissionHistoryBucket)).ForEach(func(k, v []byte) error {
		if _, err := admission.ParseCandidateID(string(k)); err != nil {
			return admission.ErrCorruptRecord
		}
		h, err := admission.UnmarshalHistoryEntry(v)
		if err != nil {
			return err
		}
		if !h.Ended.IsZero() && (out.ReviewHorizon.IsZero() || h.Ended.Before(out.ReviewHorizon)) {
			out.ReviewHorizon = h.Ended
		}
		return nil
	})
}

// outboxStatus counts the rows and records the outbox holds, from the
// outbox itself, so a damaged storage record does not hide them.
func outboxStatus(tx *bolt.Tx, out *admission.OutboxStatus) error {
	if err := tx.Bucket([]byte(admissionOutboxBucket)).ForEach(func(k, v []byte) error {
		switch k[0] {
		case 'a':
			if row, err := admission.UnmarshalAuditRow(v); err != nil || string(row.Key()) != string(k) {
				return admission.ErrCorruptRecord
			}
			out.AuditRows++
		case 'n':
			out.NoticeRecords++
		case 'q':
			// Notice records and their quiet indexes are proved in notices.
		default:
			return admission.ErrCorruptRecord
		}
		return nil
	}); err != nil {
		return err
	}
	out.AuditBytes = out.AuditRows * admission.AuditSlotBytes
	out.NoticeBytes = out.NoticeRecords * admission.NoticeSlotBytes
	return nil
}

func noticesStatus(tx *bolt.Tx, out *admission.NoticesStatus) error {
	for _, key := range admission.FixedNoticeKeys() {
		if _, found, err := loadNoticeRecord(tx, key); err != nil || !found {
			return admission.ErrCorruptRecord
		}
	}
	cur := tx.Bucket([]byte(admissionOutboxBucket)).Cursor()
	quiet := map[admission.NoticeKey]time.Time{}
	for k, v := cur.Seek([]byte{'n'}); k != nil && k[0] == 'n'; k, v = cur.Next() {
		key, err := admission.ParseNoticeKey(k)
		if err != nil {
			return err
		}
		r, err := admission.UnmarshalNoticeRecord(v)
		if err != nil || r.Key != key {
			return admission.ErrCorruptRecord
		}
		if key.Kind == admission.NoticeCriticalSummary {
			out.LastCriticalGap = r.Last
		}
		if r.Count > 0 {
			out.Records = append(out.Records, admission.NoticeRow(r))
		}
		if at := r.QuietAt(); !at.IsZero() {
			quiet[key] = at
		}
	}
	for k, v := cur.Seek([]byte{'q'}); k != nil && k[0] == 'q'; k, v = cur.Next() {
		at, key, err := admission.ParseQuietKey(k)
		if err != nil || v == nil || len(v) != 0 || !quiet[key].Equal(at) {
			return admission.ErrCorruptRecord
		}
		delete(quiet, key)
	}
	if len(quiet) != 0 {
		return admission.ErrCorruptRecord
	}
	return nil
}
