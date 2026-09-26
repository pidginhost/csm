package admission

import (
	"fmt"
	"sort"
	"time"
)

const queueEntryVersion = 1
const queueStateVersion = 1
const queueCountersVersion = 1
const ingressStateVersion = 1

// QueueEntry is the ledger's derived record of a live candidate: where it
// holds its queue position and how it was last assessed. Recovery rebuilds
// it from the candidate and its roots; it is never proof of anything.
type QueueEntry struct {
	Partition Partition
	// Tier, Direct, Corroborated and NextChange come from the last
	// successful assessment. All are zero before one has succeeded; such
	// an entry holds a general position.
	Tier         Tier
	Direct       bool
	Corroborated bool
	NextChange   time.Time
}

// Assessed reports whether an assessment has succeeded for the entry.
func (q QueueEntry) Assessed() bool { return q.Tier != (Tier{}) }

// Eligible reports whether the last assessment allows the reserved lane.
func (q QueueEntry) Eligible() bool { return q.Direct || q.Corroborated }

type queueEntryRecord struct {
	V            uint8     `json:"v"`
	Partition    Partition `json:"partition"`
	Class        Class     `json:"class,omitempty"`
	Severity     Severity  `json:"severity,omitempty"`
	Direct       bool      `json:"direct,omitempty"`
	Corroborated bool      `json:"corroborated,omitempty"`
	NextChange   int64     `json:"next_change,omitempty"`
}

func (q QueueEntry) record() (queueEntryRecord, error) {
	bad := func(detail string) (queueEntryRecord, error) {
		return queueEntryRecord{}, refuse(ReasonInvalid, detail)
	}
	if !q.Partition.Valid() {
		return bad("queue entry has no partition")
	}
	rec := queueEntryRecord{V: queueEntryVersion, Partition: q.Partition, Class: q.Tier.Class, Severity: q.Tier.Severity, Direct: q.Direct, Corroborated: q.Corroborated}
	if !q.Assessed() {
		if q.Eligible() || !q.NextChange.IsZero() || q.Partition != PartitionGeneral {
			return bad("an unassessed queue entry carries assessment fields")
		}
		return rec, nil
	}
	var ok bool
	switch {
	case !q.Tier.Valid():
		return bad("queue entry tier is invalid")
	case q.Direct && q.Corroborated:
		return bad("queue entry is both direct and corroborated")
	case q.Eligible() && q.Tier.Class != ClassC3:
		return bad("only a C3 queue entry uses the reserved lane")
	case q.Partition == PartitionReserved && !q.Eligible():
		return bad("an ineligible queue entry holds a reserved position")
	}
	if rec.NextChange, ok = unixNano(q.NextChange); !ok {
		return bad("queue entry has no reassessment time")
	}
	return rec, nil
}

// Validate checks the entry's invariants.
func (q QueueEntry) Validate() error {
	_, err := q.record()
	return err
}

func (q QueueEntry) MarshalBinary() ([]byte, error) {
	rec, err := q.record()
	if err != nil {
		return nil, err
	}
	return sealRecord(rec)
}

// UnmarshalQueueEntry decodes a stored entry and checks its invariants.
func UnmarshalQueueEntry(data []byte) (QueueEntry, error) {
	var rec queueEntryRecord
	if err := openRecord(data, &rec); err != nil {
		return QueueEntry{}, err
	}
	q := QueueEntry{Partition: rec.Partition, Tier: Tier{Class: rec.Class, Severity: rec.Severity}, Direct: rec.Direct,
		Corroborated: rec.Corroborated, NextChange: fromNano(rec.NextChange)}
	if again, err := q.record(); rec.V != queueEntryVersion || err != nil || again != rec {
		return QueueEntry{}, ErrCorruptRecord
	}
	return q, nil
}

// QueueState is the ledger's queue bookkeeping.
type QueueState struct {
	// NextSweep is the earliest time a queued candidate may need attention
	// without a new report: an age-out, an effect expiry while it waits to
	// retry, or a reassessment. Zero when nothing waits.
	NextSweep time.Time
	Cursors   QueueCursors
}

type queueStateRecord struct {
	V         uint8  `json:"v"`
	NextSweep int64  `json:"next_sweep,omitempty"`
	General   string `json:"general,omitempty"`
	Reserved  string `json:"reserved,omitempty"`
}

func validCursor(c string) bool { return c == "" || boundedToken(c, 128) }

func (s QueueState) record() (queueStateRecord, error) {
	rec := queueStateRecord{V: queueStateVersion, General: s.Cursors.General, Reserved: s.Cursors.Reserved}
	if !s.NextSweep.IsZero() {
		var ok bool
		if rec.NextSweep, ok = unixNano(s.NextSweep); !ok {
			return queueStateRecord{}, refuse(ReasonInvalid, "queue sweep time is not representable")
		}
	}
	if !validCursor(rec.General) || !validCursor(rec.Reserved) {
		return queueStateRecord{}, refuse(ReasonInvalid, "queue cursor is malformed")
	}
	return rec, nil
}

func (s QueueState) MarshalBinary() ([]byte, error) {
	rec, err := s.record()
	if err != nil {
		return nil, err
	}
	return sealRecord(rec)
}

// UnmarshalQueueState decodes stored queue bookkeeping.
func UnmarshalQueueState(data []byte) (QueueState, error) {
	var rec queueStateRecord
	if err := openRecord(data, &rec); err != nil {
		return QueueState{}, err
	}
	s := QueueState{NextSweep: fromNano(rec.NextSweep), Cursors: QueueCursors{General: rec.General, Reserved: rec.Reserved}}
	if again, err := s.record(); rec.V != queueStateVersion || err != nil || again != rec {
		return QueueState{}, ErrCorruptRecord
	}
	return s, nil
}

// QueueEvent is what a queue counter counts. Values are persisted: append,
// never renumber.
type QueueEvent uint8

const (
	// EventRefused counts arrivals refused before they held a position.
	EventRefused QueueEvent = iota + 1
	// EventDeferred counts queued candidates taking a new deferral reason.
	EventDeferred
	// EventEnded counts queued candidates ending as refused, withheld or
	// dropped, including those displaced by overflow.
	EventEnded
	queueEventEnd
)

func (e QueueEvent) Valid() bool { return e >= EventRefused && e < queueEventEnd }

// CountKey is one counter. Class and Severity are both zero for a
// candidate without an assessment. No counter names an address, account or
// check: spec 5.17 keeps these dimensions fixed.
type CountKey struct {
	Event    QueueEvent
	Reason   Reason
	Class    Class
	Severity Severity
}

func (k CountKey) valid() bool {
	unassessed := k.Class == 0 && k.Severity == 0
	return k.Event.Valid() && k.Reason.Valid() && (unassessed || (k.Class.Valid() && k.Severity.Valid()))
}

// QueueCounters are durable, fixed-dimensional queue counts. Counts
// saturate instead of wrapping. The zero value is empty and ready to use.
type QueueCounters struct {
	counts map[CountKey]uint64
}

// Add counts one event.
func (q *QueueCounters) Add(k CountKey) error {
	if !k.valid() {
		return refuse(ReasonInvalid, "queue counter key is invalid")
	}
	if q.counts == nil {
		q.counts = map[CountKey]uint64{}
	}
	if q.counts[k] != ^uint64(0) {
		q.counts[k]++
	}
	return nil
}

// Count returns the count for k.
func (q QueueCounters) Count(k CountKey) uint64 { return q.counts[k] }

type queueCountRow struct {
	Event    QueueEvent `json:"e"`
	Reason   Reason     `json:"r"`
	Class    Class      `json:"c,omitempty"`
	Severity Severity   `json:"s,omitempty"`
	N        uint64     `json:"n"`
}

type queueCountersRecord struct {
	V    uint8           `json:"v"`
	Rows []queueCountRow `json:"rows"`
}

func rowLess(a, b queueCountRow) bool {
	switch {
	case a.Event != b.Event:
		return a.Event < b.Event
	case a.Reason != b.Reason:
		return a.Reason < b.Reason
	case a.Class != b.Class:
		return a.Class < b.Class
	}
	return a.Severity < b.Severity
}

func (q QueueCounters) MarshalBinary() ([]byte, error) {
	rows := make([]queueCountRow, 0, len(q.counts))
	for k, n := range q.counts {
		if !k.valid() || n == 0 {
			return nil, refuse(ReasonInvalid, "queue counter is invalid")
		}
		rows = append(rows, queueCountRow{Event: k.Event, Reason: k.Reason, Class: k.Class, Severity: k.Severity, N: n})
	}
	sort.Slice(rows, func(i, j int) bool { return rowLess(rows[i], rows[j]) })
	return sealRecord(queueCountersRecord{V: queueCountersVersion, Rows: rows})
}

// UnmarshalQueueCounters decodes stored counters.
func UnmarshalQueueCounters(data []byte) (QueueCounters, error) {
	var rec queueCountersRecord
	if err := openRecord(data, &rec); err != nil {
		return QueueCounters{}, err
	}
	if rec.V != queueCountersVersion || rec.Rows == nil {
		return QueueCounters{}, ErrCorruptRecord
	}
	q := QueueCounters{counts: make(map[CountKey]uint64, len(rec.Rows))}
	for i, row := range rec.Rows {
		k := CountKey{Event: row.Event, Reason: row.Reason, Class: row.Class, Severity: row.Severity}
		if !k.valid() || row.N == 0 || (i > 0 && !rowLess(rec.Rows[i-1], row)) {
			return QueueCounters{}, ErrCorruptRecord
		}
		q.counts[k] = row.N
	}
	return q, nil
}

func (e QueueEvent) String() string {
	switch e {
	case EventRefused:
		return "refused"
	case EventDeferred:
		return "deferred"
	case EventEnded:
		return "ended"
	}
	return fmt.Sprintf("event(%d)", uint8(e))
}

// IngressState is the ledger's record of ingress generations. Items the
// ingress held when the daemon stopped without a clean close are lost; the
// ledger cannot count them, only record that a generation was interrupted.
type IngressState struct {
	// Generation numbers the current ingress generation, from 1; zero
	// before the first.
	Generation uint64
	// Open is true from BeginIngress until a clean EndIngress.
	Open bool
	// Persisted counts arrivals decided in the current generation.
	Persisted uint64
	// Interrupted counts generations that ended without a clean close.
	Interrupted uint64
	Checkpoint  *IngressCheckpoint
}

type ingressStateRecord struct {
	V           uint8              `json:"v"`
	Generation  uint64             `json:"generation,omitempty"`
	Open        bool               `json:"open,omitempty"`
	Persisted   uint64             `json:"persisted,omitempty"`
	Interrupted uint64             `json:"interrupted,omitempty"`
	Checkpoint  *IngressCheckpoint `json:"checkpoint,omitempty"`
}

func (s IngressState) record() (ingressStateRecord, error) {
	if (s.Generation == 0 && (s.Open || s.Persisted != 0)) || s.Interrupted >= max(s.Generation, 1) {
		return ingressStateRecord{}, refuse(ReasonInvalid, "ingress state is inconsistent")
	}
	if cp := s.Checkpoint; cp != nil {
		if cp.Generation > s.Generation || cp.Validate(nil, cp.Generation) != nil {
			return ingressStateRecord{}, refuse(ReasonInvalid, "ingress checkpoint is inconsistent")
		}
	}
	return ingressStateRecord{V: ingressStateVersion, Generation: s.Generation, Open: s.Open, Persisted: s.Persisted, Interrupted: s.Interrupted, Checkpoint: s.Checkpoint}, nil
}

func (s IngressState) MarshalBinary() ([]byte, error) {
	rec, err := s.record()
	if err != nil {
		return nil, err
	}
	return sealRecord(rec)
}

// UnmarshalIngressState decodes the stored ingress record.
func UnmarshalIngressState(data []byte) (IngressState, error) {
	var rec ingressStateRecord
	if err := openRecord(data, &rec); err != nil {
		return IngressState{}, err
	}
	s := IngressState{Generation: rec.Generation, Open: rec.Open, Persisted: rec.Persisted, Interrupted: rec.Interrupted, Checkpoint: rec.Checkpoint}
	if _, err := s.record(); rec.V != ingressStateVersion || err != nil {
		return IngressState{}, ErrCorruptRecord
	}
	return s, nil
}
