package admission

import (
	"fmt"
	"strconv"
	"time"
)

// Record bounds for storage accounting (spec 5.4). The invariants keep every
// valid record inside its bound; tests pin each bound with the largest
// record the invariants allow.
const (
	// MaxAttemptBytes bounds one encoded attempt record.
	MaxAttemptBytes = 320
	// MaxReportLinksBytes bounds one encoded set of report links.
	MaxReportLinksBytes = 256
	// MaxHistoryEntryBytes bounds one encoded history entry.
	MaxHistoryEntryBytes = 192
	// MaxEvidenceRefsBytes bounds one encoded evidence reference count.
	MaxEvidenceRefsBytes = 64
	// MaxHistoryBytes bounds the history bytes one candidate can be
	// charged: its largest record, its attempts, its history rows and its
	// roots at their largest.
	MaxHistoryBytes = 32 << 10
)

// HistoryRetention is the review window: an admitted candidate's details
// are kept at least this long after it ends (spec 5.4).
const HistoryRetention = 7 * 24 * time.Hour

// HistoryTarget is how long an ended candidate's details are kept when no
// quota needs their bytes.
const HistoryTarget = 30 * 24 * time.Hour

// candidateIDLen is the length of a derived candidate ID.
const candidateIDLen = len("cand_") + 32

// HistoryIndexKeyLen is the length of a history index key: a kind byte, a
// time as 19 decimal digits of nanoseconds and a candidate ID.
const HistoryIndexKeyLen = 1 + 19 + candidateIDLen

// HistoryTimes is when the details of an admitted candidate that ended at
// ended may first be retired, and when they are retired without pressure.
// They stay through the review window, and a verified effect's for as long
// as the effect can last.
func HistoryTimes(ended, expires time.Time, verified bool) (eligible, target time.Time) {
	eligible = ended.Add(HistoryRetention)
	if verified && expires.After(eligible) {
		eligible = expires
	}
	return eligible, retireTarget(ended, eligible)
}

func retireTarget(ended, eligible time.Time) time.Time {
	if target := ended.Add(HistoryTarget); target.After(eligible) {
		return target
	}
	return eligible
}

const historyEntryVersion = 1

// HistoryEntry is the ledger's storage record of an admitted candidate: the
// history bytes its reservations charged to each allowance and, once it
// ends, the earliest time its details may be retired.
type HistoryEntry struct {
	// General and Reserved are the bytes charged to each allowance. The
	// direct and corroborated lanes share the reserved one.
	General, Reserved uint32
	// RootMask names roots covered by the last reservation, in candidate order.
	// Retry support stays queue data until a reservation pays for it.
	RootMask uint32
	// Ended is when the candidate ended; zero while it is live.
	Ended time.Time
	// Eligible is the earliest time its details may be retired. It is set
	// when the candidate ends, unless the outcome is pinned.
	Eligible time.Time
	// Pinned: the outcome is unresolved. Its bytes are held in the recovery
	// reserve, and it is not retired until recovery settles it.
	Pinned bool
}

// Charged is the history bytes the entry holds.
func (h HistoryEntry) Charged() uint32 { return h.General + h.Reserved }

// Target is when an ended entry's details are retired without pressure;
// zero while it is live or pinned.
func (h HistoryEntry) Target() time.Time {
	if h.Eligible.IsZero() {
		return time.Time{}
	}
	return retireTarget(h.Ended, h.Eligible)
}

type historyEntryRecord struct {
	V        uint8  `json:"v"`
	General  uint32 `json:"general,omitempty"`
	Reserved uint32 `json:"reserved,omitempty"`
	Ended    int64  `json:"ended,omitempty"`
	Eligible int64  `json:"eligible,omitempty"`
	Pinned   bool   `json:"pinned,omitempty"`
	RootMask uint32 `json:"root_mask,omitempty"`
}

func (h HistoryEntry) record() (historyEntryRecord, error) {
	bad := func(detail string) (historyEntryRecord, error) {
		return historyEntryRecord{}, refuse(ReasonInvalid, detail)
	}
	rec := historyEntryRecord{V: historyEntryVersion, General: h.General, Reserved: h.Reserved, Pinned: h.Pinned, RootMask: h.RootMask}
	if charged := uint64(h.General) + uint64(h.Reserved); charged == 0 || charged > MaxHistoryBytes {
		return bad("history entry charges nothing or more than any candidate")
	}
	if h.RootMask>>MaxRoots != 0 {
		return bad("history root mask exceeds the candidate bound")
	}
	if h.Ended.IsZero() {
		if !h.Eligible.IsZero() || h.Pinned {
			return bad("a live history entry is pinned or has a retirement time")
		}
		return rec, nil
	}
	var ok bool
	if rec.Ended, ok = unixNano(h.Ended); !ok || rec.Ended < 0 {
		return bad("history entry has no end time after the epoch")
	}
	if h.Pinned {
		if !h.Eligible.IsZero() {
			return bad("a pinned history entry has a retirement time")
		}
		return rec, nil
	}
	if rec.Eligible, ok = unixNano(h.Eligible); !ok || h.Eligible.Before(h.Ended.Add(HistoryRetention)) {
		return bad("history entry may be retired inside its review window")
	}
	if _, ok = unixNano(h.Target()); !ok {
		return bad("history entry target is not representable")
	}
	return rec, nil
}

// Index kinds of the history retirement keys.
const (
	// RetireGeneral and RetireReserved order an allowance's ended entries
	// by the earliest time they may be retired.
	RetireGeneral  = 'g'
	RetireReserved = 'r'
	// RetireTarget orders ended entries by their target.
	RetireTarget = 't'
)

// RetireKeys are an ended, unpinned entry's index keys: one for each
// allowance it charged, ordered by when it may be retired, and one ordered
// by its target. Each is its kind, the time as 19 decimal digits of
// nanoseconds, which sort as the times do, and the candidate ID. A live or
// pinned entry has none.
func (h HistoryEntry) RetireKeys(id CandidateID) ([][]byte, error) {
	if _, err := h.record(); err != nil {
		return nil, err
	}
	if _, err := ParseCandidateID(string(id)); err != nil {
		return nil, err
	}
	if h.Eligible.IsZero() {
		return nil, nil
	}
	// Both times are after the end, which is after the epoch, so each has
	// exactly 19 digits once padded.
	key := func(kind byte, at time.Time) []byte {
		return fmt.Appendf(make([]byte, 0, HistoryIndexKeyLen), "%c%019d%s", kind, at.UnixNano(), id)
	}
	var keys [][]byte
	if h.General > 0 {
		keys = append(keys, key(RetireGeneral, h.Eligible))
	}
	if h.Reserved > 0 {
		keys = append(keys, key(RetireReserved, h.Eligible))
	}
	return append(keys, key(RetireTarget, h.Target())), nil
}

// ParseRetireKey splits a history index key into its kind, time and
// candidate.
func ParseRetireKey(k []byte) (byte, time.Time, CandidateID, error) {
	if len(k) != HistoryIndexKeyLen || (k[0] != RetireGeneral && k[0] != RetireReserved && k[0] != RetireTarget) {
		return 0, time.Time{}, "", ErrCorruptRecord
	}
	n, err := strconv.ParseInt(string(k[1:20]), 10, 64)
	if err != nil || n <= 0 || fmt.Sprintf("%019d", n) != string(k[1:20]) {
		return 0, time.Time{}, "", ErrCorruptRecord
	}
	id, err := ParseCandidateID(string(k[20:]))
	if err != nil {
		return 0, time.Time{}, "", ErrCorruptRecord
	}
	return k[0], fromNano(n), id, nil
}

// Validate checks the entry's invariants.
func (h HistoryEntry) Validate() error {
	_, err := h.record()
	return err
}

func (h HistoryEntry) MarshalBinary() ([]byte, error) {
	rec, err := h.record()
	if err != nil {
		return nil, err
	}
	return sealRecord(rec)
}

// UnmarshalHistoryEntry decodes a stored history entry and checks its
// invariants.
func UnmarshalHistoryEntry(data []byte) (HistoryEntry, error) {
	var rec historyEntryRecord
	if err := openRecord(data, &rec); err != nil {
		return HistoryEntry{}, err
	}
	h := HistoryEntry{General: rec.General, Reserved: rec.Reserved, Ended: fromNano(rec.Ended), Eligible: fromNano(rec.Eligible), Pinned: rec.Pinned, RootMask: rec.RootMask}
	if again, err := h.record(); rec.V != historyEntryVersion || err != nil || again != rec {
		return HistoryEntry{}, ErrCorruptRecord
	}
	return h, nil
}

const evidenceRefsVersion = 1

// EvidenceRefs is how many stored candidates name one evidence record as a
// root. Evidence no candidate names is loose: it waits in a bounded ring,
// oldest out first, so rejected traffic allocates no unbounded rows.
type EvidenceRefs struct {
	// Refs counts the stored candidates that name the evidence.
	Refs uint32
	// Loose is the evidence's position in the loose ring while no candidate
	// names it; zero while one does.
	Loose uint64
}

type evidenceRefsRecord struct {
	V     uint8  `json:"v"`
	Refs  uint32 `json:"refs,omitempty"`
	Loose uint64 `json:"loose,omitempty"`
}

func (r EvidenceRefs) record() (evidenceRefsRecord, error) {
	if (r.Refs == 0) == (r.Loose == 0) {
		return evidenceRefsRecord{}, refuse(ReasonInvalid, "evidence must be named by a candidate or wait in the loose ring")
	}
	return evidenceRefsRecord{V: evidenceRefsVersion, Refs: r.Refs, Loose: r.Loose}, nil
}

func (r EvidenceRefs) MarshalBinary() ([]byte, error) {
	rec, err := r.record()
	if err != nil {
		return nil, err
	}
	return sealRecord(rec)
}

// UnmarshalEvidenceRefs decodes a stored reference count and checks its
// invariants.
func UnmarshalEvidenceRefs(data []byte) (EvidenceRefs, error) {
	var rec evidenceRefsRecord
	if err := openRecord(data, &rec); err != nil {
		return EvidenceRefs{}, err
	}
	r := EvidenceRefs{Refs: rec.Refs, Loose: rec.Loose}
	if again, err := r.record(); rec.V != evidenceRefsVersion || err != nil || again != rec {
		return EvidenceRefs{}, ErrCorruptRecord
	}
	return r, nil
}
