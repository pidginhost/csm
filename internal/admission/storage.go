package admission

import (
	"math"
	"time"
)

// Storage budgets of spec 5.4, internal constants rather than settings.
const (
	// HistoryBytes is the terminal-history budget: the details the ledger
	// keeps about admitted candidates. A fifth, rounded up, is reserved for
	// direct compromise and corroborated work.
	HistoryBytes = 256 << 20
	// RecoveryReserveBytes holds the details of unresolved outcomes apart
	// from history, until recovery settles them.
	RecoveryReserveBytes = 64 << 20
	// HistoryBurst is the most pacing credit an allowance saves: ten
	// minutes of its rate.
	HistoryBurst = 10 * time.Minute
	// HistoryQuantum is the history bytes a scope earns per scheduler turn,
	// so a scope of large records cannot take more than its share.
	HistoryQuantum = 4 << 10
	// MaxEndedCandidates bounds the candidates kept after ending before
	// any attempt. They are not history: only the newest are kept.
	MaxEndedCandidates = QueueCapacity
	// MaxLooseEvidence bounds the evidence kept that no stored candidate
	// names. The oldest leaves first.
	MaxLooseEvidence = QueueCapacity
)

// Stored IDs are fixed-length derived strings.
const (
	actionIDLen   = len("act_") + 32
	evidenceIDLen = len("ev_") + 32
)

// byteTicks is one byte of credit. An allowance admitting S bytes per
// second gains S ticks per nanosecond, so credit accrues without rounding.
const byteTicks = uint64(time.Second)

// HistoryLanes splits the history budget into the general allowance and
// the reserved one, ceil(HistoryBytes/5), as the ceiling splits its limit.
func HistoryLanes() (general, reserved uint64) {
	reserved = (HistoryBytes + 4) / 5
	return HistoryBytes - reserved, reserved
}

// HistoryRate is the bytes per second an allowance of size bytes admits:
// its size over the retention, so a week of admissions fits the budget
// however an attacker times them.
func HistoryRate(size uint64) uint64 { return size / uint64(HistoryRetention/time.Second) }

// HistoryCap is the most credit an allowance of size bytes saves.
func HistoryCap(size uint64) uint64 { return HistoryRate(size) * uint64(HistoryBurst/time.Second) }

// HistoryCost is the most ledger bytes an admitted candidate can retain,
// given the encoded size of each root's evidence in root order: its record
// at its widest, every attempt it may make, its history entry and index
// keys, and each root's evidence with a full set of report links and its
// reference count. Every record counts with its key. Evidence several
// candidates share is counted for each of them.
func HistoryCost(c Candidate, evidence []int) (uint32, error) {
	if len(evidence) != len(c.Roots) {
		return 0, refuse(ReasonInvalid, "history cost needs the size of every root")
	}
	record, err := c.MaxBytes()
	if err != nil {
		return 0, err
	}
	n := 2*candidateIDLen + record + MaxHistoryEntryBytes + 3*HistoryIndexKeyLen + MaxAttempts*(actionIDLen+MaxAttemptBytes)
	for _, size := range evidence {
		if size <= 0 || size > MaxEvidenceBytes {
			return 0, refuse(ReasonInvalid, "evidence size is out of range")
		}
		n += 3*evidenceIDLen + size + MaxReportLinksBytes + MaxEvidenceRefsBytes
	}
	if n <= 0 || n > MaxHistoryBytes {
		return 0, refuse(ReasonInvalid, "history cost is outside any candidate's range")
	}
	return uint32(n), nil
}

// HistoryMeter is one allowance of the history budget.
type HistoryMeter struct {
	// Credit is the saved pacing credit in ticks.
	Credit uint64
	// Used is the history bytes the allowance holds.
	Used uint64
}

// Bytes is the whole bytes of saved credit.
func (m HistoryMeter) Bytes() uint64 { return m.Credit / byteTicks }

// RingState counts the entries of one bounded ring. Positions start at 1 and
// only grow, so the oldest entry has the smallest.
type RingState struct {
	Count uint32
	// Last is the position the newest entry took; zero before the first.
	Last uint64
}

// Push takes the next position.
func (r RingState) Push() (RingState, uint64) {
	r.Count++
	r.Last++
	return r, r.Last
}

// Remove drops one entry.
func (r RingState) Remove() (RingState, error) {
	if r.Count == 0 {
		return r, ErrCorruptRecord
	}
	r.Count--
	return r, nil
}

// StorageState is the ledger's record of its storage budgets (spec 5.4):
// each history allowance's pacing credit and retained bytes, the recovery
// reserve and the two bounded rings.
type StorageState struct {
	General, Reserved HistoryMeter
	// Recovery is the history bytes of unresolved outcomes.
	Recovery uint64
	// Ended holds candidates that ended before any attempt; Loose holds
	// evidence no stored candidate names.
	Ended, Loose RingState
}

type historyAllowance struct {
	m    *HistoryMeter
	size uint64
}

func (s *StorageState) allowances() [2]historyAllowance {
	g, r := HistoryLanes()
	return [2]historyAllowance{{&s.General, g}, {&s.Reserved, r}}
}

func (s *StorageState) allowance(l Lane) historyAllowance {
	if l == LaneGeneral {
		return s.allowances()[0]
	}
	return s.allowances()[1]
}

// NewStorageState is a new ledger's state: each allowance saves its full
// credit once. An upgraded ledger starts from the zero value, without
// credit, since its recent spend is unknown.
func NewStorageState() StorageState {
	var s StorageState
	for _, a := range s.allowances() {
		a.m.Credit = HistoryCap(a.size) * byteTicks
	}
	return s
}

// HistoryBudget is the history bytes lane l can charge now: its saved
// credit, bounded by the room its allowance has once retirable bytes of
// ended history are retired.
func (s StorageState) HistoryBudget(l Lane, retirable uint64) uint64 {
	if !l.Valid() {
		return 0
	}
	a := s.allowance(l)
	used := a.m.Used - min(retirable, a.m.Used)
	if used >= a.size {
		return 0
	}
	return min(a.m.Bytes(), a.size-used)
}

// Advance credits elapsed admission time, refilling each allowance at its
// rate up to its cap. A long gap saturates instead of overflowing.
func (s StorageState) Advance(elapsed time.Duration) (StorageState, error) {
	if elapsed <= 0 {
		return s, nil
	}
	e := uint64(elapsed)
	for _, a := range s.allowances() {
		full, rate := HistoryCap(a.size)*byteTicks, HistoryRate(a.size)
		if a.m.Credit >= full {
			continue
		}
		if need := full - a.m.Credit; e >= (need+rate-1)/rate {
			a.m.Credit = full
		} else {
			a.m.Credit += rate * e
		}
	}
	return s, nil
}

// ChargeHistory spends bytes of lane l's credit and allowance. The ledger
// retires ended history first when the allowance needs room. A refusal
// changes nothing.
func (s StorageState) ChargeHistory(l Lane, bytes uint32) (StorageState, error) {
	if !l.Valid() || bytes == 0 || bytes > MaxHistoryBytes {
		return s, refuse(ReasonInvalid, "history charge has no lane or an invalid size")
	}
	if uint64(bytes) > s.HistoryBudget(l, 0) {
		return s, refuse(ReasonStorageShare, "lane has no history budget for the charge")
	}
	a := s.allowance(l)
	a.m.Credit -= uint64(bytes) * byteTicks
	a.m.Used += uint64(bytes)
	return s, nil
}

// ReleaseHistory returns retired history bytes to each allowance. It never
// refunds credit.
func (s StorageState) ReleaseHistory(general, reserved uint32) (StorageState, error) {
	if s.General.Used < uint64(general) || s.Reserved.Used < uint64(reserved) {
		return s, ErrCorruptRecord
	}
	s.General.Used -= uint64(general)
	s.Reserved.Used -= uint64(reserved)
	return s, nil
}

// PinHistory moves an unresolved outcome's history bytes from its
// allowances to the recovery reserve.
func (s StorageState) PinHistory(general, reserved uint32) (StorageState, error) {
	charged := uint64(general) + uint64(reserved)
	if charged > math.MaxUint64-s.Recovery {
		return s, ErrCorruptRecord
	}
	next, err := s.ReleaseHistory(general, reserved)
	if err != nil {
		return s, err
	}
	next.Recovery += charged
	return next, nil
}

// CheckRecovery refuses a reservation whose candidate, if its outcome were
// unresolved, would not fit the recovery reserve: new work waits while
// unresolved outcomes fill it.
func (s StorageState) CheckRecovery(bytes uint32) error {
	if s.Recovery > RecoveryReserveBytes || uint64(bytes) > RecoveryReserveBytes-s.Recovery {
		return refuse(ReasonPendingRecovery, "unresolved outcomes fill the recovery reserve")
	}
	return nil
}

const storageStateVersion = 1

type storageStateRecord struct {
	V              uint8  `json:"v"`
	GeneralCredit  uint64 `json:"general_credit,omitempty"`
	GeneralUsed    uint64 `json:"general_used,omitempty"`
	ReservedCredit uint64 `json:"reserved_credit,omitempty"`
	ReservedUsed   uint64 `json:"reserved_used,omitempty"`
	Recovery       uint64 `json:"recovery,omitempty"`
	EndedCount     uint32 `json:"ended_count,omitempty"`
	EndedLast      uint64 `json:"ended_last,omitempty"`
	LooseCount     uint32 `json:"loose_count,omitempty"`
	LooseLast      uint64 `json:"loose_last,omitempty"`
}

func (s StorageState) record() (storageStateRecord, error) {
	bad := func(detail string) (storageStateRecord, error) {
		return storageStateRecord{}, refuse(ReasonInvalid, detail)
	}
	for _, a := range s.allowances() {
		if a.m.Credit > HistoryCap(a.size)*byteTicks {
			return bad("history credit exceeds its cap")
		}
	}
	for _, r := range []struct {
		ring  RingState
		bound uint32
	}{{s.Ended, MaxEndedCandidates}, {s.Loose, MaxLooseEvidence}} {
		if r.ring.Count > r.bound || uint64(r.ring.Count) > r.ring.Last {
			return bad("ring holds more entries than its bound or its positions")
		}
	}
	return storageStateRecord{
		V: storageStateVersion, GeneralCredit: s.General.Credit, GeneralUsed: s.General.Used,
		ReservedCredit: s.Reserved.Credit, ReservedUsed: s.Reserved.Used, Recovery: s.Recovery,
		EndedCount: s.Ended.Count, EndedLast: s.Ended.Last, LooseCount: s.Loose.Count, LooseLast: s.Loose.Last,
	}, nil
}

// Validate checks the state's invariants.
func (s StorageState) Validate() error {
	_, err := s.record()
	return err
}

func (s StorageState) MarshalBinary() ([]byte, error) {
	rec, err := s.record()
	if err != nil {
		return nil, err
	}
	return sealRecord(rec)
}

// UnmarshalStorageState decodes a stored storage state and checks its
// invariants.
func UnmarshalStorageState(data []byte) (StorageState, error) {
	var rec storageStateRecord
	if err := openRecord(data, &rec); err != nil {
		return StorageState{}, err
	}
	s := StorageState{
		General:  HistoryMeter{Credit: rec.GeneralCredit, Used: rec.GeneralUsed},
		Reserved: HistoryMeter{Credit: rec.ReservedCredit, Used: rec.ReservedUsed},
		Recovery: rec.Recovery,
		Ended:    RingState{Count: rec.EndedCount, Last: rec.EndedLast},
		Loose:    RingState{Count: rec.LooseCount, Last: rec.LooseLast},
	}
	if again, err := s.record(); rec.V != storageStateVersion || err != nil || again != rec {
		return StorageState{}, ErrCorruptRecord
	}
	return s, nil
}
