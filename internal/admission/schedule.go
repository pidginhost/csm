package admission

import (
	"fmt"
	"sort"
	"time"
)

// MaxMemberCost bounds one candidate's cost in block units: one member
// spans at most 64 set elements (spec 5.5).
const MaxMemberCost = 64

// MaxBatchMembers bounds the candidates one schedule picks (spec 5.5).
const MaxBatchMembers = 64

const scheduleStateVersion = 1

// Lane is the service a pick draws on. Values are persisted: append, never
// renumber.
type Lane uint8

const (
	LaneGeneral Lane = iota + 1
	// LaneDirect is the reserved lane's turn for direct compromise evidence.
	LaneDirect
	// LaneCorroborated is the reserved lane's turn for independently
	// corroborated evidence.
	LaneCorroborated
	laneEnd
)

var laneNames = [...]string{"", "general", "direct", "corroborated"}

func (l Lane) Valid() bool { return l >= LaneGeneral && l < laneEnd }

func (l Lane) String() string {
	if l.Valid() {
		return laneNames[l]
	}
	return fmt.Sprintf("lane(%d)", uint8(l))
}

// Rings of the scheduler: one per general class and one per reserved
// sub-lane. Each rotates its scopes on its own.
const (
	ringC1 = iota
	ringC2
	ringC3
	ringDirect
	ringCorroborated
	ringCount
)

// patternSlots is the length of both 4:2:1 quantum patterns.
const patternSlots uint8 = 7

// classPattern is the repeating C3:C2:C1 quantum schedule of 4:2:1.
var classPattern = [patternSlots]Class{ClassC3, ClassC3, ClassC3, ClassC3, ClassC2, ClassC2, ClassC1}

// severityPattern is the Critical:High:Warning quantum schedule of 4:2:1
// inside a scope.
var severityPattern = [patternSlots]Severity{SeverityCritical, SeverityCritical, SeverityCritical, SeverityCritical, SeverityHigh, SeverityHigh, SeverityWarning}

// ScheduleItem is a queued candidate as the scheduler sees it.
type ScheduleItem struct {
	ID           CandidateID
	Scope        string
	Tier         Tier
	Direct       bool
	Corroborated bool
	Queued       time.Time
	// Cost is the candidate's size in block units, 1 to MaxMemberCost.
	Cost uint32
	// Ready is false while a proven failure's retry wait lasts. A waiting
	// candidate is never picked, but its scope keeps its deficit.
	Ready bool
}

// ScheduleLimits bound one schedule.
type ScheduleLimits struct {
	// General and Reserved are the block units each lane may serve.
	General  uint32
	Reserved uint32
	// Members bounds the picks, 1 to MaxBatchMembers.
	Members int
}

// Pick is one candidate chosen for service and the lane it draws on.
type Pick struct {
	ID   CandidateID
	Lane Lane
	Cost uint32
}

// ScopeTurn is a scope's persisted place in one ring.
type ScopeTurn struct {
	// Severity is the scope's position in the severity pattern.
	Severity uint8
	// Deficit is the block units the scope has earned toward a member that
	// costs more than one turn; it never exceeds MaxMemberCost.
	Deficit uint32
}

// Ring is the persisted rotation of one ring: the scope served last and
// the turns of scopes that still have work in it.
type Ring struct {
	Last   string
	Scopes map[string]ScopeTurn
}

// ScheduleState is the persisted scheduler position. The zero value is a
// fresh scheduler.
type ScheduleState struct {
	// ClassSlot is the general lane's position in the class pattern.
	ClassSlot uint8
	// NextCorroborated: the reserved lane serves corroboration next when
	// both of its turns have work.
	NextCorroborated bool
	Rings            [ringCount]Ring
}

func (s ScheduleState) clone() ScheduleState {
	out := s
	for i := range out.Rings {
		scopes := make(map[string]ScopeTurn, len(s.Rings[i].Scopes))
		for k, v := range s.Rings[i].Scopes {
			scopes[k] = v
		}
		out.Rings[i].Scopes = scopes
	}
	return out
}

func validateItems(items []ScheduleItem) error {
	seen := make(map[CandidateID]bool, len(items))
	for _, it := range items {
		switch {
		case seen[it.ID] || it.Scope == "":
			return refuse(ReasonInvalid, "schedule item is repeated or has no scope")
		case !it.Tier.Valid() || it.Cost == 0 || it.Cost > MaxMemberCost:
			return refuse(ReasonInvalid, "schedule item has an invalid tier or cost")
		case it.Direct && it.Corroborated, (it.Direct || it.Corroborated) && it.Tier.Class != ClassC3:
			return refuse(ReasonInvalid, "schedule item has an impossible reserved turn")
		}
		seen[it.ID] = true
	}
	return nil
}

// before orders candidates of one severity: oldest first, then by ID.
func before(a, b *ScheduleItem) bool {
	if !a.Queued.Equal(b.Queued) {
		return a.Queued.Before(b.Queued)
	}
	return a.ID < b.ID
}

type ringMembers struct {
	// ready holds each scope's ready members by severity.
	ready map[string]map[Severity][]*ScheduleItem
}

func memberOf(r int, it *ScheduleItem) bool {
	switch r {
	case ringDirect:
		return it.Direct
	case ringCorroborated:
		return it.Corroborated
	}
	return int(it.Tier.Class)-1 == r
}

func buildRings(items []ScheduleItem) [ringCount]ringMembers {
	var rings [ringCount]ringMembers
	for r := range rings {
		rings[r] = ringMembers{ready: map[string]map[Severity][]*ScheduleItem{}}
	}
	for i := range items {
		it := &items[i]
		for r := range rings {
			if !memberOf(r, it) || !it.Ready {
				continue
			}
			bySeverity := rings[r].ready[it.Scope]
			if bySeverity == nil {
				bySeverity = map[Severity][]*ScheduleItem{}
				rings[r].ready[it.Scope] = bySeverity
			}
			bySeverity[it.Tier.Severity] = append(bySeverity[it.Tier.Severity], it)
		}
	}
	for r := range rings {
		for _, bySeverity := range rings[r].ready {
			for _, list := range bySeverity {
				sort.Slice(list, func(i, j int) bool { return before(list[i], list[j]) })
			}
		}
	}
	return rings
}

type scheduler struct {
	st     ScheduleState
	rings  [ringCount]ringMembers
	picked map[CandidateID]bool
}

// head is the member a scope serves next in ring r: the first severity in
// the pattern from the scope's position that has a ready member, and its
// oldest member. slot is that severity's pattern position.
func (s *scheduler) head(r int, scope string) (*ScheduleItem, uint8) {
	bySeverity := s.rings[r].ready[scope]
	start := s.st.Rings[r].Scopes[scope].Severity
	for k := uint8(0); k < patternSlots; k++ {
		slot := (start + k) % patternSlots
		for _, it := range bySeverity[severityPattern[slot]] {
			if !s.picked[it.ID] {
				return it, slot
			}
		}
	}
	return nil, 0
}

// serve takes one turn of ring r within budget. It rotates the scopes that
// have a ready member, from the one after the last served; each visit adds
// one block unit to the scope's deficit, capped at MaxMemberCost, and the
// first scope whose deficit and the budget both cover its head is served.
// A head above the full budget can still earn bounded credit while other
// scopes run. A head that fits the full batch budget but not its remainder
// holds its turn for the next batch:
// lending that turn could leave it with too little budget on every call.
// The boolean reports this budget block; otherwise nil means no head fits.
func (s *scheduler) serve(r int, budget, fullBudget uint32) (*ScheduleItem, bool) {
	var scopes []string
	fits := false
	for scope := range s.rings[r].ready {
		if it, _ := s.head(r, scope); it != nil {
			scopes = append(scopes, scope)
			fits = fits || it.Cost <= fullBudget
		}
	}
	if !fits {
		return nil, false
	}
	sort.Strings(scopes)
	ring := &s.st.Rings[r]
	start := sort.SearchStrings(scopes, ring.Last)
	if start < len(scopes) && scopes[start] == ring.Last {
		start++
	}
	// A fitting head is served or held for a fresh budget within
	// MaxMemberCost rotations, since each visit earns a unit.
	for visit := 0; ; visit++ {
		scope := scopes[(start+visit)%len(scopes)]
		it, slot := s.head(r, scope)
		if it.Cost > budget && it.Cost <= fullBudget {
			return nil, true
		}
		turn := ring.Scopes[scope]
		if turn.Deficit < MaxMemberCost {
			turn.Deficit++
		}
		ring.Last = scope
		if it.Cost <= turn.Deficit && it.Cost <= budget {
			turn.Deficit -= it.Cost
			turn.Severity = (slot + 1) % patternSlots
			ring.Scopes[scope] = turn
			return it, false
		}
		ring.Scopes[scope] = turn
	}
}

// Schedule picks up to lim.Members candidates, reserved lane first. The
// reserved lane alternates its direct and corroborated turns while both
// have work; the general lane follows the C3:C2:C1 pattern, lending an
// empty class's turn to the next class with work. Inside a ring, verified
// scopes rotate, a scope serves Critical:High:Warning 4:2:1, and a severity
// serves its oldest candidate. No candidate is picked twice. The returned
// state keeps turns only for scopes that still have work in a ring.
func Schedule(items []ScheduleItem, st ScheduleState, lim ScheduleLimits) ([]Pick, ScheduleState, error) {
	if lim.Members < 1 || lim.Members > MaxBatchMembers {
		return nil, st, refuse(ReasonInvalid, "schedule member bound is out of range")
	}
	if err := validateItems(items); err != nil {
		return nil, st, err
	}
	if err := st.validate(); err != nil {
		return nil, st, err
	}
	own := append([]ScheduleItem(nil), items...)
	s := &scheduler{st: st.clone(), rings: buildRings(own), picked: map[CandidateID]bool{}}
	var picks []Pick
	take := func(it *ScheduleItem, lane Lane) {
		s.picked[it.ID] = true
		picks = append(picks, Pick{ID: it.ID, Lane: lane, Cost: it.Cost})
	}
	budget := lim.Reserved
reserved:
	for budget > 0 && len(picks) < lim.Members {
		order := []int{ringDirect, ringCorroborated}
		if s.st.NextCorroborated {
			order = []int{ringCorroborated, ringDirect}
		}
		served := false
		for _, r := range order {
			it, blocked := s.serve(r, budget, lim.Reserved)
			if blocked {
				s.st.NextCorroborated = r == ringCorroborated
				break reserved
			}
			if it != nil {
				budget -= it.Cost
				lane := LaneDirect
				if r == ringCorroborated {
					lane = LaneCorroborated
				}
				take(it, lane)
				s.st.NextCorroborated = r == ringDirect
				served = true
				break
			}
		}
		if !served {
			break
		}
	}
	budget = lim.General
general:
	for budget > 0 && len(picks) < lim.Members {
		served := false
		for k := uint8(0); k < patternSlots; k++ {
			slot := (s.st.ClassSlot + k) % patternSlots
			it, blocked := s.serve(int(classPattern[slot])-1, budget, lim.General)
			if blocked {
				s.st.ClassSlot = slot
				break general
			}
			if it != nil {
				budget -= it.Cost
				take(it, LaneGeneral)
				s.st.ClassSlot = (slot + 1) % patternSlots
				served = true
				break
			}
		}
		if !served {
			break
		}
	}
	// A scope keeps its turn only while it has work left in the ring; a
	// scope that emptied starts afresh, as in deficit round robin.
	var left [ringCount]map[string]bool
	for r := range left {
		left[r] = map[string]bool{}
	}
	for i := range own {
		for r := range left {
			if !s.picked[own[i].ID] && memberOf(r, &own[i]) {
				left[r][own[i].Scope] = true
			}
		}
	}
	for r := range s.st.Rings {
		for scope, turn := range s.st.Rings[r].Scopes {
			if !left[r][scope] || turn == (ScopeTurn{}) {
				delete(s.st.Rings[r].Scopes, scope)
			}
		}
	}
	return picks, s.st, nil
}

type scopeTurnRecord struct {
	Scope    string `json:"scope"`
	Severity uint8  `json:"severity,omitempty"`
	Deficit  uint32 `json:"deficit,omitempty"`
}

type ringRecord struct {
	Last   string            `json:"last,omitempty"`
	Scopes []scopeTurnRecord `json:"scopes"`
}

type scheduleStateRecord struct {
	V                uint8        `json:"v"`
	ClassSlot        uint8        `json:"class_slot,omitempty"`
	NextCorroborated bool         `json:"next_corroborated,omitempty"`
	Rings            []ringRecord `json:"rings"`
}

func (s ScheduleState) record() (scheduleStateRecord, error) {
	bad := func(detail string) (scheduleStateRecord, error) {
		return scheduleStateRecord{}, refuse(ReasonInvalid, detail)
	}
	if s.ClassSlot >= patternSlots {
		return bad("schedule class position is out of range")
	}
	rec := scheduleStateRecord{V: scheduleStateVersion, ClassSlot: s.ClassSlot, NextCorroborated: s.NextCorroborated, Rings: make([]ringRecord, ringCount)}
	for r, ring := range s.Rings {
		if !validCursor(ring.Last) || len(ring.Scopes) > QueueCapacity {
			return bad("schedule ring is malformed")
		}
		rows := make([]scopeTurnRecord, 0, len(ring.Scopes))
		for scope, turn := range ring.Scopes {
			if !boundedToken(scope, 128) || turn.Severity >= patternSlots || turn.Deficit > MaxMemberCost || turn == (ScopeTurn{}) {
				return bad("schedule scope turn is malformed")
			}
			rows = append(rows, scopeTurnRecord{Scope: scope, Severity: turn.Severity, Deficit: turn.Deficit})
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].Scope < rows[j].Scope })
		rec.Rings[r] = ringRecord{Last: ring.Last, Scopes: rows}
	}
	return rec, nil
}

func (s ScheduleState) validate() error {
	_, err := s.record()
	return err
}

func (s ScheduleState) MarshalBinary() ([]byte, error) {
	rec, err := s.record()
	if err != nil {
		return nil, err
	}
	return sealRecord(rec)
}

// UnmarshalScheduleState decodes a stored scheduler position.
func UnmarshalScheduleState(data []byte) (ScheduleState, error) {
	var rec scheduleStateRecord
	if err := openRecord(data, &rec); err != nil {
		return ScheduleState{}, err
	}
	if rec.V != scheduleStateVersion || len(rec.Rings) != ringCount {
		return ScheduleState{}, ErrCorruptRecord
	}
	s := ScheduleState{ClassSlot: rec.ClassSlot, NextCorroborated: rec.NextCorroborated}
	for r, ring := range rec.Rings {
		if ring.Scopes == nil {
			return ScheduleState{}, ErrCorruptRecord
		}
		s.Rings[r] = Ring{Last: ring.Last, Scopes: make(map[string]ScopeTurn, len(ring.Scopes))}
		for i, row := range ring.Scopes {
			if i > 0 && ring.Scopes[i-1].Scope >= row.Scope {
				return ScheduleState{}, ErrCorruptRecord
			}
			s.Rings[r].Scopes[row.Scope] = ScopeTurn{Severity: row.Severity, Deficit: row.Deficit}
		}
	}
	if s.validate() != nil {
		return ScheduleState{}, ErrCorruptRecord
	}
	return s, nil
}
