package admission

import "time"

// MaxCeiling bounds the hourly ceiling the ledger accepts. Every charge
// retained in the window is one stored record, so it also bounds them.
const MaxCeiling = 20000

// CeilingWindow is the rolling window the ceiling counts charges over.
const CeilingWindow = time.Hour

// CeilingLanes splits the hourly ceiling L into the general allowance
// G = L-R and the reserved allowance R = ceil(L/5), which only direct
// compromise and independently corroborated work may spend (spec 5.6). For
// L=1 only the reserved lane exists.
func CeilingLanes(limit uint32) (general, reserved uint32) {
	reserved = limit / 5
	if limit%5 != 0 {
		reserved++
	}
	return limit - reserved, reserved
}

// BucketCap is the most credit a lane of size units per hour may save: ten
// minutes of its rate, and at least one unit so a small lane can run. An
// empty lane never runs.
func BucketCap(size uint32) uint32 {
	if size == 0 {
		return 0
	}
	return max(1, size/6)
}

// CeilingCost is what one attempt of kind k charges the ceiling. Each new
// address, prefix, promotion or service tuple costs one unit. Challenge
// work has its own bound (spec 5.12) and is never charged: it cannot
// create a block.
func (k Kind) CeilingCost() uint32 {
	if k == KindChallenge {
		return 0
	}
	return 1
}

const ceilingStateVersion = 1

// unitTicks is one unit of credit. A lane of S units per hour gains S ticks
// per nanosecond of elapsed time, so credit accrues exactly, without
// rounding, and an hour earns S units.
const unitTicks = uint64(time.Hour)

// Meter is one of the ceiling's two allowances.
type Meter struct {
	// Credit is the saved pacing credit in ticks.
	Credit uint64
	// Used is the units charged inside the rolling window.
	Used uint32
}

// Units is the whole units of saved credit.
func (m Meter) Units() uint32 { return uint32(min(m.Credit/unitTicks, MaxCeiling)) }

// CeilingState is the ledger's record of the emergency ceiling (spec 5.6):
// the effective limit, each lane's token bucket and its usage inside the
// rolling window. The zero value is an upgraded ledger's first state.
type CeilingState struct {
	// Limit is the effective hourly ceiling L; zero until the engine sets
	// one, and nothing is charged before it does.
	Limit uint32
	// Fill makes the first limit fill each bucket to its cap. A new ledger
	// starts with it; an upgraded one starts without credit, since its
	// recent spend is unknown.
	Fill bool
	// Elapsed is the admission time elapsed within boots since metering
	// began. Downtime between boots is never credited.
	Elapsed time.Duration
	// General and Reserved are the two allowances. The direct and
	// corroborated lanes share the reserved one.
	General, Reserved Meter
}

type allowance struct {
	m    *Meter
	size uint32
}

// allowances pairs each meter with its lane size under the current limit.
func (s *CeilingState) allowances() [2]allowance {
	g, r := CeilingLanes(s.Limit)
	return [2]allowance{{&s.General, g}, {&s.Reserved, r}}
}

// meter is the allowance lane l spends: the direct and corroborated lanes
// share the reserved one.
func (s *CeilingState) meter(l Lane) allowance {
	if l == LaneGeneral {
		return s.allowances()[0]
	}
	return s.allowances()[1]
}

func room(size, used uint32) uint32 {
	if used >= size {
		return 0
	}
	return size - used
}

// Budget is the units lane l can charge now: its saved credit, bounded by
// what its own allowance and the whole ceiling leave in the window.
func (s CeilingState) Budget(l Lane) uint32 {
	if !l.Valid() {
		return 0
	}
	a := s.meter(l)
	return min(a.m.Units(), room(a.size, a.m.Used), room(s.Limit, s.General.Used+s.Reserved.Used))
}

// SetLimit applies a new effective limit. The first limit of a new ledger
// fills each bucket to its cap; every later one clips saved credit to the
// new caps and never tops it up, so no restart or reload manufactures
// credit. Charges keep their lanes: a lane whose retained usage exceeds a
// reduced allowance waits for them to age out.
func (s CeilingState) SetLimit(limit uint32) (CeilingState, error) {
	if limit == 0 || limit > MaxCeiling {
		return s, refuse(ReasonInvalid, "ceiling is out of range")
	}
	s.Limit = limit
	for _, a := range s.allowances() {
		full := uint64(BucketCap(a.size)) * unitTicks
		if s.Fill || a.m.Credit > full {
			a.m.Credit = full
		}
	}
	s.Fill = false
	return s, nil
}

// Advance credits elapsed admission time: it accumulates Elapsed and
// refills each running lane at its hourly rate, up to its cap. Exhausting
// the elapsed representation refuses the whole update, preserving charge ages.
func (s CeilingState) Advance(elapsed time.Duration) (CeilingState, error) {
	if elapsed <= 0 {
		return s, nil
	}
	if elapsed > time.Duration(1<<63-1)-s.Elapsed {
		return s, refuse(ReasonEngineUnavailable, "ceiling elapsed time is exhausted")
	}
	s.Elapsed += elapsed
	e := uint64(elapsed)
	for _, a := range s.allowances() {
		full := uint64(BucketCap(a.size)) * unitTicks
		if a.m.Credit >= full {
			continue
		}
		rate := uint64(a.size)
		// Compare elapsed time with the time left to fill before
		// multiplying, so a long gap saturates instead of overflowing.
		if need := full - a.m.Credit; e >= (need+rate-1)/rate {
			a.m.Credit = full
		} else {
			a.m.Credit += rate * e
		}
	}
	return s, nil
}

// Charge spends cost units of lane l's budget. A refusal changes nothing.
func (s CeilingState) Charge(l Lane, cost uint32) (CeilingState, error) {
	switch {
	case !l.Valid() || cost == 0 || cost > MaxMemberCost:
		return s, refuse(ReasonInvalid, "charge has no lane or an invalid cost")
	case s.Limit == 0:
		return s, refuse(ReasonEngineUnavailable, "ceiling is not set")
	case cost > s.Budget(l):
		return s, refuse(ReasonCeiling, "lane has no ceiling budget for the charge")
	}
	a := s.meter(l)
	a.m.Credit -= uint64(cost) * unitTicks
	a.m.Used += cost
	return s, nil
}

// Release returns a charge's units to the window once it has aged out. It
// never refunds credit.
func (s CeilingState) Release(l Lane, cost uint32) (CeilingState, error) {
	if !l.Valid() {
		return s, ErrCorruptRecord
	}
	a := s.meter(l)
	if a.m.Used < cost {
		return s, ErrCorruptRecord
	}
	a.m.Used -= cost
	return s, nil
}

type ceilingStateRecord struct {
	V              uint8  `json:"v"`
	Limit          uint32 `json:"limit,omitempty"`
	Fill           bool   `json:"fill,omitempty"`
	Elapsed        int64  `json:"elapsed,omitempty"`
	GeneralCredit  uint64 `json:"general_credit,omitempty"`
	GeneralUsed    uint32 `json:"general_used,omitempty"`
	ReservedCredit uint64 `json:"reserved_credit,omitempty"`
	ReservedUsed   uint32 `json:"reserved_used,omitempty"`
}

func (s CeilingState) record() (ceilingStateRecord, error) {
	bad := func(detail string) (ceilingStateRecord, error) {
		return ceilingStateRecord{}, refuse(ReasonInvalid, detail)
	}
	g, r := CeilingLanes(s.Limit)
	switch {
	case s.Limit > MaxCeiling:
		return bad("ceiling is out of range")
	case s.Fill && s.Limit != 0:
		return bad("a set ceiling cannot still be waiting to fill")
	case s.Elapsed < 0:
		return bad("ceiling elapsed time is negative")
	case s.General.Credit > uint64(BucketCap(g))*unitTicks, s.Reserved.Credit > uint64(BucketCap(r))*unitTicks:
		return bad("ceiling credit exceeds its cap")
	case uint64(s.General.Used)+uint64(s.Reserved.Used) > MaxCeiling:
		return bad("ceiling usage exceeds any ceiling")
	}
	return ceilingStateRecord{
		V: ceilingStateVersion, Limit: s.Limit, Fill: s.Fill, Elapsed: int64(s.Elapsed),
		GeneralCredit: s.General.Credit, GeneralUsed: s.General.Used,
		ReservedCredit: s.Reserved.Credit, ReservedUsed: s.Reserved.Used,
	}, nil
}

// Validate checks the state's invariants.
func (s CeilingState) Validate() error {
	_, err := s.record()
	return err
}

func (s CeilingState) MarshalBinary() ([]byte, error) {
	rec, err := s.record()
	if err != nil {
		return nil, err
	}
	return sealRecord(rec)
}

// UnmarshalCeilingState decodes a stored ceiling state and checks its
// invariants.
func UnmarshalCeilingState(data []byte) (CeilingState, error) {
	var rec ceilingStateRecord
	if err := openRecord(data, &rec); err != nil {
		return CeilingState{}, err
	}
	s := CeilingState{
		Limit: rec.Limit, Fill: rec.Fill, Elapsed: time.Duration(rec.Elapsed),
		General:  Meter{Credit: rec.GeneralCredit, Used: rec.GeneralUsed},
		Reserved: Meter{Credit: rec.ReservedCredit, Used: rec.ReservedUsed},
	}
	if again, err := s.record(); rec.V != ceilingStateVersion || err != nil || again != rec {
		return CeilingState{}, ErrCorruptRecord
	}
	return s, nil
}
