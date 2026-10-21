package admission

import "time"

// LegacyHandover is what legacy blocking's state holds when the owner first
// executes: the current hour's count, and how many pending entries legacy
// would still retry. A pending entry names no observation, so admission
// cannot answer it (design C7).
type LegacyHandover struct {
	Spend   LegacySpend
	Pending int
}

const liveStartVersion = 1

// LiveStart is the ledger's record that its live start ran, at admission
// time At.
type LiveStart struct {
	At time.Time
}

type liveStartRecord struct {
	V  uint8 `json:"v"`
	At int64 `json:"at"`
}

func (s LiveStart) MarshalBinary() ([]byte, error) {
	at, ok := unixNano(s.At)
	if !ok {
		return nil, refuse(ReasonInvalid, "live start has no time")
	}
	return sealRecord(liveStartRecord{V: liveStartVersion, At: at})
}

// UnmarshalLiveStart decodes a stored live start record.
func UnmarshalLiveStart(data []byte) (LiveStart, error) {
	var rec liveStartRecord
	if err := openRecord(data, &rec); err != nil {
		return LiveStart{}, err
	}
	if rec.V != liveStartVersion || rec.At == 0 {
		return LiveStart{}, ErrCorruptRecord
	}
	return LiveStart{At: fromNano(rec.At)}, nil
}

// CarryLegacy charges, at the live start, the legacy hour's units that the
// ledger's retained charges in that hour do not already count (design C7):
// observe previews and legacy blocking describe the same responses, so the
// hour counts the greater of the two, never their sum. The extra units are
// dated at the hour's end, as an import's are, on the general lane up to
// its room and the rest on the reserved allowance, and spend saved credit
// without a budget check: legacy blocking already spent them. Usage never
// passes MaxCeiling. An unreadable legacy counter keeps no saved credit, as
// a failed first import grants none.
func (s CeilingState) CarryLegacy(spend LegacySpend, retained uint32) (CeilingState, []Charge, error) {
	if s.Limit == 0 {
		return s, nil, refuse(ReasonEngineUnavailable, "ceiling is not set")
	}
	if spend.Unknown {
		s.General.Credit, s.Reserved.Credit = 0, 0
		return s, nil, nil
	}
	units := min(spend.Units, MaxCeiling)
	if units == 0 {
		return s, nil, nil
	}
	if at, ok := unixNano(spend.At); !ok || at <= 0 {
		return s, nil, refuse(ReasonInvalid, "legacy spend names no hour")
	}
	used := s.General.Used + s.Reserved.Used
	if units <= retained || used >= MaxCeiling {
		return s, nil, nil
	}
	extra := min(units-retained, MaxCeiling-used)
	g, _ := CeilingLanes(s.Limit)
	general := min(extra, room(g, s.General.Used))
	var charges []Charge
	var seq uint32
	for _, part := range []struct {
		lane  Lane
		m     *Meter
		units uint32
	}{{LaneGeneral, &s.General, general}, {LaneDirect, &s.Reserved, extra - general}} {
		part.m.Used += part.units
		part.m.Credit -= min(part.m.Credit, uint64(part.units)*unitTicks)
		for part.units > 0 {
			cost := min(part.units, MaxMemberCost)
			seq++
			charges = append(charges, Charge{At: spend.At, Action: LiveStartActionID(spend.At, seq), Lane: part.lane, Cost: cost, Elapsed: s.Elapsed})
			part.units -= cost
		}
	}
	return s, charges, nil
}
