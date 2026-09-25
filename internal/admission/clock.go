package admission

import "time"

// maxClockSkew is how far wall time may drift from elapsed time between two
// readings before the clock reports degraded coverage.
const maxClockSkew = time.Second

const clockVersion = 1

// ClockReading is one sample of the host clocks: wall time, the kernel's
// boot identity and the time elapsed since that boot.
type ClockReading struct {
	Wall      time.Time
	BootID    string
	SinceBoot time.Duration
}

// ClockTick is what one reading means for admission.
type ClockTick struct {
	// Now is the admission time: the persisted high-water mark. A wall
	// clock that steps back never lowers it, so rollback cannot release
	// capacity or make old evidence fresh.
	Now time.Time
	// Elapsed is the time elapsed since the previous reading within the
	// same boot. A new boot grants none: downtime is never credited.
	Elapsed time.Duration
	// Degraded is true while the wall clock is behind the high-water mark,
	// disagrees with elapsed time by more than maxClockSkew, or elapsed
	// time ran backward. Wall time alone proves nothing new while it holds.
	Degraded bool
}

type clockRecord struct {
	V          uint8  `json:"v"`
	HighWater  int64  `json:"high_water"`
	BootID     string `json:"boot_id"`
	CheckWall  int64  `json:"check_wall"`
	CheckSince int64  `json:"check_since"`
}

// Clock is the persisted admission clock (spec 5.4). It is a value: Advance
// returns the next clock, so a failed transaction leaves the stored one.
// The zero value has seen no reading.
type Clock struct {
	rec clockRecord
}

func (c Clock) Initialized() bool { return c.rec.V != 0 }

// Now is the high-water mark; zero before the first reading.
func (c Clock) Now() time.Time { return fromNano(c.rec.HighWater) }

func validBootID(id string) bool {
	if len(id) != 36 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				return false
			}
		}
	}
	return true
}

// Advance folds r into the clock. Within one boot, elapsed time is the
// truth and a wall step beyond maxClockSkew is degraded coverage. Across
// boots nothing elapsed is credited. The high-water mark only moves forward.
func (c Clock) Advance(r ClockReading) (Clock, ClockTick, error) {
	wall, ok := unixNano(r.Wall)
	switch {
	case !ok:
		return c, ClockTick{}, refuse(ReasonInvalid, "clock reading has no representable wall time")
	case !validBootID(r.BootID):
		return c, ClockTick{}, refuse(ReasonInvalid, "clock reading has a malformed boot ID")
	case r.SinceBoot < 0:
		return c, ClockTick{}, refuse(ReasonInvalid, "clock reading has negative time since boot")
	}
	since := int64(r.SinceBoot)
	next := clockRecord{V: clockVersion, HighWater: c.rec.HighWater, BootID: r.BootID, CheckWall: wall, CheckSince: since}
	var tick ClockTick
	if c.Initialized() && r.BootID == c.rec.BootID {
		if since < c.rec.CheckSince {
			// Keep the elapsed checkpoint until it is reached again, so a
			// later reading cannot credit the same interval twice.
			next.CheckWall, next.CheckSince = c.rec.CheckWall, c.rec.CheckSince
			tick.Degraded = true
		} else {
			tick.Elapsed = time.Duration(since - c.rec.CheckSince)
			skew := r.Wall.Sub(fromNano(c.rec.CheckWall).Add(tick.Elapsed))
			if skew > maxClockSkew || skew < -maxClockSkew {
				tick.Degraded = true
			}
		}
	}
	switch {
	case !c.Initialized() || wall > next.HighWater:
		next.HighWater = wall
	case wall < next.HighWater:
		tick.Degraded = true
	}
	tick.Now = fromNano(next.HighWater)
	return Clock{rec: next}, tick, nil
}

// MarshalBinary encodes an initialized clock.
func (c Clock) MarshalBinary() ([]byte, error) {
	if !c.Initialized() {
		return nil, refuse(ReasonInvalid, "clock has seen no reading")
	}
	return sealRecord(c.rec)
}

// UnmarshalClock decodes a stored clock and checks its invariants.
func UnmarshalClock(data []byte) (Clock, error) {
	var rec clockRecord
	if err := openRecord(data, &rec); err != nil {
		return Clock{}, err
	}
	if rec.V != clockVersion || !validBootID(rec.BootID) || rec.CheckWall == 0 || rec.HighWater == 0 || rec.HighWater < rec.CheckWall || rec.CheckSince < 0 {
		return Clock{}, ErrCorruptRecord
	}
	return Clock{rec: rec}, nil
}
