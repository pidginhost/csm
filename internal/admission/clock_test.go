package admission

import (
	"bytes"
	"crypto/sha256"
	"testing"
	"time"
)

const (
	bootA = "0f5e3c2a-1b4d-4e6f-8a9b-0c1d2e3f4a5b"
	bootB = "7a6b5c4d-3e2f-4a1b-9c8d-7e6f5a4b3c2d"
)

func reading(wall time.Time, boot string, since time.Duration) ClockReading {
	return ClockReading{Wall: wall, BootID: boot, SinceBoot: since}
}

func advance(t *testing.T, c Clock, r ClockReading) (Clock, ClockTick) {
	t.Helper()
	next, tick, err := c.Advance(r)
	if err != nil {
		t.Fatalf("Advance: %v", err)
	}
	return next, tick
}

// Each case starts from one reading at t0 on boot A with an hour since boot.
func TestClockAdvance(t *testing.T) {
	start, _ := advance(t, Clock{}, reading(t0, bootA, time.Hour))
	for _, c := range []struct {
		name     string
		r        ClockReading
		now      time.Time
		elapsed  time.Duration
		degraded bool
	}{
		{"steady", reading(t0.Add(10*time.Second), bootA, time.Hour+10*time.Second), t0.Add(10 * time.Second), 10 * time.Second, false},
		{"drift at the limit", reading(t0.Add(11*time.Second), bootA, time.Hour+10*time.Second), t0.Add(11 * time.Second), 10 * time.Second, false},
		{"forward step", reading(t0.Add(time.Hour), bootA, time.Hour+10*time.Second), t0.Add(time.Hour), 10 * time.Second, true},
		{"wall lags elapsed", reading(t0.Add(2*time.Second), bootA, time.Hour+10*time.Second), t0.Add(2 * time.Second), 10 * time.Second, true},
		{"rollback", reading(t0.Add(-time.Hour), bootA, time.Hour+10*time.Second), t0, 10 * time.Second, true},
		{"elapsed runs backward", reading(t0.Add(time.Second), bootA, time.Minute), t0.Add(time.Second), 0, true},
		{"reboot forward", reading(t0.Add(5*time.Minute), bootB, 30*time.Second), t0.Add(5 * time.Minute), 0, false},
		{"reboot behind", reading(t0.Add(-time.Minute), bootB, 30*time.Second), t0, 0, true},
	} {
		next, tick := advance(t, start, c.r)
		if !tick.Now.Equal(c.now) || tick.Elapsed != c.elapsed || tick.Degraded != c.degraded {
			t.Errorf("%s: tick = %+v, want now %v elapsed %v degraded %v", c.name, tick, c.now, c.elapsed, c.degraded)
		}
		if !next.Now().Equal(c.now) {
			t.Errorf("%s: clock high-water %v, want %v", c.name, next.Now(), c.now)
		}
		if !start.Now().Equal(t0) {
			t.Fatalf("%s: Advance changed its receiver", c.name)
		}
	}
	if _, tick := advance(t, start, reading(t0.Add(11*time.Second+time.Nanosecond), bootA, time.Hour+10*time.Second)); !tick.Degraded {
		t.Error("drift just past the limit is not degraded")
	}
}

// After a rollback the clock stays degraded until wall time catches up
// with the high-water mark, and never reports an earlier Now.
func TestClockRollbackHoldsUntilCaughtUp(t *testing.T) {
	c, _ := advance(t, Clock{}, reading(t0, bootA, time.Hour))
	c, tick := advance(t, c, reading(t0.Add(-10*time.Second), bootA, time.Hour+time.Second))
	if !tick.Degraded || !tick.Now.Equal(t0) {
		t.Fatalf("rollback tick = %+v", tick)
	}
	c, tick = advance(t, c, reading(t0.Add(-5*time.Second), bootA, time.Hour+6*time.Second))
	if !tick.Degraded || !tick.Now.Equal(t0) {
		t.Fatalf("still behind: tick = %+v", tick)
	}
	_, tick = advance(t, c, reading(t0.Add(time.Second), bootA, time.Hour+12*time.Second))
	if tick.Degraded || !tick.Now.Equal(t0.Add(time.Second)) {
		t.Fatalf("caught up: tick = %+v", tick)
	}
}

func TestClockRefusesBadReadings(t *testing.T) {
	for name, r := range map[string]ClockReading{
		"zero wall":        reading(time.Time{}, bootA, time.Second),
		"out of range":     reading(time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC), bootA, time.Second),
		"upper boot ID":    reading(t0, "0F5E3C2A-1B4D-4E6F-8A9B-0C1D2E3F4A5B", time.Second),
		"short boot ID":    reading(t0, "0f5e3c2a", time.Second),
		"negative uptime":  reading(t0, bootA, -time.Second),
		"misplaced dashes": reading(t0, "0f5e3c2a1-b4d-4e6f-8a9b-0c1d2e3f4a5b", time.Second),
	} {
		if _, _, err := (Clock{}).Advance(r); refusalReason(err) != ReasonInvalid {
			t.Errorf("%s: err = %v, want an invalid refusal", name, err)
		}
	}
}

// refusalReason is the refusal reason of err, or zero.
func refusalReason(err error) Reason {
	r, _ := ReasonOf(err)
	return r
}

func TestClockRoundTripsAndRefusesTampering(t *testing.T) {
	if _, err := (Clock{}).MarshalBinary(); err == nil {
		t.Fatal("an uninitialized clock encoded")
	}
	c, _ := advance(t, Clock{}, reading(t0, bootA, time.Hour))
	c, _ = advance(t, c, reading(t0.Add(-time.Minute), bootA, time.Hour+time.Second))
	data, err := c.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	back, err := UnmarshalClock(data)
	if err != nil || back != c {
		t.Fatalf("round trip: %+v %v, want %+v", back, err, c)
	}
	body := data[:len(data)-8]
	for name, tampered := range map[string][]byte{
		"flipped byte": func() []byte { d := bytes.Clone(data); d[3] ^= 1; return d }(),
		"truncated":    data[:5],
		"unknown field": func() []byte {
			b := bytes.Replace(body, []byte(`{"v":1,`), []byte(`{"v":1,"x":1,`), 1)
			return resealForTest(b)
		}(),
		"non-canonical": resealForTest(bytes.Replace(body, []byte(`{"v":1,`), []byte(`{ "v":1,`), 1)),
		"version 2":     resealForTest(bytes.Replace(body, []byte(`{"v":1,`), []byte(`{"v":2,`), 1)),
		"high-water behind checkpoint": func() []byte {
			bad := c
			bad.rec.HighWater = bad.rec.CheckWall - 1
			d, _ := sealRecord(bad.rec)
			return d
		}(),
	} {
		if _, err := UnmarshalClock(tampered); err != ErrCorruptRecord {
			t.Errorf("%s: err = %v, want ErrCorruptRecord", name, err)
		}
	}
}

// resealForTest recomputes the checksum over a hand-edited body, so a test
// reaches the decoding and invariant checks behind it.
func resealForTest(body []byte) []byte {
	sum := sha256.Sum256(body)
	return append(bytes.Clone(body), sum[:8]...)
}

func TestClockElapsedCheckpointNeverRegresses(t *testing.T) {
	c, _ := advance(t, Clock{}, reading(t0, bootA, time.Hour))
	c, tick := advance(t, c, reading(t0.Add(time.Second), bootA, time.Minute))
	if tick.Elapsed != 0 || !tick.Degraded {
		t.Fatalf("regression: %+v", tick)
	}
	data, err := c.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	c, err = UnmarshalClock(data)
	if err != nil {
		t.Fatal(err)
	}
	_, tick = advance(t, c, reading(t0.Add(2*time.Second), bootA, time.Hour+2*time.Second))
	if tick.Elapsed != 2*time.Second {
		t.Fatalf("credited time twice: %+v", tick)
	}
}

func TestClockRepresentableBoundaries(t *testing.T) {
	for _, wall := range []time.Time{time.Unix(0, 0), {}} {
		if _, _, err := (Clock{}).Advance(reading(wall, bootA, 0)); refusalReason(err) != ReasonInvalid {
			t.Fatalf("reserved zero timestamp accepted: %v", err)
		}
	}
	early := time.Unix(0, -1<<63).UTC()
	late := time.Unix(0, 1<<63-1).UTC()
	c, _ := advance(t, Clock{}, reading(early, bootA, 0))
	_, tick := advance(t, c, reading(late, bootA, 0))
	if !tick.Degraded || !tick.Now.Equal(late) {
		t.Fatalf("forward overflow: %+v", tick)
	}
	c, _ = advance(t, Clock{}, reading(late, bootA, 0))
	_, tick = advance(t, c, reading(early, bootA, 0))
	if !tick.Degraded || !tick.Now.Equal(late) {
		t.Fatalf("backward overflow: %+v", tick)
	}
	zone := time.FixedZone("fixture", 5*60*60)
	c, _ = advance(t, Clock{}, reading(t0, bootA, time.Hour))
	_, tick = advance(t, c, reading(t0.In(zone), bootA, time.Hour))
	if tick.Degraded || tick.Elapsed != 0 || !tick.Now.Equal(t0) {
		t.Fatalf("timezone changed time: %+v", tick)
	}
	if _, _, err := c.Advance(reading(t0, "", 0)); refusalReason(err) != ReasonInvalid {
		t.Fatalf("missing boot identity accepted: %v", err)
	}
}
