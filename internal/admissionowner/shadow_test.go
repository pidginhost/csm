package admissionowner

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
)

var shadowT0 = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

// freshCeiling is a new ledger's ceiling after its first limit.
func freshCeiling(t *testing.T, limit uint32) admission.CeilingState {
	t.Helper()
	c, err := admission.CeilingState{Fill: true}.SetLimit(limit)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func testShadow(t *testing.T, ceiling admission.CeilingState, charges []admission.Charge) *shadow {
	t.Helper()
	s, err := newShadow(strings.Repeat("ab", 16), shadowT0, resetStartup, ceiling, charges)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

var (
	generalOnly  = []admission.Lane{admission.LaneGeneral}
	directGen    = []admission.Lane{admission.LaneGeneral, admission.LaneDirect}
	room         = firewall.BlockAdmission{}
	shadowExpiry = shadowT0.Add(time.Hour)
)

// admitNow decides and commits one pick, returning its prediction.
func admitNow(t *testing.T, s *shadow, ip string, lanes []admission.Lane, now time.Time, adm firewall.BlockAdmission) prediction {
	t.Helper()
	p, change, err := s.admit(ip, admission.KindBlockIP, now.Add(time.Hour), lanes, now, adm)
	if err != nil {
		t.Fatal(err)
	}
	s.commit(p, change, now)
	return p
}

func tickBy(s *shadow, now time.Time, elapsed time.Duration) error {
	return s.advance(admission.ClockTick{Now: now, Elapsed: elapsed})
}

// The shadow starts from the real ceiling, spent credit and retained
// charges included: a forecast after live work is not a fresh ceiling.
func TestShadowStartsFromTheRealCeiling(t *testing.T) {
	real := freshCeiling(t, 10)
	real, err := real.Charge(admission.LaneGeneral, 1)
	if err != nil {
		t.Fatal(err)
	}
	charges := []admission.Charge{{At: shadowT0.Add(-time.Minute), Lane: admission.LaneGeneral, Cost: 1}}
	s := testShadow(t, real, charges)
	if p := admitNow(t, s, "203.0.113.1", generalOnly, shadowT0, room); p != predictCeiling {
		t.Fatalf("spent real credit = %s, want ceiling", p)
	}
	// G=8 refills a unit every 7.5 minutes of running time.
	if err = tickBy(s, shadowT0.Add(7*time.Minute+30*time.Second), 7*time.Minute+30*time.Second); err != nil {
		t.Fatal(err)
	}
	if p := admitNow(t, s, "203.0.113.1", generalOnly, shadowT0.Add(7*time.Minute+30*time.Second), room); p != predictCapacityAdmit {
		t.Fatalf("after refill = %s", p)
	}
	if real.General.Used != 1 || s.ceiling.General.Used != 2 || len(s.charges) != 2 {
		t.Fatalf("real %+v, shadow %+v, %d charges", real.General, s.ceiling.General, len(s.charges))
	}
	for _, bad := range []struct {
		ceiling admission.CeilingState
		charges []admission.Charge
	}{
		{admission.CeilingState{}, nil},
		{real, make([]admission.Charge, admission.MaxCeiling+1)},
	} {
		if _, err := newShadow(strings.Repeat("ab", 16), shadowT0, resetStartup, bad.ceiling, bad.charges); err == nil {
			t.Fatalf("seeded from %+v and %d charges", bad.ceiling, len(bad.charges))
		}
	}
}

// With L=5 (G=4, R=1) fresh pacing admits one general pick at once, not
// four. Fifteen minutes of running time earn each next one: picks at 0,
// 15, 30 and 45 minutes exhaust G, and another at 45 waits for the
// ceiling. Reserved-eligible work then draws on R, which general-only work
// never borrows.
func TestShadowPacesTheCeiling(t *testing.T) {
	s := testShadow(t, freshCeiling(t, 5), nil)
	if p := admitNow(t, s, "203.0.113.1", generalOnly, shadowT0, room); p != predictCapacityAdmit {
		t.Fatalf("first = %s", p)
	}
	if p := admitNow(t, s, "203.0.113.2", generalOnly, shadowT0, room); p != predictCeiling {
		t.Fatalf("second at once = %s, want ceiling", p)
	}
	at := shadowT0
	for i := 2; i <= 4; i++ {
		at = at.Add(15 * time.Minute)
		if err := tickBy(s, at, 15*time.Minute); err != nil {
			t.Fatal(err)
		}
		if p := admitNow(t, s, fmt.Sprintf("203.0.113.%d", i), generalOnly, at, room); p != predictCapacityAdmit {
			t.Fatalf("pick at %v = %s", at.Sub(shadowT0), p)
		}
	}
	if p := admitNow(t, s, "203.0.113.9", generalOnly, at, room); p != predictCeiling {
		t.Fatalf("fifth general pick = %s, want ceiling", p)
	}
	if p := admitNow(t, s, "203.0.113.10", directGen, at, room); p != predictCapacityAdmit {
		t.Fatalf("eligible pick = %s", p)
	}
	if last := s.charges[len(s.charges)-1]; last.Lane != admission.LaneDirect || s.ceiling.Reserved.Used != 1 || s.ceiling.General.Used != 4 {
		t.Fatalf("charged %+v; general %+v reserved %+v", last, s.ceiling.General, s.ceiling.Reserved)
	}
}

// With L=1 only the reserved lane exists.
func TestShadowReservedOnlyCeiling(t *testing.T) {
	s := testShadow(t, freshCeiling(t, 1), nil)
	if p := admitNow(t, s, "203.0.113.1", generalOnly, shadowT0, room); p != predictCeiling {
		t.Fatalf("general-only = %s", p)
	}
	reserved := []admission.Lane{admission.LaneCorroborated, admission.LaneGeneral}
	if p := admitNow(t, s, "203.0.113.2", reserved, shadowT0, room); p != predictCapacityAdmit || s.charges[0].Lane != admission.LaneCorroborated {
		t.Fatalf("corroborated = %s, charges %+v", p, s.charges)
	}
}

// Real occupancy 8 of 10: two distinct picks fit and the third finds the
// modelled set full, whatever their address families. A full set refuses
// before the ceiling is tried.
func TestShadowFillsTheTemporarySet(t *testing.T) {
	s := testShadow(t, freshCeiling(t, 2000), nil)
	adm := firewall.BlockAdmission{Temporary: 8, Limit: 10}
	for i, ip := range []string{"203.0.113.1", "2001:db8::1"} {
		if p := admitNow(t, s, ip, generalOnly, shadowT0, adm); p != predictCapacityAdmit {
			t.Fatalf("pick %d = %s", i, p)
		}
	}
	used := s.ceiling
	if p := admitNow(t, s, "203.0.113.3", generalOnly, shadowT0, adm); p != predictSetFull {
		t.Fatalf("third = %s, want set_full", p)
	}
	if s.ceiling != used || !s.full(adm) || len(s.entries) != 2 {
		t.Fatal("a full set charged the ceiling or took an entry")
	}
	// A real block of a shadow address counts once: as real occupancy.
	if s.full(firewall.BlockAdmission{Temporary: 9, Limit: 11, ShadowTemporary: 1}) {
		t.Fatal("an address held by a real and a shadow block counted twice")
	}
	// A real permanent block of a shadow address takes no temporary slot.
	if s.full(firewall.BlockAdmission{Temporary: 8, Limit: 10, ShadowPermanent: 1}) {
		t.Fatal("permanent coverage counted as temporary demand")
	}
}

// A shadow block that covers a repeat's lifetime answers it; a shorter one
// holds the address. A repeat never renews or extends the entry.
func TestShadowCoversRepeats(t *testing.T) {
	s := testShadow(t, freshCeiling(t, 2000), nil)
	if p := admitNow(t, s, "203.0.113.1", generalOnly, shadowT0, room); p != predictCapacityAdmit {
		t.Fatalf("first = %s", p)
	}
	entry := s.entries["203.0.113.1"]
	for _, tc := range []struct {
		expires time.Time
		want    prediction
	}{
		{shadowExpiry, predictExistingShadow},
		{shadowExpiry.Add(-time.Minute), predictExistingShadow},
		{shadowExpiry.Add(time.Nanosecond), predictPendingRecovery},
	} {
		if got := s.covering("203.0.113.1", tc.expires); got != tc.want {
			t.Errorf("expiry %v = %s, want %s", tc.expires.Sub(shadowExpiry), got, tc.want)
		}
	}
	if got := s.covering("203.0.113.2", shadowExpiry); got != 0 {
		t.Fatalf("an unmodelled address = %s", got)
	}
	if s.entries["203.0.113.1"] != entry {
		t.Fatal("a repeat changed the entry")
	}
}

// A lease ends at its expiry exactly, on the engine's lease clock; a
// charge leaves the window only after a full hour of admission and of
// running time. A wall-clock jump alone earns nothing and releases
// nothing, release refunds no credit, and a reduced limit keeps old
// charges until they age out.
func TestShadowClocks(t *testing.T) {
	s := testShadow(t, freshCeiling(t, 10), nil)
	if p := admitNow(t, s, "203.0.113.1", generalOnly, shadowT0, room); p != predictCapacityAdmit {
		t.Fatalf("admit = %s", p)
	}
	s.expire(shadowExpiry.Add(-time.Nanosecond))
	if len(s.entries) != 1 {
		t.Fatal("expired before its lease")
	}
	s.expire(shadowExpiry)
	if len(s.entries) != 0 {
		t.Fatal("kept at its expiry")
	}
	credit := s.ceiling.General.Credit
	if err := tickBy(s, shadowT0.Add(3*time.Hour), 0); err != nil {
		t.Fatal(err)
	}
	if len(s.charges) != 1 || s.ceiling.General.Credit != credit {
		t.Fatal("a wall jump released a charge or earned credit")
	}
	if err := tickBy(s, shadowT0.Add(3*time.Hour), time.Hour-time.Nanosecond); err != nil {
		t.Fatal(err)
	}
	if len(s.charges) != 1 || s.ceiling.General.Used != 1 {
		t.Fatal("released before a full hour of running time")
	}
	if err := s.setLimit(5); err != nil {
		t.Fatal(err)
	}
	if len(s.charges) != 1 || s.ceiling.General.Used != 1 {
		t.Fatal("a reduced limit dropped a retained charge")
	}
	want, err := s.ceiling.Advance(time.Nanosecond)
	if err != nil {
		t.Fatal(err)
	}
	if err = tickBy(s, shadowT0.Add(3*time.Hour), time.Nanosecond); err != nil {
		t.Fatal(err)
	}
	if len(s.charges) != 0 || s.ceiling.General.Used != 0 || s.ceiling.General.Credit != want.General.Credit {
		t.Fatalf("release: %d charges, %+v; want credit %d, no refund", len(s.charges), s.ceiling.General, want.General.Credit)
	}
}

// The forecast models at most 20000 active blocks. With an unlimited or a
// larger set the next unique address is forecast-limited, not set-full,
// and consumes nothing; an expiry frees a slot.
func TestShadowForecastBound(t *testing.T) {
	for _, limit := range []int{0, firewall.MaxShadowBlocks + 5000} {
		s := testShadow(t, freshCeiling(t, 2000), nil)
		for i := range forecastEntries {
			s.entries[fmt.Sprintf("2001:db8::%x", i+1)] = shadowEntry{kind: admission.KindBlockIP, expires: shadowExpiry.Add(time.Duration(i))}
		}
		adm := firewall.BlockAdmission{Limit: limit}
		used := s.ceiling
		if p := admitNow(t, s, "203.0.113.1", generalOnly, shadowT0, adm); p != predictForecastLimited {
			t.Fatalf("limit %d: next unique = %s", limit, p)
		}
		if s.ceiling != used || len(s.entries) != forecastEntries || !s.limited() {
			t.Fatal("a limited forecast consumed something")
		}
		s.expire(shadowExpiry)
		if p := admitNow(t, s, "203.0.113.1", generalOnly, shadowT0, adm); p != predictCapacityAdmit {
			t.Fatalf("limit %d: after an expiry = %s", limit, p)
		}
	}
}

// A decision changes nothing until it is committed: an ending that failed
// to commit leaves no charge or entry, and a later decision sees only
// committed ones.
func TestShadowDecisionsAreSpeculative(t *testing.T) {
	s := testShadow(t, freshCeiling(t, 5), nil)
	p, change, err := s.admit("203.0.113.1", admission.KindBlockIP, shadowExpiry, generalOnly, shadowT0, room)
	if err != nil || p != predictCapacityAdmit || change == nil {
		t.Fatalf("decision = %s %+v %v", p, change, err)
	}
	again, _, err := s.admit("203.0.113.2", admission.KindBlockIP, shadowExpiry, generalOnly, shadowT0, room)
	if err != nil || again != predictCapacityAdmit || len(s.entries) != 0 || len(s.charges) != 0 || s.picks[predictCapacityAdmit] != 0 {
		t.Fatalf("an uncommitted decision changed the shadow: %s %v", again, err)
	}
	s.commit(p, change, shadowT0)
	if after, _, _ := s.admit("203.0.113.2", admission.KindBlockIP, shadowExpiry, generalOnly, shadowT0, room); after != predictCeiling {
		t.Fatalf("after the commit = %s", after)
	}
	s.commit(predictSetFull, nil, shadowT0)
	if s.picks[predictCapacityAdmit] != 1 || s.picks[predictSetFull] != 1 || len(s.entries) != 1 {
		t.Fatalf("counters %v, %d entries", s.picks, len(s.entries))
	}
}

// Session counters saturate; the recent totals keep sixty minutes of the
// process's monotonic time and forget older minutes.
func TestShadowCountsPredictions(t *testing.T) {
	s := testShadow(t, freshCeiling(t, 5), nil)
	mono := time.Unix(0, 0)
	s.commit(predictCeiling, nil, mono)
	s.commit(predictCeiling, nil, mono.Add(59*time.Minute))
	if got := s.recent.total(mono.Add(59 * time.Minute)); got[predictCeiling] != 2 {
		t.Fatalf("last hour = %v", got)
	}
	if got := s.recent.total(mono.Add(60 * time.Minute)); got[predictCeiling] != 1 {
		t.Fatalf("an hour later = %v", got)
	}
	if got := s.recent.total(mono.Add(200 * time.Minute)); got[predictCeiling] != 0 {
		t.Fatalf("much later = %v", got)
	}
	s.picks[predictSetFull] = ^uint64(0)
	s.commit(predictSetFull, nil, mono)
	if s.picks[predictSetFull] != ^uint64(0) || s.picks[predictCeiling] != 2 {
		t.Fatalf("counters = %v", s.picks)
	}
}

// Every prediction has a fixed, distinct name.
func TestPredictionNames(t *testing.T) {
	want := map[prediction]string{
		predictCapacityAdmit: "capacity_admit", predictExistingActual: "existing_actual", predictExistingShadow: "existing_shadow",
		predictCeiling: "ceiling", predictSetFull: "set_full", predictPendingRecovery: "pending_recovery",
		predictForecastLimited: "forecast_limited", predictNotModelled: "not_modelled",
	}
	if len(want) != int(predictionEnd)-1 {
		t.Fatalf("%d names for %d predictions", len(want), predictionEnd-1)
	}
	for p, name := range want {
		if got := p.String(); got != name || !p.Valid() {
			t.Errorf("prediction %d = %q, want %q", p, got, name)
		}
	}
	if prediction(0).Valid() || predictionEnd.Valid() {
		t.Fatal("an out-of-range prediction is valid")
	}
}

// A session ID is 128 random bits in hex; a failed read names none.
func TestShadowSessionID(t *testing.T) {
	id, err := newSessionID(bytes.NewReader(bytes.Repeat([]byte{0xab}, 16)))
	if err != nil || id != strings.Repeat("ab", 16) {
		t.Fatalf("id = %q, %v", id, err)
	}
	if id, err = newSessionID(bytes.NewReader([]byte{1, 2})); err == nil || id != "" {
		t.Fatalf("short read = %q, %v", id, err)
	}
	if _, err = newShadow("short", shadowT0, resetStartup, freshCeiling(t, 5), nil); err == nil {
		t.Fatal("a malformed session ID was accepted")
	}
}

// When several limits are exhausted the full set wins, then the modelling
// bound, then the ceiling.
func TestShadowLimitPrecedence(t *testing.T) {
	s := testShadow(t, freshCeiling(t, 5), nil)
	if p := admitNow(t, s, "203.0.113.1", generalOnly, shadowT0, room); p != predictCapacityAdmit {
		t.Fatalf("spending the credit = %s", p)
	}
	for i := len(s.entries); i < forecastEntries; i++ {
		s.entries[fmt.Sprintf("2001:db8::%x", i+1)] = shadowEntry{kind: admission.KindBlockIP, expires: shadowExpiry}
	}
	if p := admitNow(t, s, "203.0.113.2", generalOnly, shadowT0, firewall.BlockAdmission{Limit: forecastEntries}); p != predictSetFull {
		t.Fatalf("full, limited and spent = %s, want set_full", p)
	}
	if p := admitNow(t, s, "203.0.113.2", generalOnly, shadowT0, room); p != predictForecastLimited {
		t.Fatalf("limited and spent = %s, want forecast_limited", p)
	}
}

// A simulated charge ages out by its own admission and running time, as a
// real one does.
func TestShadowSimulatedChargesAge(t *testing.T) {
	s := testShadow(t, freshCeiling(t, 10), nil)
	at := shadowT0.Add(30 * time.Minute)
	if err := tickBy(s, at, 30*time.Minute); err != nil {
		t.Fatal(err)
	}
	if p := admitNow(t, s, "203.0.113.1", generalOnly, at, room); p != predictCapacityAdmit {
		t.Fatalf("admit = %s", p)
	}
	if err := tickBy(s, at.Add(59*time.Minute), 59*time.Minute); err != nil {
		t.Fatal(err)
	}
	if len(s.charges) != 1 {
		t.Fatal("a simulated charge left the window early")
	}
	if err := tickBy(s, at.Add(time.Hour), time.Minute); err != nil {
		t.Fatal(err)
	}
	if len(s.charges) != 0 || s.ceiling.General.Used != 0 {
		t.Fatalf("a simulated charge outlived its window: %+v", s.charges)
	}
}

// A minute's bucket is reused for the same minute an hour later only after
// it is emptied.
func TestShadowReusesMinuteBuckets(t *testing.T) {
	s := testShadow(t, freshCeiling(t, 5), nil)
	mono := time.Unix(0, 0)
	s.commit(predictCeiling, nil, mono)
	s.commit(predictCeiling, nil, mono.Add(time.Hour))
	if got := s.recent.total(mono.Add(time.Hour)); got[predictCeiling] != 1 {
		t.Fatalf("last hour = %v", got)
	}
}

// Neither wall time nor running time alone ends a simulated charge: both
// must pass a full window from the charge's own reading.
func TestShadowSimulatedChargesNeedBothClocks(t *testing.T) {
	for _, tc := range []struct {
		name    string
		wall    time.Duration
		elapsed time.Duration
	}{
		{"wall only", 3 * time.Hour, 59 * time.Minute},
		{"running time only", 59 * time.Minute, 3 * time.Hour},
	} {
		s := testShadow(t, freshCeiling(t, 10), nil)
		at := shadowT0.Add(30 * time.Minute)
		if err := tickBy(s, at, 30*time.Minute); err != nil {
			t.Fatal(err)
		}
		if p := admitNow(t, s, "203.0.113.1", generalOnly, at, room); p != predictCapacityAdmit {
			t.Fatalf("admit = %s", p)
		}
		if err := tickBy(s, at.Add(tc.wall), tc.elapsed); err != nil {
			t.Fatal(err)
		}
		if len(s.charges) != 1 {
			t.Fatalf("%s released a simulated charge", tc.name)
		}
	}
}
