package admission

import (
	"bytes"
	"math"
	"strings"
	"testing"
	"time"
)

// largestCandidate is the widest candidate the invariants allow: a service
// target, the longest check and account, every root and every counter at
// its widest.
func largestCandidate(t *testing.T) Candidate {
	t.Helper()
	c := queuedCandidate(t)
	c.Key.Kind, c.Scope.Effect = KindBlockService, EffectService
	c.Key.Target = mustService(t, "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", "tcp", 65535)
	c.Key.Generation = math.MaxUint32
	c.Check = strings.Repeat("c", 64)
	c.Roots = nil
	for i := 0; i < MaxRoots; i++ {
		c.Roots = append(c.Roots, EvidenceID("ev_"+strings.Repeat("f", 30)+string("0123456789abcdef"[i/16])+string("0123456789abcdef"[i%16])))
	}
	c.State, c.Disposition, c.Attempts = StateUnknown, DispositionUnknown, MaxAttempts
	c.ExpiresAt, c.Transitions = t0.Add(24*time.Hour), math.MaxUint32
	return c
}

// Storage accounting reserves each record's bound, so the largest record
// the invariants allow must fit it.
func TestStoredRecordsFitTheirBounds(t *testing.T) {
	c := largestCandidate(t)
	cand, err := c.ID()
	if err != nil {
		t.Fatal(err)
	}
	third, _ := NewAttempt(cand, MaxAttempts)
	far := time.Unix(0, math.MaxInt64).UTC()
	links := ReportLinks{Evidence: testEvidenceID(1), Dropped: math.MaxUint32}
	for i := 0; i < MaxReportLinks; i++ {
		links.Links = append(links.Links, strings.Repeat("f", 14)+string("0123456789abcdef"[i])+"f")
	}
	for _, tc := range []struct {
		name  string
		rec   interface{ MarshalBinary() ([]byte, error) }
		bound int
	}{
		{"candidate", c, MaxCandidateBytes},
		{"attempt", AttemptRecord{Attempt: third, State: StateUnknown, Disposition: DispositionUnknown, ExpiresAt: far, Reserved: far.Add(-time.Hour), Finished: far, Lane: LaneCorroborated}, MaxAttemptBytes},
		{"report links", links, MaxReportLinksBytes},
		{"history entry", HistoryEntry{RootMask: (1 << MaxRoots) - 1, General: MaxHistoryBytes / 2, Reserved: MaxHistoryBytes / 2, Ended: far.Add(-HistoryTarget), Eligible: far}, MaxHistoryEntryBytes},
		{"pinned history entry", HistoryEntry{RootMask: (1 << MaxRoots) - 1, General: MaxHistoryBytes / 2, Reserved: MaxHistoryBytes / 2, Ended: far, Pinned: true}, MaxHistoryEntryBytes},
		{"evidence references", EvidenceRefs{Refs: math.MaxUint32}, MaxEvidenceRefsBytes},
		{"loose evidence", EvidenceRefs{Loose: math.MaxUint64}, MaxEvidenceRefsBytes},
	} {
		data, err := tc.rec.MarshalBinary()
		if err != nil || len(data) > tc.bound {
			t.Errorf("largest %s: %d bytes (bound %d), %v", tc.name, len(data), tc.bound, err)
		}
	}
}

// MaxBytes bounds every encoding the candidate can reach later: its
// identity, scope and roots stay, and every other field grows.
func TestCandidateMaxBytesCoversEveryLaterState(t *testing.T) {
	for _, base := range []Candidate{queuedCandidate(t), largestCandidate(t)} {
		want, err := base.MaxBytes()
		if err != nil {
			t.Fatal(err)
		}
		queued := base
		queued.State, queued.Disposition, queued.Attempts, queued.ExpiresAt, queued.Transitions = StateQueued, 0, 0, time.Time{}, 1
		if got, err := queued.MaxBytes(); err != nil || got != want {
			t.Fatalf("MaxBytes changed with the state: %d, %v; want %d", got, err, want)
		}
		widest := func(mutate func(*Candidate)) Candidate {
			c := base
			c.Reason, c.Disposition, c.NotBefore, c.Transitions = 0, 0, time.Time{}, math.MaxUint32
			c.ExpiresAt = time.Unix(0, math.MaxInt64-int64(time.Hour)).UTC()
			mutate(&c)
			return c
		}
		for name, c := range map[string]Candidate{
			"deferred retry": widest(func(c *Candidate) {
				c.State, c.Attempts, c.Reason = StateQueued, MaxAttempts-1, ReasonPendingRecovery
				c.NotBefore = c.FirstQueued.Add(time.Hour)
			}),
			"dropped after an attempt": widest(func(c *Candidate) {
				c.State, c.Attempts = StateDropped, MaxAttempts-1
				c.Disposition, c.Reason = DispositionDropped, ReasonIngressInterruption
			}),
			"unknown": widest(func(c *Candidate) {
				c.State, c.Attempts, c.Disposition = StateUnknown, MaxAttempts, DispositionUnknown
			}),
		} {
			data, err := c.MarshalBinary()
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if len(data) > want {
				t.Errorf("%s: %d bytes exceed MaxBytes %d", name, len(data), want)
			}
		}
	}
	bad := queuedCandidate(t)
	bad.Roots = nil
	if _, err := bad.MaxBytes(); err == nil {
		t.Fatal("MaxBytes accepted an invalid candidate")
	}
}

func TestHistoryTimes(t *testing.T) {
	ended := t0
	for _, tc := range []struct {
		name     string
		expires  time.Time
		verified bool
		eligible time.Time
		target   time.Time
	}{
		{"failed", t0.Add(365 * 24 * time.Hour), false, t0.Add(HistoryRetention), t0.Add(HistoryTarget)},
		{"short effect", t0.Add(time.Hour), true, t0.Add(HistoryRetention), t0.Add(HistoryTarget)},
		{"effect past the review window", t0.Add(10 * 24 * time.Hour), true, t0.Add(10 * 24 * time.Hour), t0.Add(HistoryTarget)},
		{"effect past the target", t0.Add(90 * 24 * time.Hour), true, t0.Add(90 * 24 * time.Hour), t0.Add(90 * 24 * time.Hour)},
	} {
		e, d := HistoryTimes(ended, tc.expires, tc.verified)
		if !e.Equal(tc.eligible) || !d.Equal(tc.target) {
			t.Errorf("%s: HistoryTimes = %v, %v; want %v, %v", tc.name, e, d, tc.eligible, tc.target)
		}
		h := HistoryEntry{General: 1, Ended: ended, Eligible: e}
		if !h.Target().Equal(tc.target) {
			t.Errorf("%s: Target = %v, want %v", tc.name, h.Target(), tc.target)
		}
	}
}

func TestHistoryEntryInvariants(t *testing.T) {
	eligible := t0.Add(HistoryRetention)
	for _, tc := range []struct {
		name string
		h    HistoryEntry
		ok   bool
	}{
		{"live", HistoryEntry{General: 3000}, true},
		{"live on both allowances", HistoryEntry{General: 3000, Reserved: 400}, true},
		{"ended", HistoryEntry{Reserved: 3000, Ended: t0, Eligible: eligible}, true},
		{"ended with a long effect", HistoryEntry{General: 3000, Ended: t0, Eligible: t0.Add(40 * 24 * time.Hour)}, true},
		{"pinned", HistoryEntry{General: 3000, Ended: t0, Pinned: true}, true},
		{"largest", HistoryEntry{General: MaxHistoryBytes - 1, Reserved: 1}, true},
		{"nothing charged", HistoryEntry{}, false},
		{"root mask beyond the bound", HistoryEntry{General: 1, RootMask: 1 << MaxRoots}, false},
		{"over the largest cost", HistoryEntry{General: MaxHistoryBytes, Reserved: 1}, false},
		{"live with a retirement time", HistoryEntry{General: 3000, Eligible: eligible}, false},
		{"live and pinned", HistoryEntry{General: 3000, Pinned: true}, false},
		{"ended without a retirement time", HistoryEntry{General: 3000, Ended: t0}, false},
		{"retired inside the review window", HistoryEntry{General: 3000, Ended: t0, Eligible: eligible.Add(-time.Nanosecond)}, false},
		{"pinned with a retirement time", HistoryEntry{General: 3000, Ended: t0, Eligible: eligible, Pinned: true}, false},
		{"ended before the epoch", HistoryEntry{General: 3000, Ended: time.Unix(0, -1), Eligible: time.Unix(0, -1).Add(HistoryRetention)}, false},
	} {
		err := tc.h.Validate()
		if (err == nil) != tc.ok {
			t.Errorf("%s: Validate() = %v, want ok %v", tc.name, err, tc.ok)
			continue
		}
		if !tc.ok {
			if _, encErr := tc.h.MarshalBinary(); encErr == nil {
				t.Errorf("%s: encoded an invalid entry", tc.name)
			}
			continue
		}
		data, err := tc.h.MarshalBinary()
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if back, err := UnmarshalHistoryEntry(data); err != nil || back != tc.h {
			t.Errorf("%s: round trip = %+v, %v", tc.name, back, err)
		}
	}
	data, err := HistoryEntry{General: 3000, Ended: t0, Eligible: eligible}.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	body := data[:len(data)-8]
	for name, tampered := range map[string][]byte{
		"flipped byte":   func() []byte { d := bytes.Clone(data); d[4] ^= 1; return d }(),
		"future version": resealForTest(bytes.Replace(body, []byte(`"v":1`), []byte(`"v":2`), 1)),
		"unknown field":  resealForTest(bytes.Replace(body, []byte(`{"v":1`), []byte(`{"x":1,"v":1`), 1)),
		"early":          resealForTest(bytes.Replace(body, []byte(`"general":3000`), []byte(`"general":3000,"pinned":true`), 1)),
	} {
		if _, err := UnmarshalHistoryEntry(tampered); err != ErrCorruptRecord {
			t.Errorf("%s: err = %v, want ErrCorruptRecord", name, err)
		}
	}
}

func TestEvidenceRefsInvariants(t *testing.T) {
	for _, tc := range []struct {
		name string
		r    EvidenceRefs
		ok   bool
	}{
		{"referenced", EvidenceRefs{Refs: 2}, true},
		{"loose", EvidenceRefs{Loose: 7}, true},
		{"neither", EvidenceRefs{}, false},
		{"both", EvidenceRefs{Refs: 1, Loose: 7}, false},
	} {
		data, err := tc.r.MarshalBinary()
		if (err == nil) != tc.ok {
			t.Errorf("%s: MarshalBinary() = %v, want ok %v", tc.name, err, tc.ok)
			continue
		}
		if !tc.ok {
			continue
		}
		if back, err := UnmarshalEvidenceRefs(data); err != nil || back != tc.r {
			t.Errorf("%s: round trip = %+v, %v", tc.name, back, err)
		}
	}
	data, err := EvidenceRefs{Refs: 2}.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	body := data[:len(data)-8]
	for name, tampered := range map[string][]byte{
		"flipped byte":   func() []byte { d := bytes.Clone(data); d[4] ^= 1; return d }(),
		"future version": resealForTest(bytes.Replace(body, []byte(`"v":1`), []byte(`"v":2`), 1)),
		"both":           resealForTest(bytes.Replace(body, []byte(`"refs":2`), []byte(`"refs":2,"loose":3`), 1)),
	} {
		if _, err := UnmarshalEvidenceRefs(tampered); err != ErrCorruptRecord {
			t.Errorf("%s: err = %v, want ErrCorruptRecord", name, err)
		}
	}
}

func TestHistoryEntryRetireKeys(t *testing.T) {
	id, _ := queuedCandidate(t).ID()
	ended := HistoryEntry{General: 3000, Reserved: 400, Ended: t0, Eligible: t0.Add(10 * 24 * time.Hour)}
	keys, err := ended.RetireKeys(id)
	if err != nil || len(keys) != 3 {
		t.Fatalf("keys = %q, %v", keys, err)
	}
	for i, want := range []struct {
		kind byte
		at   time.Time
	}{{RetireGeneral, ended.Eligible}, {RetireReserved, ended.Eligible}, {RetireTarget, t0.Add(HistoryTarget)}} {
		kind, at, cand, err := ParseRetireKey(keys[i])
		if err != nil || len(keys[i]) != HistoryIndexKeyLen || kind != want.kind || !at.Equal(want.at) || cand != id {
			t.Errorf("key %d = %q, want kind %c at %v", i, keys[i], want.kind, want.at)
		}
	}
	// Keys of one kind sort by time.
	later := ended
	later.Ended, later.Eligible = t0.Add(time.Hour), t0.Add(time.Hour+HistoryRetention)
	early, _ := HistoryEntry{General: 1, Ended: t0, Eligible: t0.Add(HistoryRetention)}.RetireKeys(id)
	late, _ := later.RetireKeys(id)
	if bytes.Compare(early[0], late[0]) >= 0 || bytes.Compare(early[1], late[2]) >= 0 {
		t.Fatal("retirement keys do not sort by time")
	}
	only, _ := HistoryEntry{Reserved: 400, Ended: t0, Eligible: t0.Add(HistoryRetention)}.RetireKeys(id)
	if len(only) != 2 || only[0][0] != RetireReserved || only[1][0] != RetireTarget {
		t.Fatalf("a reserved-only entry has keys %q", only)
	}
	for name, h := range map[string]HistoryEntry{
		"live":   {General: 3000},
		"pinned": {General: 3000, Ended: t0, Pinned: true},
	} {
		if got, keysErr := h.RetireKeys(id); keysErr != nil || got != nil {
			t.Errorf("%s entry has keys %q, %v", name, got, keysErr)
		}
	}
	if _, err := (HistoryEntry{}).RetireKeys(id); err == nil {
		t.Fatal("an invalid entry has keys")
	}
	if _, err := ended.RetireKeys("cand_bad"); err == nil {
		t.Fatal("keys for a malformed candidate ID")
	}
	good := keys[0]
	for name, k := range map[string][]byte{
		"short":        good[:len(good)-1],
		"unknown kind": append([]byte{'x'}, good[1:]...),
		"not a number": append(append([]byte{good[0]}, []byte("00000000000000000x0")...), good[20:]...),
		"zero time":    append(append([]byte{good[0]}, []byte("0000000000000000000")...), good[20:]...),
		"signed":       append(append([]byte{good[0]}, []byte("+000000000000000001")...), good[20:]...),
		"malformed ID": append(append([]byte(nil), good[:20]...), []byte("cand_"+strings.Repeat("g", 32))...),
	} {
		if _, _, _, err := ParseRetireKey(k); err != ErrCorruptRecord {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}
