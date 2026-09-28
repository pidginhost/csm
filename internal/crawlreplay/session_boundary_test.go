package crawlreplay

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

func boundaryConfig() SessionConfig {
	return SessionConfig{Params: Params{W: 2, R: 3, F: 1, K: 1, D: 2, C: 80,
		Baseline: BaselineParams{Alpha: 0.5, MinObs: 1, FloorPerMin: 1}},
		Sketch: &SketchParams{M: 4, H: 4, Seed: 1}}
}

func TestRestoreRejectsMissingPinnedProfile(t *testing.T) {
	cfg := boundaryConfig()
	s := mustSession(t, cfg)
	syn := NewSynth(testSite, 1)
	records := syn.Pool(Traffic{From: monday, To: monday + 3, PerMinute: 2,
		L2: SynthKey(1), L1: SynthKey(2), Label: LabelHealthy}, 1)
	records = append(records, syn.Rotating(Traffic{From: monday + 4, To: monday + 5, PerMinute: 30,
		L2: SynthKey(1), L1: SynthKey(2), Label: LabelAttack, Episode: "e1"}, 1)...)
	feedTicks(t, s, segment(testSite, records, nil, Span{From: monday, To: monday + 5}))
	raw, err := s.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	mustRestore(t, raw, cfg)
	var snap sessionSnapshot
	if err = DecodeStrictJSON(raw, &snap); err != nil {
		t.Fatal(err)
	}
	f := snap.Sites[0].Keys[0].Finding
	if f == nil || len(f.PinSlots) == 0 {
		t.Fatal("scenario needs an active finding with a trained pinned profile")
	}
	f.PinSlots = nil
	raw, err = json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	for name, input := range map[string][]byte{
		"null":    raw,
		"omitted": bytes.Replace(raw, []byte(`,"pin_slots":null`), nil, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := Restore(input, cfg); !errors.Is(err, ErrSession) {
				t.Fatalf("missing pinned profile: %v, want ErrSession", err)
			}
		})
	}
}

func TestSessionOwnsSketchConfiguration(t *testing.T) {
	for _, restored := range []bool{false, true} {
		t.Run(map[bool]string{false: "new", true: "restored"}[restored], func(t *testing.T) {
			cfg := boundaryConfig()
			s := mustSession(t, cfg)
			records := NewSynth(testSite, 1).Pool(Traffic{From: monday, To: monday + 3, PerMinute: 3,
				L2: SynthKey(1), L1: SynthKey(2), Label: LabelHealthy}, 2)
			feedTicks(t, s, segment(testSite, records, nil, Span{From: monday, To: monday + 1}))
			raw, err := s.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			if restored {
				s = mustRestore(t, raw, cfg)
			}
			control := mustRestore(t, raw, boundaryConfig())
			// Reusing a configuration for another experiment must not change
			// the hash contract of summaries already held by this session.
			cfg.Sketch.Seed++
			next := segment(testSite, records, nil, Span{From: monday + 2, To: monday + 3})
			got, want := feedTicks(t, s, next), feedTicks(t, control, next)
			if !reflect.DeepEqual(got, want) {
				t.Fatal("caller configuration mutation changed replay decisions")
			}
			a, err := s.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			b, err := control.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			if string(a) != string(b) {
				t.Fatal("caller configuration mutation changed retained state")
			}
		})
	}
}

func TestSessionOwnsStateDeclarationKeys(t *testing.T) {
	cfg := boundaryConfig()
	s := mustSession(t, cfg)
	key := l1(2)
	seg := segment(testSite, nil, nil, Span{From: monday, To: monday})
	seg.States = append(seg.States, StateSpan{Key: &key, From: monday, To: monday + 3, State: StateProtected})
	feedTicks(t, s, seg)
	key = l1(3)
	raw, err := s.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	s = mustRestore(t, raw, cfg)
	records := NewSynth(testSite, 1).Pool(Traffic{From: monday + 1, To: monday + 3, PerMinute: 1,
		L2: SynthKey(1), L1: SynthKey(2), Label: LabelHealthy}, 1)
	feedTicks(t, s, segment(testSite, records, nil, Span{From: monday + 1, To: monday + 3}))
	if got := slotOf(t, s, testSite, l1(2), monday); got != (slot{}) {
		t.Fatalf("reused declaration key unfroze protected learning after restore: %+v", got)
	}
}

func TestRestoreUnprocessedSiteAfterInvalidation(t *testing.T) {
	for _, change := range []string{"window", "baseline", "identity"} {
		t.Run(change, func(t *testing.T) {
			cfg := boundaryConfig()
			s := mustSession(t, cfg)
			// A segment can declare states even when none of its minutes
			// have certified coverage yet.
			feedTicks(t, s, ReplaySegment{Site: testSite, States: normal(monday, monday+3)})
			raw, err := s.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "window":
				cfg.Params.W++
			case "baseline":
				cfg.Params.Baseline.Alpha /= 2
			case "identity":
				cfg.IdentityVersion++
			}
			s = mustRestore(t, raw, cfg)
			raw, err = s.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			s = mustRestore(t, raw, cfg)
			records := NewSynth(testSite, 1).Pool(Traffic{From: monday, To: monday + 3, PerMinute: 1,
				L2: SynthKey(1), L1: SynthKey(2), Label: LabelHealthy}, 1)
			feedTicks(t, s, ReplaySegment{Site: testSite, Records: records, Coverage: []Span{{From: monday, To: monday + 3}}})
			if got := slotOf(t, s, testSite, l1(2), monday); got.obs != 5-cfg.Params.W || got.mean != 1 {
				t.Fatalf("restored declarations did not govern learning: %+v", got)
			}
		})
	}
}
