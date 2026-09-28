package crawlreplay

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// monday is 2026-09-21 00:00 UTC as a Unix minute: hour-of-week slot 0.
var monday = time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC).Unix() / 60

const week = int64(7 * 24 * 60)

func l1(n uint64) KeyID { return KeyID{Level: 1, Key: SynthKey(n), Parent: SynthKey(1)} }

func normal(from, to int64) []StateSpan { return []StateSpan{{From: from, To: to, State: StateNormal}} }

func mustSession(t *testing.T, cfg SessionConfig) *ReplaySession {
	t.Helper()
	s, err := NewReplaySession(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// feedTicks feeds one segment and returns every tick it produced.
func feedTicks(t *testing.T, s *ReplaySession, seg ReplaySegment) []Tick {
	t.Helper()
	var ticks []Tick
	if err := s.Feed(seg, func(tk Tick) error { ticks = append(ticks, tk); return nil }); err != nil {
		t.Fatal(err)
	}
	return ticks
}

// segment builds a normal-state segment over coverage, keeping only the
// records coverage holds.
func segment(site string, recs []Record, score []Span, coverage ...Span) ReplaySegment {
	return ReplaySegment{Site: site, Records: RestrictToCoverage(recs, coverage), Coverage: coverage, Score: score,
		States: normal(coverage[0].From, coverage[len(coverage)-1].To)}
}

func evalOf(tk Tick, id KeyID) *Evaluation {
	for i := range tk.Evaluations {
		if tk.Evaluations[i].Key == id {
			return &tk.Evaluations[i]
		}
	}
	return nil
}

func eventsFor(ticks []Tick, id KeyID) []FindingEvent {
	var out []FindingEvent
	for _, tk := range ticks {
		for _, e := range tk.Events {
			if e.Key == id {
				out = append(out, e)
			}
		}
	}
	return out
}

func activeFor(tk Tick, id KeyID) *ActiveFinding {
	for i := range tk.Active {
		if tk.Active[i].Key == id {
			return &tk.Active[i]
		}
	}
	return nil
}

func slotOf(t *testing.T, s *ReplaySession, site string, id KeyID, m int64) slot {
	t.Helper()
	ks := s.sites[site].keys[id]
	if ks == nil {
		t.Fatalf("key %+v has no state", id)
	}
	return ks.baseline.slots[hourOfWeek(m)]
}

func TestBaselineLearningState(t *testing.T) {
	p := Params{W: 5, R: 3, F: 1, K: 2, D: 5, C: 80, Baseline: BaselineParams{Alpha: 0.5, MinObs: 3, MinAge: 0, FloorPerMin: 1}}
	hour := monday + 10*60
	bg := l1(2)
	// train fills minutes 0..29 of one UTC hour with eight requests a minute
	// on bg, so the slot holds a mature mean of 8, far from the floor of 1.
	train := func(t *testing.T) (*ReplaySession, slot) {
		t.Helper()
		s := mustSession(t, SessionConfig{Params: p})
		recs := NewSynth(testSite, 5).Pool(Traffic{From: hour, To: hour + 29, PerMinute: 8, L2: SynthKey(1), L1: SynthKey(2), Label: LabelHealthy}, 4)
		feedTicks(t, s, segment(testSite, recs, nil, Span{From: hour, To: hour + 29}))
		// The first W-1 minutes had traffic no complete window judged.
		trained := slotOf(t, s, testSite, bg, hour)
		if trained.obs != 30-(p.W-1) || trained.mean != 8 || trained.last != hour+29 {
			t.Fatalf("trained slot %+v, want %d observations of 8 ending at minute 29", trained, 30-(p.W-1))
		}
		return s, trained
	}
	later := Span{From: hour + 30, To: hour + 39}
	healthy := func(seed uint64) []Record {
		return NewSynth(testSite, seed).Pool(Traffic{From: later.From, To: later.To, PerMinute: 8, L2: SynthKey(1), L1: SynthKey(2), Label: LabelHealthy}, 4)
	}

	// The harness never acts, so every anomalous minute is a dry-run
	// decision: it must freeze learning exactly as applied protection would.
	for _, rate := range []int{200, 1000, 5000} {
		t.Run(fmt.Sprintf("attack at %d a minute", rate), func(t *testing.T) {
			s, trained := train(t)
			parent, site := bg.parent(), KeyID{Level: 3}
			before := map[KeyID]slot{bg: trained, parent: slotOf(t, s, testSite, parent, hour), site: slotOf(t, s, testSite, site, hour)}
			recs := append(healthy(7), NewSynth(testSite, 6).Rotating(Traffic{From: later.From, To: later.To, PerMinute: rate,
				L2: SynthKey(1), L1: SynthKey(2), Label: LabelAttack, Episode: "e1"}, 1)...)
			for _, tk := range feedTicks(t, s, segment(testSite, recs, nil, later)) {
				if e := evalOf(tk, bg); e == nil || !e.Anomalous {
					t.Fatalf("minute %d: attacked key not anomalous", tk.Minute-hour)
				}
			}
			for id, want := range before {
				if got := slotOf(t, s, testSite, id, hour); got != want {
					t.Fatalf("key %+v: anomalous minutes changed its slot from %+v to %+v", id, want, got)
				}
			}
		})
	}

	for _, state := range []string{StateProtected, StateDegraded, StateRecoveryHold} {
		for _, scope := range []string{"site", "key"} {
			t.Run(state+"/"+scope, func(t *testing.T) {
				s, trained := train(t)
				seg := segment(testSite, healthy(8), nil, later)
				if scope == "site" {
					seg.States = []StateSpan{{From: later.From, To: later.To, State: state}}
				} else {
					seg.States = append(seg.States, StateSpan{Key: &bg, From: later.From, To: later.To, State: state})
				}
				for _, tk := range feedTicks(t, s, seg) {
					if e := evalOf(tk, bg); e == nil || e.Anomalous {
						t.Fatalf("minute %d: healthy key must be judged and normal", tk.Minute-hour)
					}
				}
				if got := slotOf(t, s, testSite, bg, hour); got != trained {
					t.Fatalf("%s minutes changed the slot from %+v to %+v", state, trained, got)
				}
			})
		}
	}

	t.Run("key declaration wins over the site", func(t *testing.T) {
		s, trained := train(t)
		seg := segment(testSite, healthy(8), nil, later)
		seg.States = []StateSpan{{From: later.From, To: later.To, State: StateProtected}, {Key: &bg, From: later.From, To: later.To, State: StateNormal}}
		feedTicks(t, s, seg)
		if got := slotOf(t, s, testSite, bg, hour); got.obs != trained.obs+10 || got.last != later.To {
			t.Fatalf("normal key under a protected site did not learn: %+v", got)
		}
	})

	t.Run("unknown state", func(t *testing.T) {
		s, trained := train(t)
		seg := segment(testSite, healthy(8), nil, later)
		seg.States = nil
		feedTicks(t, s, seg)
		if got := slotOf(t, s, testSite, bg, hour); got != trained {
			t.Fatalf("undeclared minutes changed the slot from %+v to %+v", trained, got)
		}
	})

	t.Run("known zero updates once", func(t *testing.T) {
		s, trained := train(t)
		quiet := Span{From: hour + 30, To: hour + 30}
		feedTicks(t, s, segment(testSite, nil, nil, quiet))
		want := slot{mean: trained.mean / 2, obs: trained.obs + 1, last: quiet.From}
		if got := slotOf(t, s, testSite, bg, hour); got != want {
			t.Fatalf("covered zero gave %+v, want %+v", got, want)
		}
		if err := s.Feed(segment(testSite, nil, nil, quiet), func(Tick) error { return nil }); !errors.Is(err, ErrSession) {
			t.Fatalf("minute fed twice: %v, want ErrSession", err)
		}
		if s.sites[testSite].keys[bg].baseline.Observe(quiet.From, 0) {
			t.Fatal("baseline learned a minute twice")
		}
		if got := slotOf(t, s, testSite, bg, hour); got != want {
			t.Fatalf("duplicate minute changed the slot to %+v, want %+v", got, want)
		}
	})
}

func (id KeyID) parent() KeyID { return KeyID{Level: 2, Key: id.Parent} }

// seasonalHistory trains one week before the episode week: Sunday 23:00 at
// ten requests a minute, Monday 00:00 at twenty, and Monday 01:00 covered
// but silent, on bg.
func seasonalHistory(site string, seed uint64) ([]Record, Span) {
	start := monday - 60 // Sunday 23:00, one week before the episode
	s := NewSynth(site, seed)
	recs := s.Pool(Traffic{From: start, To: start + 59, PerMinute: 10, L2: SynthKey(1), L1: SynthKey(2), Label: LabelHealthy}, 5)
	recs = append(recs, s.Pool(Traffic{From: start + 60, To: start + 119, PerMinute: 20, L2: SynthKey(1), L1: SynthKey(2), Label: LabelHealthy}, 5)...)
	return recs, Span{From: start, To: start + 179}
}

func TestPinnedSeasonalProfile(t *testing.T) {
	boundary := monday + week // Monday 00:00 of the episode week
	// D exceeds every background client count, so no background window is
	// anomalous and every slot minute trains.
	base := Params{W: 5, R: 3, F: 1, K: 2, D: 20, C: 80, Baseline: BaselineParams{Alpha: 0.5, MinObs: 60, FloorPerMin: 1}}
	bg := l1(2)
	episode := func(site string, seed uint64) ([]Record, Span) {
		s := NewSynth(site, seed)
		span := Span{From: boundary - 15, To: boundary + 65}
		recs := s.Pool(Traffic{From: span.From, To: boundary - 1, PerMinute: 10, L2: SynthKey(1), L1: SynthKey(2), Label: LabelHealthy}, 5)
		recs = append(recs, s.Pool(Traffic{From: boundary, To: boundary + 59, PerMinute: 20, L2: SynthKey(1), L1: SynthKey(2), Label: LabelHealthy}, 5)...)
		// The attack uses bg itself, from Sunday 23:57 into Monday 01:02.
		recs = append(recs, s.Rotating(Traffic{From: boundary - 3, To: boundary + 62, PerMinute: 600, L2: SynthKey(1), L1: SynthKey(2),
			Label: LabelAttack, Episode: "e1"}, 1)...)
		return recs, span
	}
	run := func(t *testing.T, p Params, extraSite bool) (*ReplaySession, []Tick) {
		t.Helper()
		s := mustSession(t, SessionConfig{Params: p})
		history, hspan := seasonalHistory(testSite, 1)
		feedTicks(t, s, segment(testSite, history, nil, hspan))
		if extraSite {
			other := "dom-0f0f0f.example"
			oh, ospan := seasonalHistory(other, 9)
			oh = append(oh, NewSynth(other, 10).Rotating(Traffic{From: ospan.From, To: ospan.To, PerMinute: 900, L2: SynthKey(1), L1: SynthKey(2)}, 1)...)
			feedTicks(t, s, segment(other, oh, nil, ospan))
		}
		recs, span := episode(testSite, 2)
		ticks := feedTicks(t, s, segment(testSite, recs, []Span{span}, span))
		if extraSite {
			other := "dom-0f0f0f.example"
			orecs, ospan := episode(other, 11)
			feedTicks(t, s, segment(other, orecs, []Span{ospan}, ospan))
		}
		return s, ticks
	}
	pinnedValue := func(m int64) float64 {
		switch hourOfWeek(m) {
		case 167:
			return 10
		case 0:
			return 20
		}
		return base.Baseline.FloorPerMin // Monday 01:00 learned only zeros
	}

	t.Run("trusted profile across the week boundary", func(t *testing.T) {
		s, ticks := run(t, base, false)
		events := eventsFor(ticks, bg)
		if len(events) != 1 || events[0].Minute != boundary-3 {
			t.Fatalf("events %+v, want one transition when the attack starts", events)
		}
		since := events[0].Minute
		judged := 0
		for _, tk := range ticks {
			e := evalOf(tk, bg)
			if e == nil || tk.Minute <= since || activeFor(tk, bg) == nil {
				continue
			}
			var want float64
			trusted := false
			for j := tk.Minute - int64(base.W) + 1; j <= tk.Minute; j++ {
				want += pinnedValue(j)
				trusted = trusted || hourOfWeek(j) != 1
			}
			if e.Expected != want || e.Trusted != trusted {
				t.Fatalf("minute %d: expected %v (trusted %t), want pinned sum %v", tk.Minute-boundary, e.Expected, e.Trusted, want)
			}
			judged++
		}
		if judged < 60 {
			t.Fatalf("only %d pinned windows judged", judged)
		}
		// Monday 01:00 learned silence as zero: a zero slot uses the floor.
		if sl := slotOf(t, s, testSite, bg, boundary+60); sl.obs != 60 || sl.mean != 0 {
			t.Fatalf("silent covered hour gave slot %+v, want 60 zero observations", sl)
		}
	})

	t.Run("key coming of age during the episode keeps its entry trust", func(t *testing.T) {
		p := base
		history, _ := seasonalHistory(testSite, 1)
		first := history[0].T / 60
		// Old enough only from Monday 00:00, three minutes after the pin.
		p.Baseline.MinAge = boundary - first
		s, ticks := run(t, p, false)
		events := eventsFor(ticks, bg)
		if len(events) != 1 {
			t.Fatalf("events %+v, want one", events)
		}
		for _, tk := range ticks {
			e := evalOf(tk, bg)
			if e == nil || activeFor(tk, bg) == nil || tk.Minute <= events[0].Minute {
				continue
			}
			if e.Expected != float64(p.W)*p.Baseline.FloorPerMin || e.Trusted {
				t.Fatalf("minute %d: expected %v trusted %t, want the entry floor", tk.Minute-boundary, e.Expected, e.Trusted)
			}
		}
		// The live profile has matured: judged now, the window would use 20.
		if live := s.sites[testSite].keys[bg].baseline.Expected(boundary + 5); live != 20 {
			t.Fatalf("live expectation %v, want the matured slot 20", live)
		}
	})

	t.Run("learning behind the finding cannot move the pin", func(t *testing.T) {
		s := mustSession(t, SessionConfig{Params: base})
		history, hspan := seasonalHistory(testSite, 1)
		feedTicks(t, s, segment(testSite, history, nil, hspan))
		recs, span := episode(testSite, 2)
		feedTicks(t, s, segment(testSite, recs, []Span{span}, Span{From: span.From, To: boundary + 1}))
		ks := s.sites[testSite].keys[bg]
		if ks.finding == nil {
			t.Fatal("scenario needs an active finding")
		}
		// Teach the live profile a huge rate for the minutes still to come.
		for m := boundary + 2; m <= boundary+10; m++ {
			if !ks.baseline.Observe(m, 100000) {
				t.Fatalf("live profile refused minute %d", m-boundary)
			}
		}
		rest := feedTicks(t, s, segment(testSite, recs, []Span{span}, Span{From: boundary + 2, To: span.To}))
		judged := 0
		for _, tk := range rest {
			e := evalOf(tk, bg)
			if e == nil || activeFor(tk, bg) == nil {
				continue
			}
			var want float64
			for j := tk.Minute - int64(base.W) + 1; j <= tk.Minute; j++ {
				want += pinnedValue(j)
			}
			if e.Expected != want {
				t.Fatalf("minute %d: expected %v, want the pinned %v", tk.Minute-boundary, e.Expected, want)
			}
			judged++
		}
		if judged < 50 {
			t.Fatalf("only %d pinned windows judged", judged)
		}
	})

	t.Run("another site's traffic changes nothing", func(t *testing.T) {
		_, alone := run(t, base, false)
		_, shared := run(t, base, true)
		if !reflect.DeepEqual(alone, shared) {
			t.Fatal("a second site's traffic changed this site's replay")
		}
	})
}

// warmScenario is one trained week, Monday to Sunday, then a held-out Monday.
type warmScenario struct {
	p       Params
	records []Record
	train   Span
	heldOut Span
}

func newWarmScenario() warmScenario {
	w := warmScenario{
		// A small weight keeps one attack minute from raising the night
		// slot past the attack before the next window judges it.
		p:       Params{W: 10, R: 3, F: 1, K: 5, D: 10, C: 80, Baseline: BaselineParams{Alpha: 1.0 / 64, MinObs: 60, MinAge: week, FloorPerMin: 10}},
		train:   Span{From: monday, To: monday + week - 1},
		heldOut: Span{From: monday + week, To: monday + week + 24*60 - 1},
	}
	s := NewSynth(testSite, 77)
	// Days are busy (20 a minute), nights quiet (1 a minute).
	for h := w.train.From; h <= w.heldOut.To; h += 60 {
		rate := 1
		if hod := (h / 60) % 24; hod >= 8 && hod < 20 {
			rate = 20
		}
		w.records = append(w.records, s.Pool(Traffic{From: h, To: h + 59, PerMinute: rate, L2: SynthKey(1), L1: SynthKey(2), Label: LabelHealthy}, 300)...)
	}
	// A training attack on Wednesday while every key is still young.
	wednesday := monday + 2*24*60 + 3*60
	w.records = append(w.records, s.Rotating(Traffic{From: wednesday, To: wednesday + 20, PerMinute: 300, L2: SynthKey(1), L1: SynthKey(4),
		Label: LabelAttack, Episode: "e-train"}, 1)...)
	// An attack that starts in the last training hour and runs on.
	w.records = append(w.records, s.Rotating(Traffic{From: w.train.To - 29, To: w.heldOut.From + 30, PerMinute: 300, L2: SynthKey(1), L1: SynthKey(5),
		Label: LabelAttack, Episode: "e-cross"}, 1)...)
	// A held-out night attack: only a warm profile can see it. Its window
	// never reaches three times the cold floor.
	night := w.heldOut.From + 2*60
	w.records = append(w.records, s.Rotating(Traffic{From: night, To: night + 29, PerMinute: 25, L2: SynthKey(1), L1: SynthKey(3),
		Label: LabelAttack, Episode: "e-night"}, 1)...)
	return w
}

func (w warmScenario) config() SessionConfig { return SessionConfig{Params: w.p} }

// daily feeds the training week as seven adjacent daily segments, then the
// held-out day.
func (w warmScenario) daily(t *testing.T, s *ReplaySession) []Tick {
	var ticks []Tick
	for d := w.train.From; d <= w.train.To; d += 24 * 60 {
		ticks = append(ticks, feedTicks(t, s, segment(testSite, w.records, nil, Span{From: d, To: d + 24*60 - 1}))...)
	}
	return append(ticks, feedTicks(t, s, segment(testSite, w.records, []Span{w.heldOut}, w.heldOut))...)
}

func TestReplaySessionWarmHistory(t *testing.T) {
	w := newWarmScenario()
	warm := mustSession(t, w.config())
	split := w.daily(t, warm)

	joined := feedTicks(t, mustSession(t, w.config()),
		segment(testSite, w.records, []Span{w.heldOut}, Span{From: w.train.From, To: w.heldOut.To}))
	if !reflect.DeepEqual(split, joined) {
		t.Fatal("adjacent daily segments replayed differently from one continuous segment")
	}

	bg := l1(2)
	ks := warm.sites[testSite].keys[bg]
	for i, sl := range ks.baseline.slots {
		if sl.obs < w.p.Baseline.MinObs {
			t.Fatalf("slot %d has %d observations after the training week", i, sl.obs)
		}
	}

	var scored, training []Tick
	for _, tk := range split {
		if tk.Scored {
			scored = append(scored, tk)
		} else {
			training = append(training, tk)
		}
	}
	if len(scored) != 24*60 || scored[0].Minute != w.heldOut.From {
		t.Fatalf("%d scored ticks from minute %d, want the held-out day", len(scored), scored[0].Minute)
	}
	if n := len(eventsFor(training, l1(4))); n != 1 || len(eventsFor(scored, l1(4))) != 0 {
		t.Fatalf("training attack: %d training events, want 1 and none scored", n)
	}
	if len(eventsFor(scored, bg)) != 0 || len(eventsFor(training, bg)) != 0 {
		t.Fatal("healthy traffic raised a finding")
	}
	cross := l1(5)
	if len(eventsFor(training, cross)) != 1 || len(eventsFor(scored, cross)) != 0 {
		t.Fatal("the attack crossing the boundary must transition once, in training")
	}
	if a := activeFor(scored[0], cross); a == nil || a.Since >= w.heldOut.From {
		t.Fatalf("first scored minute does not show the finding active since training: %+v", scored[0].Active)
	}
	// The night attack uses a new L1 key, cold like any new key; its trained
	// L2 parent is what a warm profile lets detect it.
	parent := bg.parent()
	nightFrom := w.heldOut.From + 2*60
	var night []FindingEvent
	for _, e := range eventsFor(scored, parent) {
		if e.Minute >= nightFrom {
			night = append(night, e)
		}
	}
	if len(night) != 1 || night[0].Minute > nightFrom+int64(w.p.W) || !night[0].Trusted {
		t.Fatalf("warm replay night attack events %+v, want one early transition judged against trained slots", night)
	}
	for _, tk := range scored {
		if e := evalOf(tk, bg); e != nil && tk.Minute%60 >= int64(w.p.W)-1 {
			hod := (tk.Minute / 60) % 24
			want := float64(w.p.W) * 1
			if hod >= 8 && hod < 20 {
				want = float64(w.p.W) * 20
			}
			if !e.Trusted || e.Expected != want {
				t.Fatalf("held-out minute %d: expected %v trusted %t, want %v from trained slots", tk.Minute-w.heldOut.From, e.Expected, e.Trusted, want)
			}
		}
	}

	t.Run("cold start is a different experiment", func(t *testing.T) {
		cold := feedTicks(t, mustSession(t, w.config()), segment(testSite, w.records, []Span{w.heldOut}, w.heldOut))
		for _, e := range eventsFor(cold, parent) {
			if e.Minute >= nightFrom && e.Minute < nightFrom+60 {
				t.Fatalf("cold replay saw the night attack its floor hides: %+v", e)
			}
		}
		for _, tk := range cold {
			if e := evalOf(tk, bg); e != nil && (e.Trusted || e.Expected != float64(w.p.W)*w.p.Baseline.FloorPerMin) {
				t.Fatalf("cold minute %d judged against %v (trusted %t), want the floor", tk.Minute-w.heldOut.From, e.Expected, e.Trusted)
			}
		}
	})

	t.Run("no held-out minute informs an earlier one", func(t *testing.T) {
		for _, cut := range []int64{0, 2*60 + 5} {
			s := mustSession(t, w.config())
			var ticks []Tick
			for d := w.train.From; d <= w.train.To; d += 24 * 60 {
				ticks = append(ticks, feedTicks(t, s, segment(testSite, w.records, nil, Span{From: d, To: d + 24*60 - 1}))...)
			}
			upTo := Span{From: w.heldOut.From, To: w.heldOut.From + cut}
			ticks = append(ticks, feedTicks(t, s, segment(testSite, w.records, []Span{w.heldOut}, upTo))...)
			if !reflect.DeepEqual(ticks[len(ticks)-1], split[len(ticks)-1]) {
				t.Fatalf("held-out minute %d depends on later minutes", cut)
			}
		}
	})

	t.Run("a real gap flushes windows and learns nothing", func(t *testing.T) {
		s := mustSession(t, w.config())
		for d := w.train.From; d <= w.train.To; d += 24 * 60 {
			feedTicks(t, s, segment(testSite, w.records, nil, Span{From: d, To: d + 24*60 - 1}))
		}
		gap := Span{From: w.heldOut.From + 5*60, To: w.heldOut.From + 6*60 - 1}
		ticks := feedTicks(t, s, segment(testSite, w.records, []Span{w.heldOut},
			Span{From: w.heldOut.From, To: gap.From - 1}, Span{From: gap.To + 1, To: w.heldOut.To}))
		for _, tk := range ticks {
			if tk.Minute >= gap.From && tk.Minute <= gap.To {
				t.Fatalf("minute %d inside the gap was ticked", tk.Minute-w.heldOut.From)
			}
			if tk.Minute > gap.To && tk.Minute < gap.To+int64(w.p.W) && (tk.Complete || len(tk.Evaluations) > 0) {
				t.Fatalf("minute %d judged before a complete window after the gap", tk.Minute-w.heldOut.From)
			}
		}
		gapSlot := slotOf(t, s, testSite, bg, gap.From)
		if full := slotOf(t, warm, testSite, bg, gap.From); gapSlot.obs != full.obs-60 {
			t.Fatalf("gap hour slot has %d observations, want the %d of the uninterrupted run less its 60 gap minutes", gapSlot.obs, full.obs)
		}
	})
}

func TestReplayGapAndRestore(t *testing.T) {
	cold := Params{W: 5, R: 3, F: 1, K: 2, D: 4, C: 80, Baseline: BaselineParams{Alpha: 0.5, MinObs: 1, MinAge: 1 << 40, FloorPerMin: 1}}
	start := monday + 9*60
	attack := l1(3)
	traffic := func(seed uint64, attacks ...Span) []Record {
		s := NewSynth(testSite, seed)
		recs := s.Pool(Traffic{From: start, To: start + 119, PerMinute: 2, L2: SynthKey(1), L1: SynthKey(2), Label: LabelHealthy}, 3)
		for _, a := range attacks {
			recs = append(recs, s.Rotating(Traffic{From: a.From, To: a.To, PerMinute: 50, L2: SynthKey(1), L1: SynthKey(3),
				Label: LabelAttack, Episode: "e1"}, 1)...)
		}
		return recs
	}

	t.Run("unknown gap keeps the finding", func(t *testing.T) {
		recs := traffic(1, Span{From: start, To: start + 69})
		for name, feed := range map[string]func(*ReplaySession) []Tick{
			"one segment": func(s *ReplaySession) []Tick {
				return feedTicks(t, s, segment(testSite, recs, nil, Span{From: start, To: start + 29}, Span{From: start + 40, To: start + 69}))
			},
			"two segments": func(s *ReplaySession) []Tick {
				a := feedTicks(t, s, segment(testSite, recs, nil, Span{From: start, To: start + 29}))
				return append(a, feedTicks(t, s, segment(testSite, recs, nil, Span{From: start + 40, To: start + 69}))...)
			},
		} {
			ticks := feed(mustSession(t, SessionConfig{Params: cold}))
			events := eventsFor(ticks, attack)
			if len(events) != 1 || events[0].Minute != start+4 {
				t.Fatalf("%s: events %+v, want one transition at minute 4", name, events)
			}
			for _, tk := range ticks {
				a := activeFor(tk, attack)
				switch off := tk.Minute - start; {
				case off < 4:
				case a == nil:
					t.Fatalf("%s: minute %d lost the finding", name, off)
				case off >= 40 && off < 44 && !a.Uncertain:
					t.Fatalf("%s: minute %d after the gap claims certain evidence", name, off)
				case off >= 44 && a.Uncertain:
					t.Fatalf("%s: minute %d still uncertain after a complete window", name, off)
				}
			}
		}
	})

	t.Run("known quiet window clears the finding", func(t *testing.T) {
		recs := traffic(2, Span{From: start, To: start + 19}, Span{From: start + 40, To: start + 59})
		ticks := feedTicks(t, mustSession(t, SessionConfig{Params: cold}), segment(testSite, recs, nil, Span{From: start, To: start + 79}))
		events := eventsFor(ticks, attack)
		if len(events) != 2 || events[0].Minute != start+4 || events[1].Minute != start+40 {
			t.Fatalf("events %+v, want transitions at minutes 4 and 40", events)
		}
		for _, tk := range ticks {
			if tk.Minute == start+30 && activeFor(tk, attack) != nil {
				t.Fatal("finding still active after a complete quiet window")
			}
		}
	})

	trained := cold
	trained.Baseline = BaselineParams{Alpha: 0.5, MinObs: 1, MinAge: 0, FloorPerMin: 1}
	sk := &SketchParams{M: 8, H: 16, Seed: 3}
	cfg := SessionConfig{Params: trained, Sketch: sk, Shuffle: 5, IdentityVersion: 1}
	recs := traffic(3, Span{From: start + 45, To: start + 60})
	// An idle key active only early and late must learn its idle minutes
	// across the restore exactly as without one.
	idle := NewSynth(testSite, 4).Pool(Traffic{From: start, To: start + 10, PerMinute: 3, L2: SynthKey(1), L1: SynthKey(6), Label: LabelHealthy}, 2)
	idle = append(idle, NewSynth(testSite, 5).Pool(Traffic{From: start + 70, To: start + 80, PerMinute: 3, L2: SynthKey(1), L1: SynthKey(6), Label: LabelHealthy}, 2)...)
	recs = append(recs, idle...)
	first, second := Span{From: start, To: start + 49}, Span{From: start + 50, To: start + 99}

	whole := mustSession(t, cfg)
	feedTicks(t, whole, segment(testSite, recs, nil, first))
	raw, err := whole.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if a := whole.sites[testSite].keys[attack]; a == nil || a.finding == nil {
		t.Fatal("scenario needs a finding active at the snapshot")
	}
	want := feedTicks(t, whole, segment(testSite, recs, nil, second))

	t.Run("restore equals uninterrupted replay", func(t *testing.T) {
		restored, inv, err := Restore(raw, cfg)
		if err != nil || inv != (Invalidation{}) {
			t.Fatalf("restore: %v %+v", err, inv)
		}
		if got := feedTicks(t, restored, segment(testSite, recs, nil, second)); !reflect.DeepEqual(got, want) {
			t.Fatal("restored session diverged from the uninterrupted one")
		}
		a, errA := restored.Snapshot()
		b, errB := whole.Snapshot()
		if errA != nil || errB != nil || string(a) != string(b) {
			t.Fatal("restored and uninterrupted sessions hold different state")
		}
	})

	pinOf := func(s *ReplaySession) Profile { return s.sites[testSite].keys[attack].finding.pin }
	for _, tc := range []struct {
		name        string
		edit        func(*SessionConfig)
		hashVersion bool
		inv         Invalidation
		first       int64 // first complete minute after the restore
	}{
		{name: "hash version", hashVersion: true, edit: func(*SessionConfig) {}, inv: Invalidation{Windows: true}, first: second.From + 4},
		{name: "window", edit: func(c *SessionConfig) { c.Params.W = 6 }, inv: Invalidation{Windows: true}, first: second.From + 5},
		{name: "identity", edit: func(c *SessionConfig) { c.IdentityVersion = 2 }, inv: Invalidation{Windows: true, Baselines: true, Identity: true}, first: second.From + 4},
		{name: "sampling seed", edit: func(c *SessionConfig) { c.Sketch = &SketchParams{M: 8, H: 16, Seed: 4} }, inv: Invalidation{Windows: true}, first: second.From + 4},
		{name: "summary size", edit: func(c *SessionConfig) { c.Sketch = &SketchParams{M: 9, H: 16, Seed: 3} }, inv: Invalidation{Windows: true}, first: second.From + 4},
		{name: "baseline semantics", edit: func(c *SessionConfig) { c.Params.Baseline.Alpha = 0.25 }, inv: Invalidation{Windows: true, Baselines: true}, first: second.From + 4},
		{name: "cardinality size", edit: func(c *SessionConfig) { c.Sketch = &SketchParams{M: 8, H: 17, Seed: 3} }, inv: Invalidation{Windows: true}, first: second.From + 4},
		{name: "exact mode", edit: func(c *SessionConfig) { c.Sketch = nil }, inv: Invalidation{Windows: true}, first: second.From + 4},
		{name: "thresholds", edit: func(c *SessionConfig) { c.Params.R, c.Params.F, c.Params.K, c.Params.D, c.Params.C = 4, 2, 1, 6, 90 }, inv: Invalidation{}, first: second.From},
		{name: "shuffle", edit: func(c *SessionConfig) { c.Shuffle++ }, inv: Invalidation{}, first: second.From},
	} {
		t.Run("incompatible "+tc.name, func(t *testing.T) {
			next := cfg
			tc.edit(&next)
			input := raw
			if tc.hashVersion {
				input = []byte(strings.Replace(string(raw), bindingHashPurpose, "previous binding hash", 1))
			}
			restored, inv, err := Restore(input, next)
			if err != nil || inv != tc.inv {
				t.Fatalf("restore: %v %+v, want %+v", err, inv, tc.inv)
			}
			again, snapshotErr := restored.Snapshot()
			if snapshotErr != nil {
				t.Fatal(snapshotErr)
			}
			roundtrip := mustRestore(t, again, next)
			if got := pinOf(roundtrip); got != pinOf(restored) {
				t.Fatal("second restore changed the pin")
			}
			same := mustRestore(t, raw, cfg).sites[testSite]
			for id, ks := range restored.sites[testSite].keys {
				switch {
				case tc.inv.Baselines && ks.baseline.slots != [168]slot{}:
					t.Fatalf("key %+v kept invalidated history", id)
				case !tc.inv.Baselines && ks.baseline.slots != same.keys[id].baseline.slots:
					t.Fatalf("key %+v lost compatible history", id)
				}
			}
			if !tc.inv.Baselines && !reflect.DeepEqual(pinOf(restored), pinOf(mustRestore(t, raw, cfg))) {
				t.Fatal("a compatible change rewrote the pinned profile")
			}
			ticks := feedTicks(t, restored, segment(testSite, recs, nil, second))
			if resumed := feedTicks(t, roundtrip, segment(testSite, recs, nil, second)); !reflect.DeepEqual(resumed, ticks) {
				t.Fatal("snapshot after invalidation changed the continuation")
			}
			for _, tk := range ticks {
				if tk.Minute < tc.first && (tk.Complete || len(tk.Evaluations) > 0) {
					t.Fatalf("minute %d judged before a complete new window", tk.Minute-second.From)
				}
				if tk.Minute == tc.first && !tk.Complete {
					t.Fatalf("minute %d is not complete", tk.Minute-second.From)
				}
				a := activeFor(tk, attack)
				if tk.Minute < tc.first && (a == nil || !a.Uncertain) && tc.inv != (Invalidation{}) {
					t.Fatalf("minute %d: finding %+v, want it kept and uncertain", tk.Minute-second.From, a)
				}
			}
			if n := len(eventsFor(ticks, attack)); n != 0 {
				t.Fatalf("restore produced %d duplicate transitions", n)
			}
			_ = ticks
		})
	}

	t.Run("evicted, reintroduced and never seen keys", func(t *testing.T) {
		s := mustRestore(t, raw, cfg)
		bg := l1(2)
		for name, id := range map[string]KeyID{"site key": {Level: 3}, "active finding": attack, "unknown key": l1(9)} {
			if err := s.Evict(testSite, id); !errors.Is(err, ErrSession) {
				t.Fatalf("evicting %s: %v, want ErrSession", name, err)
			}
		}
		if err := s.Evict("dom-ffffff.example", bg); !errors.Is(err, ErrSession) {
			t.Fatalf("evicting from an unknown site: %v", err)
		}
		if err := s.Evict(testSite, bg); err != nil {
			t.Fatal(err)
		}
		// Both keys attack from the first minute after the restore; the
		// reintroduced one must wait for W observed minutes of its own.
		syn := NewSynth(testSite, 12)
		more := slices.Clone(recs)
		for _, n := range []uint64{2, 7} {
			more = append(more, syn.Rotating(Traffic{From: second.From, To: second.From + 20, PerMinute: 60, L2: SynthKey(1), L1: SynthKey(n),
				Label: LabelAttack, Episode: "e2"}, 1)...)
		}
		ticks := feedTicks(t, s, segment(testSite, more, nil, second))
		fresh, back := eventsFor(ticks, l1(7)), eventsFor(ticks, bg)
		if len(fresh) != 1 || fresh[0].Minute != second.From {
			t.Fatalf("never-seen key events %+v, want one at the first minute", fresh)
		}
		if len(back) != 1 || back[0].Minute != second.From+int64(trained.W)-1 || back[0].Trusted {
			t.Fatalf("reintroduced key events %+v, want one cold transition after W minutes", back)
		}
		for _, tk := range ticks[:trained.W-1] {
			if evalOf(tk, bg) != nil {
				t.Fatalf("minute %d judged the reintroduced key early", tk.Minute-second.From)
			}
		}
	})
}

func mustRestore(t *testing.T, raw []byte, cfg SessionConfig) *ReplaySession {
	t.Helper()
	s, _, err := Restore(raw, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestReplaySessionContract(t *testing.T) {
	p := Params{W: 3, R: 3, F: 1, K: 1, D: 2, C: 80, Baseline: BaselineParams{Alpha: 0.5, MinObs: 1, FloorPerMin: 1}}
	start := monday + 60
	recs := NewSynth(testSite, 1).Pool(Traffic{From: start, To: start + 29, PerMinute: 3, L2: SynthKey(1), L1: SynthKey(2), Label: LabelHealthy}, 3)
	// The first segment declares its state beyond its coverage, as a bundle
	// period can outlast its certified minutes.
	fresh := func(t *testing.T) *ReplaySession {
		s := mustSession(t, SessionConfig{Params: p, Sketch: &SketchParams{M: 2, H: 3, Seed: 1}})
		first := segment(testSite, recs, nil, Span{From: start, To: start + 9})
		first.States = append(first.States, StateSpan{From: start + 10, To: start + 10, State: StateProtected})
		feedTicks(t, s, first)
		return s
	}
	next := Span{From: start + 11, To: start + 20}

	for name, change := range map[string]func(*ReplaySegment){
		"coverage before the history": func(g *ReplaySegment) { g.Coverage = []Span{{From: start + 9, To: next.To}} },
		"unknown state":               func(g *ReplaySegment) { g.States[0].State = "idle" },
		"state before the history":    func(g *ReplaySegment) { g.States[0].From = start + 9 },
		"overlapping site states": func(g *ReplaySegment) {
			g.States = append(g.States, StateSpan{From: next.To, To: next.To + 5, State: StateProtected})
		},
		"overlapping key states": func(g *ReplaySegment) {
			k := l1(2)
			g.States = append(g.States, StateSpan{Key: &k, From: next.From, To: next.From + 2, State: StateProtected},
				StateSpan{Key: &k, From: next.From + 2, To: next.To, State: StateNormal})
		},
		"state overlapping an earlier declaration": func(g *ReplaySegment) {
			g.States = []StateSpan{{From: start + 10, To: next.To, State: StateNormal}}
		},
		"malformed state key": func(g *ReplaySegment) {
			g.States = append(g.States, StateSpan{Key: &KeyID{Level: 2}, From: next.From, To: next.To, State: StateNormal})
		},
		"unsorted scoring spans": func(g *ReplaySegment) {
			g.Score = []Span{{From: next.From + 5, To: next.To}, {From: next.From, To: next.From + 1}}
		},
		"empty scoring span": func(g *ReplaySegment) { g.Score = []Span{{From: next.To, To: next.From}} },
		"record of another site": func(g *ReplaySegment) {
			g.Records = append(g.Records, recs[0])
			g.Records[len(g.Records)-1].Site = "dom-ffffff.example"
		},
		"record outside coverage": func(g *ReplaySegment) { g.Records = append(g.Records, recs[len(recs)-1]) },
		"segment for a bad site":  func(g *ReplaySegment) { g.Site = "example.com" },
		"overlapping coverage": func(g *ReplaySegment) {
			g.Coverage = []Span{{From: next.From, To: next.From + 5}, {From: next.From + 5, To: next.To}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := fresh(t)
			before, err := s.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			seg := segment(testSite, recs, nil, next)
			change(&seg)
			calls := 0
			err = s.Feed(seg, func(Tick) error { calls++; return nil })
			if !errors.Is(err, ErrSession) && !errors.Is(err, ErrSite) || calls != 0 {
				t.Fatalf("%v after %d callbacks, want a refusal before any", err, calls)
			}
			after, err := s.Snapshot()
			if err != nil || string(after) != string(before) {
				t.Fatal("a refused segment changed the session")
			}
			feedTicks(t, s, segment(testSite, recs, nil, next))
		})
	}

	t.Run("a failed callback ends the session", func(t *testing.T) {
		s := fresh(t)
		stop := errors.New("stop")
		if err := s.Feed(segment(testSite, recs, nil, next), func(Tick) error { return stop }); !errors.Is(err, stop) {
			t.Fatalf("Feed returned %v, want the callback's error", err)
		}
		if err := s.Feed(segment(testSite, recs, nil, Span{From: next.To + 1, To: next.To + 2}), func(Tick) error { return nil }); !errors.Is(err, ErrSession) {
			t.Fatalf("broken session accepted a segment: %v", err)
		}
		if _, err := s.Snapshot(); !errors.Is(err, ErrSession) {
			t.Fatalf("broken session was snapshotted: %v", err)
		}
		if err := s.Evict(testSite, l1(2)); !errors.Is(err, ErrSession) {
			t.Fatalf("broken session evicted: %v", err)
		}
	})

	t.Run("configuration", func(t *testing.T) {
		for name, cfg := range map[string]SessionConfig{
			"params":           {Params: Params{W: 0, R: 3, F: 1, K: 1, D: 2, C: 80, Baseline: p.Baseline}},
			"counters":         {Params: p, Sketch: &SketchParams{M: p.K, H: 3}},
			"hashes":           {Params: p, Sketch: &SketchParams{M: 2, H: p.D + p.K - 1}},
			"identity version": {Params: p, IdentityVersion: -1},
		} {
			if _, err := NewReplaySession(cfg); !errors.Is(err, ErrParams) {
				t.Errorf("%s: %v, want ErrParams", name, err)
			}
			if _, _, err := Restore([]byte(`{}`), cfg); !errors.Is(err, ErrParams) {
				t.Errorf("restore under bad %s: %v, want ErrParams", name, err)
			}
		}
		s := mustSession(t, SessionConfig{Params: p, Sketch: &SketchParams{M: 2, H: 3, Hash: letterHash}})
		if _, err := s.Snapshot(); !errors.Is(err, ErrSession) {
			t.Fatalf("snapshot with a test hash: %v, want ErrSession", err)
		}
	})

	t.Run("damaged snapshots", func(t *testing.T) {
		s := fresh(t)
		raw, err := s.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		cfg := s.cfg
		if _, _, err := Restore(raw, cfg); err != nil {
			t.Fatalf("intact snapshot refused: %v", err)
		}
		for name, damage := range map[string]func(*sessionSnapshot){
			"format version":          func(v *sessionSnapshot) { v.FormatVersion = 2 },
			"hash version":            func(v *sessionSnapshot) { v.HashVersion = "" },
			"stored parameters":       func(v *sessionSnapshot) { v.Params.D = v.Params.K },
			"duplicate site":          func(v *sessionSnapshot) { v.Sites = append(v.Sites, v.Sites[0]) },
			"missing coverage":        func(v *sessionSnapshot) { v.Sites[0].Covered = []Span{} },
			"coverage past history":   func(v *sessionSnapshot) { v.Sites[0].Covered[0].To++ },
			"window before coverage":  func(v *sessionSnapshot) { v.Sites[0].WindowFrom = v.Sites[0].CoveredFrom - 1 },
			"overlapping states":      func(v *sessionSnapshot) { v.Sites[0].States = append(v.Sites[0].States, v.Sites[0].States[0]) },
			"malformed key":           func(v *sessionSnapshot) { v.Sites[0].Keys[0].Key.Key = "k-1" },
			"slot out of range":       func(v *sessionSnapshot) { v.Sites[0].Keys[0].Slots[0].Slot = 168 },
			"slot learned in future":  func(v *sessionSnapshot) { v.Sites[0].Keys[0].Slots[0].Last = v.Sites[0].ProcessedTo + 60 },
			"negative mean":           func(v *sessionSnapshot) { v.Sites[0].Keys[0].Slots[0].Mean = -1 },
			"minute outside window":   func(v *sessionSnapshot) { v.Sites[0].Keys[0].Minutes[0].Minute -= int64(p.W) },
			"labels disagree":         func(v *sessionSnapshot) { v.Sites[0].Keys[0].Minutes[0].Total++ },
			"binding not a pseudonym": func(v *sessionSnapshot) { v.Sites[0].Keys[0].Minutes[0].Bindings[0].Name = "192.0.2.1" },
			"window count overflow": func(v *sessionSnapshot) {
				k := &v.Sites[0].Keys[0]
				for i := range k.Minutes {
					m := &k.Minutes[i]
					m.Total, m.Expensive = 1<<63-1, 1<<63-1
					m.Bindings = []countSnapshot{{Name: m.Bindings[0].Name, N: m.Total}}
					m.Labels = []countSnapshot{{Name: LabelHealthy, N: m.Total}}
					k.Sketches[i].Summary = sketchState{Bound: m.Total,
						Entries: []sketchEntry{{Binding: m.Bindings[0].Name, Count: m.Total}}, Hashes: []uint64{v.Sketch.hash(m.Bindings[0].Name)}}
				}
			},
			"invented hashes": func(v *sessionSnapshot) {
				v.Sites[0].Keys[0].Sketches[0].Summary.Hashes = []uint64{1, 2, 3}
			},
			"understated counter": func(v *sessionSnapshot) {
				m := &v.Sites[0].Keys[0].Minutes[0]
				// Keep every retained identity and the total, but put more
				// requests under the first counter than its upper bound.
				es := v.Sites[0].Keys[0].Sketches[0].Summary.Entries
				if len(es) != 2 || es[0].Count+es[1].Count != 3 {
					t.Fatal("scenario needs one counter of one and one of two")
				}
				a, b := es[0].Binding, es[1].Binding
				if es[0].Count > es[1].Count {
					a, b = b, a
				}
				m.Bindings = []countSnapshot{{Name: a, N: 2}, {Name: b, N: 1}}
				witness := &bottomH{h: v.Sketch.H}
				for _, binding := range m.Bindings {
					witness.add(v.Sketch.hash(binding.Name))
				}
				v.Sites[0].Keys[0].Sketches[0].Summary.Hashes = witness.hashes
			},
			"summary bound":   func(v *sessionSnapshot) { v.Sites[0].Keys[0].Sketches[0].Summary.Bound++ },
			"summary missing": func(v *sessionSnapshot) { v.Sites[0].Keys[0].Sketches = v.Sites[0].Keys[0].Sketches[1:] },
			"finding in the future": func(v *sessionSnapshot) {
				v.Sites[0].Keys[0].Finding = &findingSnapshot{Since: v.Sites[0].ProcessedTo + 1, PinFirst: v.Sites[0].Keys[0].First, PinSlots: []slotSnapshot{}}
			},
			"retired and present": func(v *sessionSnapshot) { v.Sites[0].Retired = append(v.Sites[0].Retired, v.Sites[0].Keys[1].Key) },
		} {
			var v sessionSnapshot
			if err := DecodeStrictJSON(raw, &v); err != nil {
				t.Fatal(err)
			}
			damage(&v)
			b, err := json.Marshal(v)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := Restore(b, cfg); !errors.Is(err, ErrSession) {
				t.Errorf("%s: %v, want ErrSession", name, err)
			}
		}
		for name, b := range map[string]string{
			"unknown member": strings.Replace(string(raw), `"shuffle"`, `"shuffled"`, 1),
			"trailing data":  string(raw) + "{}",
			"not JSON":       "snapshot",
		} {
			if _, _, err := Restore([]byte(b), cfg); !errors.Is(err, ErrSession) {
				t.Errorf("%s: %v, want ErrSession", name, err)
			}
		}
	})
}

// A semantics reset starts history at the next minute, even for an idle key.
func TestRestoreDoesNotLearnBeforeReset(t *testing.T) {
	p := Params{W: 2, R: 3, F: 1, K: 1, D: 2, C: 80,
		Baseline: BaselineParams{Alpha: 0.5, MinObs: 1, FloorPerMin: 1}}
	cfg := SessionConfig{Params: p}
	start := int64(29_900_000) / 60 * 60
	records := NewSynth(testSite, 1).Pool(Traffic{From: start, To: start + 2, PerMinute: 1,
		L2: SynthKey(1), L1: SynthKey(2), Label: LabelHealthy}, 1)
	s := mustSession(t, cfg)
	feedTicks(t, s, segment(testSite, records, nil, Span{From: start, To: start + 20}))
	raw, err := s.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Params.Baseline.Alpha = 0.25
	s = mustRestore(t, raw, cfg)
	back := start + 21
	records = NewSynth(testSite, 2).Pool(Traffic{From: back, To: back, PerMinute: 1,
		L2: SynthKey(1), L1: SynthKey(2), Label: LabelHealthy}, 1)
	feedTicks(t, s, segment(testSite, records, nil, Span{From: back, To: back}))
	if got := slotOf(t, s, testSite, l1(2), back); got != (slot{}) {
		t.Fatalf("unjudged traffic or pre-reset silence trained the new baseline: %+v", got)
	}
	raw, err = s.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	mustRestore(t, raw, cfg)
}

func TestRestoreIdentityDropsKeyDeclarations(t *testing.T) {
	p := Params{W: 2, R: 3, F: 1, K: 1, D: 2, C: 80,
		Baseline: BaselineParams{Alpha: 0.5, MinObs: 1, FloorPerMin: 1}}
	cfg := SessionConfig{Params: p, IdentityVersion: 1}
	s := mustSession(t, cfg)
	key := l1(2)
	start := int64(29_900_000) / 60 * 60
	seg := segment(testSite, nil, nil, Span{From: start, To: start})
	seg.States = append(seg.States, StateSpan{Key: &key, From: start, To: start + 10, State: StateProtected})
	feedTicks(t, s, seg)
	raw, err := s.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	cfg.IdentityVersion++
	s = mustRestore(t, raw, cfg)
	recs := NewSynth(testSite, 1).Pool(Traffic{From: start + 1, To: start + 3, PerMinute: 1,
		L2: SynthKey(1), L1: SynthKey(2), Label: LabelHealthy}, 1)
	feedTicks(t, s, segment(testSite, recs, nil, Span{From: start + 1, To: start + 3}))
	if got := slotOf(t, s, testSite, key, start); got.obs != 2 || got.mean != 1 {
		t.Fatalf("old identity declaration froze a new key: %+v", got)
	}
}
