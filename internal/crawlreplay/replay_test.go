package crawlreplay

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"
)

const fixtureStart = int64(29_833_000) // a Unix minute in 2026

// fixtureParams keeps every fixture key younger than MinAge, so windows are
// judged against the fixed floor as a cold key would be.
func fixtureParams() Params {
	return Params{W: 10, R: 3, F: 5, K: 20, D: 50, C: 80,
		Baseline: BaselineParams{Alpha: 0.1, MinObs: 1, MinAge: 7 * 24 * 60, FloorPerMin: 1}}
}

// fixtureSite trains a background key for 100 minutes, then adds an attack
// on another L1 key under the same L2 from minute 100 to 129.
func fixtureSite(q int, extra func(s *Synth) []Record) Site {
	s := NewSynth(testSite, 7)
	cat, bg, attack := SynthKey(1), SynthKey(2), SynthKey(3)
	recs := s.Pool(Traffic{From: fixtureStart, To: fixtureStart + 139, PerMinute: 2, L2: cat, L1: bg, Label: LabelHealthy}, 10)
	recs = append(recs, s.Rotating(Traffic{From: fixtureStart + 100, To: fixtureStart + 129, PerMinute: 300,
		L2: cat, L1: attack, Label: LabelAttack, Episode: "e1"}, q)...)
	if extra != nil {
		recs = append(recs, extra(s)...)
	}
	return Site{Records: recs, Coverage: []Span{{From: fixtureStart, To: fixtureStart + 139}}}
}

func TestOneThreeTwentyRequestsPerBindingAllDetect(t *testing.T) {
	p := fixtureParams()
	for _, q := range []int{1, 3, 20} {
		rep, err := EvaluateSite(fixtureSite(q, nil), p, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if len(rep.Episodes) != 1 || !rep.Episodes[0].Detected {
			t.Fatalf("q=%d: episode not detected: %+v", q, rep.Episodes)
		}
		if d := rep.Episodes[0].DelaySeconds; d <= 0 || d > int64(p.W+1)*60 {
			t.Fatalf("q=%d: delay %ds outside one window", q, d)
		}
		if rep.FalsePositives[fixtureStart/1440] != 0 || rep.Transitions[LabelHealthy] != 0 {
			t.Fatalf("q=%d: healthy traffic raised findings: %+v", q, rep.Transitions)
		}
	}
}

func TestExactResidualOfThreeRequestClients(t *testing.T) {
	p := fixtureParams()
	var got *Evaluation
	err := ReplaySite(fixtureSite(3, nil), p, Options{}, func(tk Tick) {
		if tk.Minute != fixtureStart+101 {
			return
		}
		for i := range tk.Evaluations {
			if tk.Evaluations[i].Key == (KeyID{Level: 1, Key: SynthKey(3), Parent: SynthKey(1)}) {
				got = &tk.Evaluations[i]
			}
		}
	})
	if err != nil || got == nil {
		t.Fatalf("attack key not evaluated: %v", err)
	}
	// 600 requests from 200 clients of 3: removing 20 clients leaves 540 and 180.
	if got.Total != 600 || got.ExactResidual != 540 || got.ExactDistinct != 180 || !got.Anomalous {
		t.Fatalf("evaluation = %+v", got)
	}
}

func TestPaddingAndChurnKeepExactDetection(t *testing.T) {
	p := fixtureParams()
	attack := func(s *Synth, churn bool) []Record {
		return s.Heavy(Traffic{From: fixtureStart + 100, To: fixtureStart + 129, L2: SynthKey(1), L1: SynthKey(3),
			Label: LabelAttack, Episode: "e1"}, p.K, 200, churn)
	}
	for _, churn := range []bool{false, true} {
		rep, err := EvaluateSite(fixtureSite(3, func(s *Synth) []Record { return attack(s, churn) }), p, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if !rep.Episodes[0].Detected {
			t.Fatalf("churn=%v: padding hid the attack", churn)
		}
	}
}

func TestSketchBoundsStaySoundUnderChurn(t *testing.T) {
	p := fixtureParams()
	site := fixtureSite(3, func(s *Synth) []Record {
		return s.Heavy(Traffic{From: fixtureStart + 100, To: fixtureStart + 129, L2: SynthKey(1), L1: SynthKey(3),
			Label: LabelAttack, Episode: "e1"}, 40, 50, true)
	})
	for _, sk := range []SketchParams{{M: 21, H: 70, Seed: 1}, {M: 256, H: 512, Seed: 1}} {
		for _, shuffle := range []uint64{0, 99} {
			rep, err := EvaluateSite(site, p, Options{Sketch: &sk, Shuffle: shuffle})
			if err != nil {
				t.Fatal(err)
			}
			if rep.Sketch.Exceeded != 0 {
				t.Fatalf("m=%d shuffle=%d: %d bounds above exact", sk.M, shuffle, rep.Sketch.Exceeded)
			}
		}
	}
}

func TestHealthySpikeCountsAsFalsePositiveOncePerTransition(t *testing.T) {
	p := fixtureParams()
	site := fixtureSite(1, nil)
	s := NewSynth(testSite, 9)
	site.Records = s.Rotating(Traffic{From: fixtureStart + 50, To: fixtureStart + 70, PerMinute: 300,
		L2: SynthKey(4), L1: SynthKey(5), Label: LabelHealthy}, 1)
	site.Records = append(site.Records, s.Pool(Traffic{From: fixtureStart, To: fixtureStart + 139, PerMinute: 1, Label: LabelHealthy}, 3)...)
	rep, err := EvaluateSite(site, p, Options{})
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, n := range rep.FalsePositives {
		total += n
	}
	if total == 0 || total != rep.Transitions[LabelHealthy] {
		t.Fatalf("false positives %v, healthy transitions %d", rep.FalsePositives, rep.Transitions[LabelHealthy])
	}
	// One spike moves three keys (site, L2, L1) into the anomalous state once each.
	if total != 3 {
		t.Fatalf("healthy spike produced %d transitions, want 3", total)
	}
}

func TestLearningFreezesDuringAnomaly(t *testing.T) {
	p := fixtureParams()
	s := NewSynth(testSite, 3)
	recs := s.Pool(Traffic{From: fixtureStart, To: fixtureStart + 299, PerMinute: 2, L2: SynthKey(1), L1: SynthKey(2)}, 10)
	recs = append(recs, s.Rotating(Traffic{From: fixtureStart + 60, To: fixtureStart + 299, PerMinute: 200,
		L2: SynthKey(1), L1: SynthKey(3), Label: LabelAttack, Episode: "e1"}, 1)...)
	site := Site{Records: recs, Coverage: []Span{{From: fixtureStart, To: fixtureStart + 299}}}
	var last Evaluation
	if err := ReplaySite(site, p, Options{}, func(tk Tick) {
		for _, e := range tk.Evaluations {
			if e.Key.Level == 1 && e.Key.Key == SynthKey(3) {
				last = e
			}
		}
	}); err != nil {
		t.Fatal(err)
	}
	if !last.Anomalous || last.Expected != float64(p.W)*p.Baseline.FloorPerMin {
		t.Fatalf("four hours of attack trained the baseline: %+v", last)
	}
}

func TestCoverageGapRestartsWindows(t *testing.T) {
	p := fixtureParams()
	s := NewSynth(testSite, 4)
	recs := s.Pool(Traffic{From: fixtureStart, To: fixtureStart + 19, PerMinute: 5}, 4)
	recs = append(recs, s.Pool(Traffic{From: fixtureStart + 40, To: fixtureStart + 59, PerMinute: 5}, 4)...)
	site := Site{Records: recs, Coverage: []Span{{From: fixtureStart, To: fixtureStart + 19}, {From: fixtureStart + 40, To: fixtureStart + 59}}}
	var minutes []int64
	if err := ReplaySite(site, p, Options{}, func(tk Tick) { minutes = append(minutes, tk.Minute) }); err != nil {
		t.Fatal(err)
	}
	for _, m := range minutes {
		if (m > fixtureStart+19 && m < fixtureStart+49) || m < fixtureStart+9 {
			t.Fatalf("minute %d evaluated without a complete covered window", m-fixtureStart)
		}
	}
	if len(minutes) != 22 {
		t.Fatalf("evaluated %d minutes, want 11 per span", len(minutes))
	}
}

func TestAdjacentCoveragePreservesReplay(t *testing.T) {
	p := fixtureParams()
	joined := fixtureSite(3, nil)
	split := joined
	split.Coverage = []Span{
		{From: fixtureStart, To: fixtureStart + 3},
		{From: fixtureStart + 4, To: fixtureStart + 7},
		{From: fixtureStart + 8, To: fixtureStart + 103},
		{From: fixtureStart + 104, To: fixtureStart + 105},
		{From: fixtureStart + 106, To: fixtureStart + 139},
	}
	for name, options := range map[string]Options{
		"exact":  {},
		"sketch": {Sketch: &SketchParams{M: 32, H: 128, Seed: 5}, Shuffle: 11},
	} {
		t.Run(name, func(t *testing.T) {
			replay := func(site Site) []Tick {
				t.Helper()
				var ticks []Tick
				if err := ReplaySite(site, p, options, func(tk Tick) { ticks = append(ticks, tk) }); err != nil {
					t.Fatal(err)
				}
				return ticks
			}
			want, got := replay(joined), replay(split)
			if len(want) != 140-p.W+1 {
				t.Fatalf("joined replay has %d ticks", len(want))
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("adjacent spans changed replay: split %d ticks, joined %d", len(got), len(want))
			}
		})
	}
}

func TestSelectScope(t *testing.T) {
	l2 := KeyID{Level: 2, Key: "k2"}
	l1a := KeyID{Level: 1, Key: "k1a", Parent: "k2"}
	l1b := KeyID{Level: 1, Key: "k1b", Parent: "k2"}
	site := KeyID{Level: 3}
	// Every request here has a query, so each key's total is expensive.
	ev := func(id KeyID, total int64, anomalous bool) Evaluation {
		return Evaluation{Key: id, Total: total, Expensive: total, Anomalous: anomalous}
	}
	for name, tc := range map[string]struct {
		evals []Evaluation
		level uint8
		keys  []KeyID
	}{
		"narrow L1":  {[]Evaluation{ev(site, 1000, false), ev(l2, 900, true), ev(l1a, 850, true), ev(l1b, 50, false)}, 1, []KeyID{l1a}},
		"widen L2":   {[]Evaluation{ev(l2, 900, true), ev(l1a, 300, true), ev(l1b, 600, false)}, 2, []KeyID{l2}},
		"site only":  {[]Evaluation{ev(site, 1000, true), ev(l2, 100, false)}, 3, []KeyID{site}},
		"no anomaly": {[]Evaluation{ev(site, 1000, false)}, 0, nil},
	} {
		got := selectScope(tc.evals, 80, nil)
		if got.Level != tc.level || !reflect.DeepEqual(got.Keys, tc.keys) {
			t.Errorf("%s: scope %+v, want level %d keys %v", name, got, tc.level, tc.keys)
		}
	}
}

func TestClassifyMajority(t *testing.T) {
	for want, labels := range map[string]map[string]int64{
		LabelAttack:   {"attack/e2": 3, "attack/e1": 3, "healthy": 4},
		LabelOverload: {"overload/o1": 5, "": 5},
		LabelHealthy:  {"healthy": 6, "attack/e1": 4},
		"unlabeled":   {"healthy": 4, "": 6},
	} {
		var total int64
		for _, n := range labels {
			total += n
		}
		got, ep := classify(Evaluation{Total: total, Labels: labels})
		if got != want || (want == LabelAttack && ep != "e1") {
			t.Errorf("%v: classify = %s/%s, want %s", labels, got, ep, want)
		}
	}
}

func TestReplayRefusesBadInput(t *testing.T) {
	p := fixtureParams()
	good := fixtureSite(1, nil)
	mixed := fixtureSite(1, nil)
	mixed.Records[5].Site = "dom-ffffff.example"
	outside := fixtureSite(1, nil)
	outside.Coverage = []Span{{From: fixtureStart + 1, To: fixtureStart + 139}}
	overlap := fixtureSite(1, nil)
	overlap.Coverage = []Span{{From: fixtureStart, To: fixtureStart + 70}, {From: fixtureStart + 70, To: fixtureStart + 139}}
	for name, site := range map[string]Site{"mixed sites": mixed, "outside coverage": outside, "overlapping spans": overlap} {
		if err := ReplaySite(site, p, Options{}, func(Tick) {}); !errors.Is(err, ErrSite) {
			t.Errorf("%s: %v, want ErrSite", name, err)
		}
	}
	bad := p
	bad.D = bad.K
	if err := ReplaySite(good, bad, Options{}, func(Tick) {}); !errors.Is(err, ErrParams) {
		t.Errorf("D <= K: %v, want ErrParams", err)
	}
	if err := ReplaySite(good, p, Options{Sketch: &SketchParams{M: p.K, H: p.D + p.K}}, func(Tick) {}); !errors.Is(err, ErrParams) {
		t.Errorf("m <= K: %v, want ErrParams", err)
	}
	if err := ReplaySite(good, p, Options{Sketch: &SketchParams{M: p.K + 1, H: p.D + p.K - 1}}, func(Tick) {}); !errors.Is(err, ErrParams) {
		t.Errorf("h < D+K: %v, want ErrParams", err)
	}
}

func TestReplayRefusesInvalidRecordsBeforeCallbacks(t *testing.T) {
	for name, corrupt := range map[string]func(*Record){
		"unknown class":    func(r *Record) { r.Class = ClassExpensive + 1 },
		"missing L1":       func(r *Record) { r.L1 = "" },
		"invalid binding":  func(r *Record) { r.Binding = "not-a-binding" },
		"invalid label":    func(r *Record) { r.Label = "not-a-label" },
		"missing episode":  func(r *Record) { r.Episode = "" },
		"invalid sequence": func(r *Record) { r.Seq = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			site := fixtureSite(1, nil)
			corrupt(&site.Records[len(site.Records)-1])
			calls := 0
			err := ReplaySite(site, fixtureParams(), Options{}, func(Tick) { calls++ })
			if !errors.Is(err, ErrSite) || calls != 0 {
				t.Fatalf("invalid record: error %v, callbacks %d; want ErrSite and no callbacks", err, calls)
			}
			if _, err := EvaluateSite(site, fixtureParams(), Options{}); !errors.Is(err, ErrSite) {
				t.Fatalf("evaluation accepted invalid record: %v", err)
			}
		})
	}
}

func TestRampPreservesClientRequestCounts(t *testing.T) {
	for name, rates := range map[string][]int{
		"rising":  {2, 4, 6, 8},
		"falling": {8, 6, 4, 2},
		"flat":    {2, 2, 2, 2},
	} {
		t.Run(name, func(t *testing.T) {
			const q = 3
			traffic := Traffic{From: fixtureStart, To: fixtureStart + int64(len(rates)) - 1}
			records := NewSynth(testSite, 7).Ramp(traffic, rates[0], rates[len(rates)-1], q)
			perMinute := map[int64]int{}
			bindings := map[string]int{}
			var clients []string
			for _, r := range records {
				if err := r.Validate(); err != nil {
					t.Fatal(err)
				}
				perMinute[r.T/60]++
				if bindings[r.Binding] == 0 {
					clients = append(clients, r.Binding)
				}
				bindings[r.Binding]++
			}
			total := 0
			for i, want := range rates {
				total += want
				if got := perMinute[fixtureStart+int64(i)]; got != want {
					t.Errorf("minute %d: %d requests, want %d", i, got, want)
				}
			}
			if len(records) != total || len(clients) != (total+q-1)/q {
				t.Errorf("got %d requests from %d clients, want %d requests from %d clients", len(records), len(clients), total, (total+q-1)/q)
			}
			for i, b := range clients {
				want := q
				if i == len(clients)-1 {
					want = (total-1)%q + 1
				}
				if got := bindings[b]; got != want {
					t.Errorf("client %d made %d requests, want %d", i, got, want)
				}
			}
		})
	}
}

func TestReplayIsDeterministic(t *testing.T) {
	p := fixtureParams()
	sk := SketchParams{M: 32, H: 128, Seed: 5}
	a, errA := EvaluateSite(fixtureSite(3, nil), p, Options{Sketch: &sk, Shuffle: 11})
	b, errB := EvaluateSite(fixtureSite(3, nil), p, Options{Sketch: &sk, Shuffle: 11})
	if errA != nil || errB != nil || !reflect.DeepEqual(a, b) {
		t.Fatalf("same input and seeds gave different reports: %v %v", errA, errB)
	}
}

// A young key that is not yet anomalous trains its slot, so an attack that
// needs several minutes to reach A2 raises its own expectation: the
// poisoning limit spec 6.4 asks phase 1 to measure, pinned here.
func TestTrustedYoungSlotLearnsAttackBeforeA2(t *testing.T) {
	p := fixtureParams()
	p.Baseline.MinAge = 0
	rep, err := EvaluateSite(fixtureSite(20, nil), p, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Episodes[0].Detected {
		t.Fatal("expected the trusted young slot to absorb the slow-accumulating attack")
	}
	rep, err = EvaluateSite(fixtureSite(1, nil), p, Options{})
	if err != nil || !rep.Episodes[0].Detected {
		t.Fatalf("one-request clients reach A2 in the first minute and must still detect: %v", err)
	}
}

// thresholdRecords sends, in one minute, k heavy bindings of heavy requests
// each plus residual requests from exactly distinct further bindings; the
// first residual binding takes what the others leave. Every record carries
// the given label on one L1 key.
func thresholdRecords(minute int64, k int, heavy, residual, distinct int64, seq *int64) []Record {
	var out []Record
	add := func(binding string, n int64) {
		for range n {
			*seq++
			out = append(out, Record{T: minute*60 + 30, Seq: *seq, Site: testSite, Binding: binding,
				Class: ClassExpensive, L2: SynthKey(1), L1: SynthKey(2), Status: 200})
		}
	}
	for i := range k {
		add(synthBinding(uint64(1000+i)), heavy)
	}
	for i := range distinct {
		n := int64(1)
		if i == 0 {
			n = residual - distinct + 1
		}
		add(synthBinding(uint64(2000+i)), n)
	}
	return out
}

// lastL1 replays the site and returns the L1 key's evaluation at the site's
// last covered minute.
func lastL1(t *testing.T, site Site, p Params, o Options) Evaluation {
	t.Helper()
	var got *Evaluation
	last := site.Coverage[len(site.Coverage)-1].To
	if err := ReplaySite(site, p, o, func(tk Tick) {
		for i := range tk.Evaluations {
			if tk.Minute == last && tk.Evaluations[i].Key.Level == 1 {
				got = &tk.Evaluations[i]
			}
		}
	}); err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("L1 key was not evaluated at the last minute")
	}
	return *got
}

func TestResidualThresholdEquality(t *testing.T) {
	const w = 2
	cold := BaselineParams{Alpha: 0.5, MinObs: 1, MinAge: 1 << 40, FloorPerMin: 5}
	// A cold key expects W times the floor: 10 requests over the window.
	for _, tc := range []struct {
		name string
		r, f float64
		need int64 // max(R*expected, F*W)
	}{
		{name: "rate multiple binds", r: 3, f: 1, need: 30},
		{name: "rate floor binds", r: 1.5, f: 12, need: 24},
	} {
		p := Params{W: w, R: tc.r, F: tc.f, K: 2, D: 4, C: 80, Baseline: cold}
		for _, dr := range []int64{-1, 0, 1} {
			for _, dd := range []int64{-1, 0, 1} {
				residual, distinct := tc.need+dr, int64(p.D)+dd
				t.Run(fmt.Sprintf("%s/residual%+d/distinct%+d", tc.name, dr, dd), func(t *testing.T) {
					var seq int64
					site := Site{Records: thresholdRecords(fixtureStart+1, p.K, residual+1, residual, distinct, &seq),
						Coverage: []Span{{From: fixtureStart, To: fixtureStart + 1}}}
					e := lastL1(t, site, p, Options{})
					want := dr >= 0 && dd >= 0
					if e.ExactResidual != residual || e.ExactDistinct != distinct || e.Expected != 10 {
						t.Fatalf("window residual %d/%d expected %v, want %d/%d and 10", e.ExactResidual, e.ExactDistinct, e.Expected, residual, distinct)
					}
					if e.Anomalous != want || e.ExactAnomalous != want {
						t.Fatalf("anomalous %t (exact %t), want %t", e.Anomalous, e.ExactAnomalous, want)
					}
				})
			}
		}
	}

	p := Params{W: w, R: 3, F: 1, K: 2, D: 4, C: 80, Baseline: cold}
	t.Run("too few bindings", func(t *testing.T) {
		for _, bindings := range []int{1, p.K} {
			var seq int64
			site := Site{Records: thresholdRecords(fixtureStart+1, bindings, 500, 0, 0, &seq),
				Coverage: []Span{{From: fixtureStart, To: fixtureStart + 1}}}
			if e := lastL1(t, site, p, Options{}); e.ExactResidual != 0 || e.ExactDistinct != 0 || e.Anomalous {
				t.Fatalf("%d bindings: %+v, want an empty residual and no anomaly", bindings, e)
			}
		}
	})

	t.Run("supporting evidence and infrastructure change nothing", func(t *testing.T) {
		for _, residual := range []int64{29, 30} {
			var seq int64
			base := Site{Records: thresholdRecords(fixtureStart+1, p.K, 31, residual, int64(p.D), &seq),
				Coverage: []Span{{From: fixtureStart, To: fixtureStart + 1}}}
			want := lastL1(t, base, p, Options{})
			if want.Anomalous != (residual == 30) {
				t.Fatalf("residual %d: anomalous %t", residual, want.Anomalous)
			}
			for name, change := range map[string]func(*Record){
				"same-site referer": func(r *Record) { r.Referer = RefSameSite },
				"verified bot":      func(r *Record) { r.Bot, r.BotProof = "googlebot", BotProofRange },
				"claimed bot":       func(r *Record) { r.Bot = "googlebot" },
				"origin 5xx":        func(r *Record) { r.Status = 503 },
			} {
				changed := base
				changed.Records = slices.Clone(base.Records)
				for i := range changed.Records {
					change(&changed.Records[i])
				}
				if got := lastL1(t, changed, p, Options{}); !reflect.DeepEqual(got, want) {
					t.Fatalf("residual %d, %s: %+v, want %+v", residual, name, got, want)
				}
			}
			infra := base
			infra.Records = slices.Clone(base.Records)
			for i := range 400 {
				seq++
				infra.Records = append(infra.Records, Record{T: (fixtureStart+1)*60 + 40, Seq: seq, Site: testSite,
					Binding: synthBinding(uint64(5000 + i)), Class: ClassExpensive, L2: SynthKey(1), L1: SynthKey(2), Status: 200, Infra: true})
			}
			if got := lastL1(t, infra, p, Options{}); !reflect.DeepEqual(got, want) {
				t.Fatalf("residual %d: infrastructure changed the window: %+v, want %+v", residual, got, want)
			}
		}
	})

	t.Run("infrastructure never trains the baseline", func(t *testing.T) {
		trained := p
		trained.Baseline = BaselineParams{Alpha: 0.5, MinObs: 1, MinAge: 0, FloorPerMin: 5}
		// Minutes 0..49 of one UTC hour train the slot; 58 and 59 are judged.
		hour := fixtureStart - fixtureStart%60
		s := NewSynth(testSite, 21)
		history := s.Pool(Traffic{From: hour, To: hour + 59, PerMinute: 3, L2: SynthKey(1), L1: SynthKey(2)}, 4)
		site := Site{Records: history, Coverage: []Span{{From: hour, To: hour + 59}}}
		want := lastL1(t, site, trained, Options{})
		if want.Expected == 2*trained.Baseline.FloorPerMin {
			t.Fatalf("slot did not train: expected %v", want.Expected)
		}
		withInfra := site
		withInfra.Records = slices.Clone(history)
		for m := hour; m <= hour+59; m++ {
			for i := range 50 {
				withInfra.Records = append(withInfra.Records, Record{T: m*60 + 5, Seq: int64(100000 + m*100 + int64(i)), Site: testSite,
					Binding: synthBinding(uint64(9000 + i)), Class: ClassExpensive, L2: SynthKey(1), L1: SynthKey(2), Status: 200, Infra: true})
			}
		}
		if got := lastL1(t, withInfra, trained, Options{}); !reflect.DeepEqual(got, want) {
			t.Fatalf("infrastructure traffic changed the trained evaluation: %+v, want %+v", got, want)
		}
	})
}

func TestReplayScopeBasisExpiresWithTraffic(t *testing.T) {
	p := Params{W: 2, R: 2, F: 1, K: 1, D: 2, C: 80,
		Baseline: BaselineParams{Alpha: 0.5, MinObs: 1, MinAge: 1 << 40, FloorPerMin: 1}}
	s := NewSynth(testSite, 7)
	l1 := KeyID{Level: 1, Key: SynthKey(2), Parent: SynthKey(1)}
	siteKey := KeyID{Level: 3}
	records := s.Rotating(Traffic{From: fixtureStart, To: fixtureStart, PerMinute: 6}, 1)
	records = append(records, s.Rotating(Traffic{From: fixtureStart + 1, To: fixtureStart + 2,
		PerMinute: 6, L2: l1.Parent, L1: l1.Key}, 1)...)
	site := Site{Records: records, Coverage: []Span{{From: fixtureStart, To: fixtureStart + 4}}}
	want := []Scope{
		{Level: 3, Keys: []KeyID{siteKey}, Covered: 12, Denominator: 12, Basis: BasisDynamic},
		{Level: 1, Keys: []KeyID{l1}, Covered: 12, Denominator: 12, Basis: BasisExpensive},
		{Level: 1, Keys: []KeyID{l1}, Covered: 6, Denominator: 6, Basis: BasisExpensive},
		{},
	}
	for name, options := range map[string]Options{
		"exact":  {},
		"sketch": {Sketch: &SketchParams{M: 16, H: 16, Seed: 7}},
	} {
		t.Run(name, func(t *testing.T) {
			var got []Scope
			err := ReplaySite(site, p, options, func(tk Tick) {
				got = append(got, tk.Scope)
				for _, e := range tk.Evaluations {
					var total, expensive int64
					for _, r := range records {
						if r.T/60 < tk.Minute-int64(p.W)+1 || r.T/60 > tk.Minute || !slices.Contains(keysOf(&r), e.Key) {
							continue
						}
						total++
						if r.Class == ClassExpensive {
							expensive++
						}
					}
					if e.Total != total || e.Expensive != expensive {
						t.Fatalf("minute %d key %+v: total/expensive %d/%d, want %d/%d",
							tk.Minute, e.Key, e.Total, e.Expensive, total, expensive)
					}
				}
			})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("scopes %+v, want %+v", got, want)
			}
		})
	}
}

func TestScopeExactUnion(t *testing.T) {
	site := KeyID{Level: 3}
	l2 := func(k string) KeyID { return KeyID{Level: 2, Key: k} }
	l1 := func(k, parent string) KeyID { return KeyID{Level: 1, Key: k, Parent: parent} }
	ev := func(id KeyID, total, expensive int64, anomalous bool) Evaluation {
		return Evaluation{Key: id, Total: total, Expensive: expensive, Anomalous: anomalous}
	}
	x := func(id KeyID, n int64, anomalous bool) Evaluation { return ev(id, n, n, anomalous) }
	for _, tc := range []struct {
		name    string
		evals   []Evaluation
		unknown []KeyID
		c       float64
		want    Scope
	}{
		{
			name: "maximal L2 and an L1 under another L2 are counted once each",
			evals: []Evaluation{x(site, 1000, false), x(l2("a"), 100, true), x(l1("a1", "a"), 30, true),
				x(l2("b"), 500, false), x(l1("b1", "b"), 50, true)},
			c:    60,
			want: Scope{Level: 2, Keys: []KeyID{l2("a")}, Covered: 100, Denominator: 150, Basis: BasisExpensive},
		},
		{
			name: "L1 keys under different L2 keys form one disjoint set",
			evals: []Evaluation{x(site, 1000, false), x(l2("a"), 100, true), x(l1("a1", "a"), 30, true),
				x(l2("b"), 500, false), x(l1("b1", "b"), 50, true)},
			c:    50,
			want: Scope{Level: 1, Keys: []KeyID{l1("a1", "a"), l1("b1", "b")}, Covered: 80, Denominator: 150, Basis: BasisExpensive},
		},
		{
			name: "narrowest level at exact coverage",
			evals: []Evaluation{x(site, 1000, false), x(l2("a"), 100, true), x(l1("a2", "a"), 50, true),
				x(l1("a1", "a"), 30, true), x(l1("a3", "a"), 20, false)},
			c:    80,
			want: Scope{Level: 1, Keys: []KeyID{l1("a1", "a"), l1("a2", "a")}, Covered: 80, Denominator: 100, Basis: BasisExpensive},
		},
		{
			name: "just above exact coverage widens",
			evals: []Evaluation{x(site, 1000, false), x(l2("a"), 100, true), x(l1("a2", "a"), 50, true),
				x(l1("a1", "a"), 30, true), x(l1("a3", "a"), 20, false)},
			c:    80.5,
			want: Scope{Level: 2, Keys: []KeyID{l2("a")}, Covered: 100, Denominator: 100, Basis: BasisExpensive},
		},
		{
			name: "fragmented L1 keys widen to their L2",
			evals: []Evaluation{x(site, 5000, false), x(l2("a"), 1000, true), x(l1("a1", "a"), 100, true),
				x(l1("a2", "a"), 10, false), x(l1("a3", "a"), 10, false), x(l1("a4", "a"), 10, false)},
			c:    80,
			want: Scope{Level: 2, Keys: []KeyID{l2("a")}, Covered: 1000, Denominator: 1000, Basis: BasisExpensive},
		},
		{
			name: "fragmented paths widen to the site",
			evals: []Evaluation{x(site, 2000, true), x(l2("a"), 300, true), x(l2("b"), 20, false),
				x(l2("c"), 20, false), x(l1("a1", "a"), 300, true)},
			c:    80,
			want: Scope{Level: 3, Keys: []KeyID{site}, Covered: 2000, Denominator: 2000, Basis: BasisExpensive},
		},
		{
			name:  "site anomaly with queryless traffic uses dynamic counts",
			evals: []Evaluation{ev(site, 3000, 2000, true), x(l2("a"), 1900, true), x(l1("a1", "a"), 1900, true)},
			c:     80,
			want:  Scope{Level: 3, Keys: []KeyID{site}, Covered: 3000, Denominator: 3000, Basis: BasisDynamic},
		},
		{
			name:  "dynamic counts throughout the selection",
			evals: []Evaluation{ev(site, 3000, 2000, true), x(l2("a"), 1900, true), x(l1("a1", "a"), 1900, true)},
			c:     60,
			want:  Scope{Level: 1, Keys: []KeyID{l1("a1", "a")}, Covered: 1900, Denominator: 3000, Basis: BasisDynamic},
		},
		{
			name:  "no anomaly selects nothing",
			evals: []Evaluation{ev(site, 3000, 2000, false), x(l2("a"), 1900, false)},
			c:     80,
			want:  Scope{},
		},
		{
			name:  "zero denominator refuses",
			evals: []Evaluation{x(site, 0, true)},
			c:     80,
			want:  Scope{Refused: RefusedZero},
		},
		{
			name:    "unknown traffic without any complete evaluations refuses",
			unknown: []KeyID{site},
			c:       80,
			want:    Scope{Refused: RefusedUnknown},
		},
		{
			name:    "normal ancestors do not resolve unknown traffic",
			evals:   []Evaluation{x(site, 1000, false), x(l2("a"), 900, false)},
			unknown: []KeyID{l1("a1", "a")},
			c:       80,
			want:    Scope{Refused: RefusedUnknown},
		},
		{
			name:    "unknown ancestor refuses",
			evals:   []Evaluation{x(site, 1000, false), x(l1("a1", "a"), 900, true)},
			unknown: []KeyID{l2("a")},
			c:       80,
			want:    Scope{Refused: RefusedUnknown},
		},
		{
			name:    "unknown key outside every anomaly refuses",
			evals:   []Evaluation{x(site, 1000, false), x(l2("a"), 900, true)},
			unknown: []KeyID{l2("b")},
			c:       80,
			want:    Scope{Refused: RefusedUnknown},
		},
		{
			name:    "unknown key inside a maximal anomaly is already counted",
			evals:   []Evaluation{x(site, 1000, false), x(l2("a"), 900, true)},
			unknown: []KeyID{l1("a9", "a")},
			c:       80,
			want:    Scope{Level: 2, Keys: []KeyID{l2("a")}, Covered: 900, Denominator: 900, Basis: BasisExpensive},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := selectScope(tc.evals, tc.c, tc.unknown); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("scope %+v, want %+v", got, tc.want)
			}
		})
	}
}
