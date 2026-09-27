package crawlreplay

import (
	"errors"
	"testing"
)

func TestSummarizeNearestRank(t *testing.T) {
	sample := make([]float64, 100)
	for i := range sample {
		sample[i] = float64(100 - i)
	}
	q := Summarize(sample)
	if q.N != 100 || q.P50 != 50 || q.P99 != 99 || q.Max != 100 {
		t.Fatalf("quantiles = %+v", q)
	}
	if Summarize(nil) != (Quantiles{}) || SummarizeCounts(nil) != (Quantiles{}) {
		t.Fatal("empty sample must be zero")
	}
	hist := map[int64]int64{}
	for _, v := range sample {
		hist[int64(v)]++
	}
	if SummarizeCounts(hist) != q {
		t.Fatalf("histogram quantiles %+v differ from sample %+v", SummarizeCounts(hist), q)
	}
}

func TestSummarizeVolumeCountsSilentMinutesAsZero(t *testing.T) {
	rows := []Volume{
		{Site: testSite, Minute: 100, Lines: 4, Bytes: 400},
		{Site: "dom-000001.example", Minute: 100, Lines: 6, Bytes: 600},
		{Site: testSite, Minute: 103, Lines: 2, Bytes: 200},
	}
	v := SummarizeVolume(rows)
	if v.LinesPerMinute.N != 4 || v.LinesPerMinute.Max != 10 || v.LinesPerMinute.P50 != 0 {
		t.Fatalf("host lines = %+v", v.LinesPerMinute)
	}
	if v.SiteLinesPerMinute.N != 3 || v.BytesPerMinute.Max != 1000 {
		t.Fatalf("site lines %+v bytes %+v", v.SiteLinesPerMinute, v.BytesPerMinute)
	}
}

func TestLongestSilence(t *testing.T) {
	span := Span{From: 100, To: 120}
	for _, tc := range []struct {
		logged []int64
		want   int64
	}{
		{nil, 21}, {[]int64{100, 101, 120}, 18}, {[]int64{110}, 10}, {[]int64{95, 100, 125}, 20},
	} {
		if got := LongestSilence(tc.logged, span); got != tc.want {
			t.Errorf("LongestSilence(%v) = %d, want %d", tc.logged, got, tc.want)
		}
	}
}

func TestShapeSiteLatenessKeysAndBindings(t *testing.T) {
	base := fixtureStart * 60
	recs := []Record{
		{T: base + 10, File: 0, Seq: 1, Site: testSite, Binding: "b-0000000000000001", Class: ClassExpensive, L2: SynthKey(1), L1: SynthKey(2), Status: 200},
		{T: base + 5, File: 0, Seq: 2, Site: testSite, Binding: "b-0000000000000002", Class: ClassExpensive, L2: SynthKey(1), L1: SynthKey(3), Status: 200},
		{T: base + 3, File: 1, Seq: 3, Site: testSite, Binding: "b-0000000000000001", Class: ClassDynamic, Status: 200},
		{T: base + 70, File: 0, Seq: 4, Site: testSite, Binding: "b-0000000000000003", Class: ClassExpensive, L2: SynthKey(1), L1: SynthKey(2), Status: 200},
		{T: base + 130, File: 0, Seq: 5, Site: testSite, Class: ClassOther, Status: 200},
	}
	shape := ShapeSite(Site{Records: recs, Coverage: []Span{{From: fixtureStart, To: fixtureStart + 2}}}, 2)
	if len(shape.Lateness) != 2 || shape.Lateness[0] != 4 || shape.Lateness[5] != 1 {
		t.Fatalf("lateness = %v", shape.Lateness)
	}
	// Windows end at minutes 1 and 2: {L1 x2, L2, site} then {L1 x1, L2, site}.
	if got := shape.WindowKeys[1]; len(got) != 2 || got[0] != 2 || got[1] != 1 {
		t.Fatalf("L1 window keys = %v", got)
	}
	if got := shape.WindowBindings; len(got) != 2 || got[0] != 3 || got[1] != 1 {
		t.Fatalf("window bindings = %v", got)
	}
	if got := shape.NewKeys[1]; len(got) != 1 || got[0] != 2 {
		t.Fatalf("new L1 keys per hour = %v", got)
	}
}

func TestFootprintGrowsWithWindowAndSummaries(t *testing.T) {
	p := fixtureParams()
	small := Footprint(p, SketchParams{M: 64, H: 128})
	wide := p
	wide.W *= 2
	if Footprint(wide, SketchParams{M: 64, H: 128}) <= small || Footprint(p, SketchParams{M: 128, H: 128}) <= small {
		t.Fatal("footprint must grow with W and m")
	}
	if want := int64(168*16) + int64(p.W)*(64*25+128*8+8); small != want {
		t.Fatalf("footprint = %d, want %d", small, want)
	}
}

func TestFixtureDetectsAcrossClientSizes(t *testing.T) {
	p := fixtureParams()
	for _, q := range []int{1, 3, 20} {
		f := Fixture{Name: "fx", Train: 100, Background: 2, Pool: 10, Minutes: 30, PerMinute: 300, Q: q,
			PaddingSources: p.K, PaddingPerSource: 200, Churn: true, Seed: 1}
		if err := f.Validate(); err != nil {
			t.Fatal(err)
		}
		rep, err := EvaluateSite(f.Site(), p, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if len(rep.Episodes) != 1 || !rep.Episodes[0].Detected || rep.Episodes[0].Episode != "fx" {
			t.Fatalf("q=%d: %+v", q, rep.Episodes)
		}
	}
	// A slow ramp into a key whose slot already trusts its own young
	// history is absorbed, while the same ramp against a cold floor is not.
	ramp := Fixture{Name: "ramp", Train: 100, Background: 2, Pool: 10, Minutes: 120, PerMinute: 300, Q: 1, RampMinutes: 120, Seed: 2}
	cold, err := EvaluateSite(ramp.Site(), p, Options{})
	if err != nil || !cold.Episodes[0].Detected {
		t.Fatalf("slow ramp against the cold floor: %v %+v", err, cold.Episodes)
	}
	trusting := p
	trusting.Baseline.MinAge = 0
	trusted, err := EvaluateSite(ramp.Site(), trusting, Options{})
	if err != nil || trusted.Episodes[0].Detected {
		t.Fatalf("slow ramp into a trusted young slot should be absorbed: %v %+v", err, trusted.Episodes)
	}
	for name, f := range map[string]Fixture{
		"ramp":     {Name: "fx", Minutes: 2, PerMinute: 1, Q: 1, RampMinutes: 3},
		"name":     {Name: "Bad Name", Minutes: 1, PerMinute: 1, Q: 1},
		"pool":     {Name: "fx", Background: 1, Minutes: 1, PerMinute: 1, Q: 1},
		"q":        {Name: "fx", Minutes: 1, PerMinute: 1},
		"padding":  {Name: "fx", Minutes: 1, PerMinute: 1, Q: 1, PaddingSources: 2},
		"minutes":  {Name: "fx", PerMinute: 1, Q: 1},
		"negative": {Name: "fx", Train: -1, Minutes: 1, PerMinute: 1, Q: 1},
	} {
		if err := f.Validate(); !errors.Is(err, ErrFixture) {
			t.Errorf("%s: %v, want ErrFixture", name, err)
		}
	}
}
