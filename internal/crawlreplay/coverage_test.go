package crawlreplay

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"slices"
	"strings"
	"testing"
)

const (
	evidenceCollection = "c000000000000000000000000000000000000000000000000000000000000000"
	evidenceLiveness   = "d000000000000000000000000000000000000000000000000000000000000000"
	evidenceLateness   = "e000000000000000000000000000000000000000000000000000000000000000"
	evidenceReject     = "f000000000000000000000000000000000000000000000000000000000000000"
)

// wholeProof certifies every minute of the period for both sites, bound to
// the bundle's manifest, with a one-minute lateness bound.
func wholeProof(t testing.TB, f bundleFiles) *CoverageProof {
	t.Helper()
	m, err := DecodeManifest(f.raw)
	if err != nil {
		t.Fatal(err)
	}
	p := &CoverageProof{FormatVersion: ProofVersion, ManifestSHA256: m.Digest(), LatenessSeconds: 60,
		Evidence: []ProofEvidence{
			{Kind: EvidenceCollection, SHA256: evidenceCollection},
			{Kind: EvidenceLiveness, SHA256: evidenceLiveness},
			{Kind: EvidenceLateness, SHA256: evidenceLateness},
			{Kind: EvidencePreApplication, SHA256: evidenceReject},
		}}
	for _, s := range m.Sites {
		p.Sites = append(p.Sites, ProofSite{Site: s.Site, Spans: []Span{{From: periodFrom, To: periodTo}}})
	}
	return p
}

// replayTicks replays one validated site over its certified coverage and
// returns the minutes whose windows were complete.
func replayTicks(t *testing.T, site BundleSite, recs []Record, w int) []int64 {
	t.Helper()
	p := fixtureParams()
	p.W = w
	var ticks []int64
	in := Site{Records: RestrictToCoverage(recs, site.Coverage), Coverage: site.Coverage}
	if err := ReplaySite(in, p, Options{}, func(tk Tick) { ticks = append(ticks, tk.Minute) }); err != nil {
		t.Fatal(err)
	}
	return ticks
}

func minuteRange(from, to int64) []int64 {
	var out []int64
	for m := from; m <= to; m++ {
		out = append(out, m)
	}
	return out
}

func TestValidateBundleCoverage(t *testing.T) {
	t.Run("separate spans evaluate separately", func(t *testing.T) {
		f := buildBundle(t, bundleStages{})
		p := wholeProof(t, f)
		p.Sites[0].Spans = []Span{{From: periodFrom, To: periodFrom + 19}, {From: periodFrom + 30, To: periodTo}}
		p.Sites[0].Excluded = []Exclusion{{From: periodFrom + 20, To: periodFrom + 29, Reason: ExcludedCollectionGap}}
		sites, recs, err := validateFiles(f, p)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(sites[0].Coverage, p.Sites[0].Spans) || sites[0].Excluded[ExcludedCollectionGap] != 10 {
			t.Fatalf("coverage = %+v excluded %v", sites[0].Coverage, sites[0].Excluded)
		}
		want := append(minuteRange(periodFrom+4, periodFrom+19), minuteRange(periodFrom+34, periodTo)...)
		if got := replayTicks(t, sites[0], recs, 5); !slices.Equal(got, want) {
			t.Fatalf("ticks = %v, want %v", got, want)
		}
	})
	t.Run("partial and unknown minutes are never zeros", func(t *testing.T) {
		f := buildBundle(t, bundleStages{})
		p := wholeProof(t, f)
		p.Sites[0].Spans = []Span{{From: periodFrom + 1, To: periodFrom + 29}, {From: periodFrom + 35, To: periodTo - 1}}
		p.Sites[0].Excluded = []Exclusion{
			{From: periodFrom, To: periodFrom, Reason: ExcludedPartialMinute},
			{From: periodFrom + 30, To: periodFrom + 34, Reason: ExcludedLivenessUnknown},
			{From: periodTo, To: periodTo, Reason: ExcludedPartialMinute},
		}
		sites, recs, err := validateFiles(f, p)
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]int64{ExcludedPartialMinute: 2, ExcludedLivenessUnknown: 5}
		if !reflect.DeepEqual(sites[0].Excluded, want) || !reflect.DeepEqual(sites[0].Coverage, p.Sites[0].Spans) {
			t.Fatalf("coverage = %+v excluded %v", sites[0].Coverage, sites[0].Excluded)
		}
		for _, m := range replayTicks(t, sites[0], recs, 1) {
			if m == periodFrom || m == periodTo || (m >= periodFrom+30 && m <= periodFrom+34) {
				t.Fatalf("minute %d was evaluated although its coverage is unknown", m)
			}
		}
	})
	t.Run("liveness certifies a quiet site", func(t *testing.T) {
		f := buildBundle(t, bundleStages{})
		sites, _, err := validateFiles(f, wholeProof(t, f))
		if err != nil {
			t.Fatal(err)
		}
		quiet := sites[1]
		if quiet.Records != 0 || !reflect.DeepEqual(quiet.Coverage, []Span{{From: periodFrom, To: periodTo}}) {
			t.Fatalf("quiet site = %+v", quiet)
		}
		if got := replayTicks(t, quiet, nil, 5); len(got) != 56 {
			t.Fatalf("quiet site produced %d complete windows, want 56", len(got))
		}
	})
	t.Run("observed extent is not coverage", func(t *testing.T) {
		f := buildBundle(t, bundleStages{})
		sites, _, err := validateFiles(f, nil)
		if err != nil {
			t.Fatal(err)
		}
		if sites[0].Extent == nil || sites[0].Coverage != nil || sites[0].Certified != nil {
			t.Fatalf("unqualified site = %+v, want an extent and no coverage", sites[0])
		}
	})
	t.Run("timed loss removes its minute", func(t *testing.T) {
		f := buildBundle(t, bundleStages{rows: func(recs *[]Record, vol *[]Volume) {
			for i := range *recs {
				if (*recs)[i].T/60 == periodFrom+12 {
					(*recs)[i].Binding = ""
				}
			}
			*vol = volumeOf(*recs)
			for i := range *vol {
				if (*vol)[i].Minute == periodFrom+10 {
					(*vol)[i].NoTarget = 1
				}
			}
		}})
		sites, _, err := validateFiles(f, wholeProof(t, f))
		if err != nil {
			t.Fatal(err)
		}
		want := []Span{{From: periodFrom, To: periodFrom + 9}, {From: periodFrom + 11, To: periodFrom + 11}, {From: periodFrom + 13, To: periodTo}}
		if !reflect.DeepEqual(sites[0].Coverage, want) || sites[0].Excluded[ExcludedUnknownLoss] != 2 {
			t.Fatalf("coverage = %+v excluded %v", sites[0].Coverage, sites[0].Excluded)
		}
		if !reflect.DeepEqual(sites[0].Certified, []Span{{From: periodFrom, To: periodTo}}) {
			t.Fatalf("certified = %+v", sites[0].Certified)
		}
	})
	t.Run("untimed loss removes its lateness bracket", func(t *testing.T) {
		f := buildBundle(t, bundleStages{manifest: func(m *Manifest) {
			addUntimed(m, UntimedLoss{Category: LossOversized, After: (periodFrom+20)*60 + 30, Before: (periodFrom+22)*60 + 10, Lines: 1}, 70000)
			addUntimed(m, UntimedLoss{Category: LossRejected, Before: (periodFrom+2)*60 + 5, Lines: 2}, 50)
		}})
		sites, _, err := validateFiles(f, wholeProof(t, f))
		if err != nil {
			t.Fatal(err)
		}
		// Oversized: 30s after minute 20 less 60s, to 10s after minute 22 plus 60s.
		// Rejected at the start of the input: from the period start.
		want := []Span{{From: periodFrom + 4, To: periodFrom + 18}, {From: periodFrom + 24, To: periodTo}}
		if !reflect.DeepEqual(sites[0].Coverage, want) || sites[0].Excluded[ExcludedUnknownLoss] != 9 {
			t.Fatalf("coverage = %+v excluded %v", sites[0].Coverage, sites[0].Excluded)
		}
	})
	t.Run("lateness the bundle contradicts is refused", func(t *testing.T) {
		// A copy lists requests in completion order, so a logged time six
		// minutes behind an earlier line proves at least six minutes of
		// completion delay.
		f := buildBundle(t, bundleStages{rows: func(recs *[]Record, vol *[]Volume) {
			for i := range *recs {
				if (*recs)[i].T/60 == periodFrom+20 {
					(*recs)[i].T -= 360
					break
				}
			}
			*vol = volumeOf(*recs)
		}})
		p := wholeProof(t, f)
		if _, _, err := validateFiles(f, p); !errors.Is(err, ErrProof) {
			t.Fatalf("a 60 s bound over a bundle with 360 s of disorder: err = %v, want ErrProof", err)
		}
		p.LatenessSeconds = 3600
		if _, _, err := validateFiles(f, p); err != nil {
			t.Fatalf("a bound above the observed disorder was refused: %v", err)
		}
	})
	t.Run("pre-application evidence waives exact loss", func(t *testing.T) {
		f := buildBundle(t, bundleStages{
			rows: func(_ *[]Record, vol *[]Volume) {
				for i := range *vol {
					if (*vol)[i].Minute == periodFrom+10 {
						(*vol)[i].NoTarget = 2
					}
				}
			},
			manifest: func(m *Manifest) {
				addUntimed(m, UntimedLoss{Category: LossOversized, After: (periodFrom+20)*60 + 30, Before: (periodFrom+22)*60 + 10, Lines: 1}, 70000)
			},
		})
		p := wholeProof(t, f)
		p.Sites[0].Rejects = []RejectWaiver{
			{From: periodFrom + 10, To: periodFrom + 10, Category: LossNoTarget, Lines: 2, Evidence: evidenceReject},
			{From: periodFrom + 19, To: periodFrom + 23, Category: LossOversized, Lines: 1, Evidence: evidenceReject},
		}
		sites, _, err := validateFiles(f, p)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(sites[0].Coverage, []Span{{From: periodFrom, To: periodTo}}) || sites[0].Excluded[ExcludedUnknownLoss] != 0 {
			t.Fatalf("waived loss still excluded: %+v %v", sites[0].Coverage, sites[0].Excluded)
		}
		for name, mutate := range map[string]func(*CoverageProof){
			"count":          func(p *CoverageProof) { p.Sites[0].Rejects[0].Lines = 1 },
			"narrow bracket": func(p *CoverageProof) { p.Sites[0].Rejects[1].From = periodFrom + 20 },
			"evidence kind":  func(p *CoverageProof) { p.Sites[0].Rejects[0].Evidence = evidenceLiveness },
			"unwaivable":     func(p *CoverageProof) { p.Sites[0].Rejects[0].Category = LossRejected },
			"overlap": func(p *CoverageProof) {
				p.Sites[0].Rejects[1].Category = LossNoTarget
				p.Sites[0].Rejects[1].From = periodFrom + 10
			},
			"outside period":   func(p *CoverageProof) { p.Sites[0].Rejects[1].To = periodTo + 1 },
			"missing evidence": func(p *CoverageProof) { p.Evidence = p.Evidence[:3] },
		} {
			q := wholeProof(t, f)
			q.Sites[0].Rejects = slices.Clone(p.Sites[0].Rejects)
			mutate(q)
			if _, _, err := validateFiles(f, q); !errors.Is(err, ErrProof) {
				t.Errorf("%s: err = %v, want ErrProof", name, err)
			}
		}
	})
	t.Run("proof must describe this bundle", func(t *testing.T) {
		f := buildBundle(t, bundleStages{})
		for name, mutate := range map[string]func(*CoverageProof){
			"manifest digest": func(p *CoverageProof) { p.ManifestSHA256 = strings.Repeat("0", 64) },
			"missing site":    func(p *CoverageProof) { p.Sites = p.Sites[:1] },
			"unknown site":    func(p *CoverageProof) { p.Sites[1].Site = "dom-ffffff.example" },
			"duplicate site":  func(p *CoverageProof) { p.Sites[1].Site = p.Sites[0].Site },
			"uncovered minute": func(p *CoverageProof) {
				p.Sites[0].Spans = []Span{{From: periodFrom, To: periodFrom + 9}, {From: periodFrom + 11, To: periodTo}}
			},
			"overlap": func(p *CoverageProof) {
				p.Sites[0].Excluded = []Exclusion{{From: periodFrom, To: periodFrom, Reason: ExcludedPartialMinute}}
			},
			"past period": func(p *CoverageProof) { p.Sites[0].Spans[0].To = periodTo + 1 },
			"reason": func(p *CoverageProof) {
				p.Sites[0].Excluded = []Exclusion{{From: periodTo + 1, To: periodTo + 1, Reason: "quiet"}}
			},
			"no liveness":   func(p *CoverageProof) { p.Evidence = slices.Delete(p.Evidence, 1, 2) },
			"no lateness":   func(p *CoverageProof) { p.LatenessSeconds = 0 },
			"proof version": func(p *CoverageProof) { p.FormatVersion = 2 },
			"unsorted spans": func(p *CoverageProof) {
				p.Sites[0].Spans = []Span{{From: periodFrom + 30, To: periodTo}, {From: periodFrom, To: periodFrom + 29}}
			},
		} {
			p := wholeProof(t, f)
			mutate(p)
			if _, _, err := validateFiles(f, p); !errors.Is(err, ErrProof) {
				t.Errorf("%s: err = %v, want ErrProof", name, err)
			}
		}
	})
}

func TestDecodeCoverageProofIsStrict(t *testing.T) {
	f := buildBundle(t, bundleStages{})
	good, err := json.Marshal(wholeProof(t, f))
	if err != nil {
		t.Fatal(err)
	}
	p, err := DecodeCoverageProof(good)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := validateFiles(f, p); err != nil {
		t.Fatalf("decoded proof refused: %v", err)
	}
	for name, raw := range map[string][]byte{
		"unknown member": bytes.Replace(good, []byte(`"format_version"`), []byte(`"note":"x","format_version"`), 1),
		"duplicate":      bytes.Replace(good, []byte(`"format_version":1`), []byte(`"format_version":1,"format_version":1`), 1),
		"null list":      bytes.Replace(good, []byte(`"spans":`), []byte(`"excluded":null,"spans":`), 1),
		"null lateness":  bytes.Replace(good, []byte(`"lateness_seconds":60`), []byte(`"lateness_seconds":null`), 1),
		"case alias":     bytes.Replace(good, []byte(`"lateness_seconds"`), []byte(`"Lateness_Seconds"`), 1),
		"trailing":       append(append([]byte{}, good...), []byte(" {}")...),
		"fraction":       bytes.Replace(good, []byte(`"lateness_seconds":60`), []byte(`"lateness_seconds":60.5`), 1),
	} {
		if bytes.Equal(raw, good) {
			t.Fatalf("%s: mutation did not change the proof", name)
		}
		if _, err := DecodeCoverageProof(raw); !errors.Is(err, ErrProof) {
			t.Errorf("%s: err = %v, want ErrProof", name, err)
		}
	}
}

// A site can be wholly unqualified without hiding it or blocking other sites.
func TestValidateBundleFullyExcludedSite(t *testing.T) {
	f := buildBundle(t, bundleStages{})
	p := wholeProof(t, f)
	p.Sites[0].Spans = []Span{}
	p.Sites[0].Excluded = []Exclusion{{From: periodFrom, To: periodTo, Reason: ExcludedLivenessUnknown}}
	sites, recs, err := validateFiles(f, p)
	if err != nil {
		t.Fatal(err)
	}
	if len(sites) != 2 || len(sites[0].Certified) != 0 || len(sites[0].Coverage) != 0 || sites[0].Excluded[ExcludedLivenessUnknown] != 60 {
		t.Fatalf("fully excluded site lost or certified: %+v", sites)
	}
	if ticks := replayTicks(t, sites[0], recs, 5); len(ticks) != 0 {
		t.Fatalf("unknown site evaluated: %v", ticks)
	}
	if ticks := replayTicks(t, sites[1], nil, 5); len(ticks) != 56 {
		t.Fatalf("quiet certified site: %d windows", len(ticks))
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeCoverageProof(raw); err != nil {
		t.Fatalf("empty spans refused: %v", err)
	}
	missing := bytes.Replace(raw, []byte(`"spans":[],`), nil, 1)
	if bytes.Equal(missing, raw) {
		t.Fatal("missing-spans mutation did not apply")
	}
	if _, err := DecodeCoverageProof(missing); !errors.Is(err, ErrProof) {
		t.Fatalf("missing spans: %v", err)
	}
}

func TestCoverageBracketAtIntegerBoundary(t *testing.T) {
	const last = int64(1<<63 - 1)
	period := Span{From: 1, To: last / 60}
	got, ok := bracket(UntimedLoss{Before: last - 1}, period, 120)
	if !ok || got != period {
		t.Fatalf("overflow shrank the possible loss interval: %+v %v", got, ok)
	}
	for _, u := range []UntimedLoss{
		{After: (periodFrom + 22) * 60, Before: (periodFrom + 20) * 60},
		{After: (periodFrom + 20) * 60, Before: (periodFrom + 22) * 60},
	} {
		got, ok := bracket(u, Span{From: periodFrom, To: periodTo}, 60)
		want := Span{From: periodFrom + 19, To: periodFrom + 23}
		if !ok || got != want {
			t.Fatalf("reordered bracket = %+v %v, want %+v", got, ok, want)
		}
	}
}

func TestCoverageLossAtLastMinute(t *testing.T) {
	f := buildBundle(t, bundleStages{manifest: func(m *Manifest) {
		m.Period.To = math.MaxInt64
		addUntimed(m, UntimedLoss{Category: LossRejected, Lines: 1}, 100)
	}})
	p := wholeProof(t, f)
	for i := range p.Sites {
		p.Sites[i].Spans[0].To = math.MaxInt64
	}
	sites, _, err := validateFiles(f, p)
	if err != nil {
		t.Fatal(err)
	}
	if len(sites[0].Coverage) != 0 || sites[0].Excluded[ExcludedUnknownLoss] != math.MaxInt64-periodFrom+1 {
		t.Fatalf("untimed loss left certified minutes: %+v", sites[0])
	}
	if !reflect.DeepEqual(sites[1].Coverage, p.Sites[1].Spans) {
		t.Fatalf("quiet site lost certified minutes: %+v", sites[1])
	}
}

func TestSubtractBoundaryLoss(t *testing.T) {
	for name, tc := range map[string]struct{ spans, cut, want []Span }{
		"last minute":           {[]Span{{1, math.MaxInt64}}, []Span{{math.MaxInt64, math.MaxInt64}}, []Span{{1, math.MaxInt64 - 1}}},
		"whole span":            {[]Span{{1, math.MaxInt64}}, []Span{{1, math.MaxInt64}}, nil},
		"cut reaches past span": {[]Span{{1, 3}}, []Span{{2, math.MaxInt64}}, []Span{{1, 1}}},
		"overlapping cuts":      {[]Span{{1, 3}, {5, 7}, {9, math.MaxInt64}}, []Span{{6, math.MaxInt64}, {2, 10}}, []Span{{1, 1}}},
		"adjacent spans":        {[]Span{{1, 3}, {4, 7}}, []Span{{3, 4}}, []Span{{1, 2}, {5, 7}}},
	} {
		t.Run(name, func(t *testing.T) {
			if got := subtract(tc.spans, tc.cut); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("coverage = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestBundleRejectsChangedProof(t *testing.T) {
	f := buildBundle(t, bundleStages{})
	raw, err := json.Marshal(wholeProof(t, f))
	if err != nil {
		t.Fatal(err)
	}
	p, err := DecodeCoverageProof(raw)
	if err != nil {
		t.Fatal(err)
	}
	p.LatenessSeconds++
	if _, _, err := validateFiles(f, p); !errors.Is(err, ErrProof) {
		t.Fatalf("changed proof retained its original provenance: %v, want ErrProof", err)
	}
}

func TestBundleSnapshotsProofBeforeCallbacks(t *testing.T) {
	f := buildBundle(t, bundleStages{})
	m, err := DecodeManifest(f.raw)
	if err != nil {
		t.Fatal(err)
	}
	p := wholeProof(t, f)
	sites, err := ValidateBundle(BundleInput{Manifest: m, Proof: p,
		Volume: bytes.NewReader(f.volume), Records: bytes.NewReader(f.records)}, 1,
		BundleVisitor{Volume: func(Volume) error {
			p.Sites[0].Spans[0].To = periodTo + 100
			return nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	want := []Span{{From: periodFrom, To: periodTo}}
	if !reflect.DeepEqual(sites[0].Coverage, want) || !reflect.DeepEqual(sites[0].Certified, want) {
		t.Fatalf("callback rewrote validated proof: %+v", sites[0])
	}
}

func TestBundleVisitorCannotRewriteValidatedSites(t *testing.T) {
	f := buildBundle(t, bundleStages{})
	m, err := DecodeManifest(f.raw)
	if err != nil {
		t.Fatal(err)
	}
	sites, err := ValidateBundle(BundleInput{Manifest: m, Proof: wholeProof(t, f),
		Volume: bytes.NewReader(f.volume), Records: bytes.NewReader(f.records)}, 1,
		BundleVisitor{Sites: func(sites []BundleSite) error {
			sites[0].Site = bundleSiteB
			sites[0].Extent.From--
			sites[0].Certified[0].To++
			sites[0].Coverage[0].To++
			sites[0].Excluded[ExcludedUnknownLoss] = 1
			return nil
		}})
	if err != nil {
		t.Fatalf("visitor changed internal validation state: %v", err)
	}
	if sites[0].Site != bundleSiteA || *sites[0].Extent != *m.Sites[0].Extent ||
		!reflect.DeepEqual(sites[0].Coverage, []Span{{From: periodFrom, To: periodTo}}) ||
		!reflect.DeepEqual(sites[0].Certified, sites[0].Coverage) || len(sites[0].Excluded) != 0 {
		t.Fatalf("visitor rewrote returned validation results: %+v", sites[0])
	}
}
