package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"testing"

	"github.com/pidginhost/csm/internal/crawlreplay"
)

func TestCalibrateCoveragePreservesEpisodes(t *testing.T) {
	for _, tc := range []struct {
		name     string
		from, to int64
		detected bool
	}{
		{name: "onset excluded", from: 60, to: 64, detected: true},
		{name: "episode excluded", from: 60, to: 79},
		{name: "site excluded", from: 0, to: 79},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := writeBundle(t, bundleOptions{spans: func(p crawlreplay.Span) ([]crawlreplay.Span, []crawlreplay.Exclusion) {
				from, to := p.From+tc.from, p.From+tc.to
				spans := []crawlreplay.Span{}
				if from > p.From {
					spans = append(spans, crawlreplay.Span{From: p.From, To: from - 1})
				}
				if to < p.To {
					spans = append(spans, crawlreplay.Span{From: to + 1, To: p.To})
				}
				return spans, []crawlreplay.Exclusion{{From: from, To: to, Reason: crawlreplay.ExcludedCollectionGap}}
			}})
			// The origin is the first labeled request in the actual bundle,
			// including records whose minutes cannot enter detector windows.
			var onset int64
			var episode string
			_, err := crawlreplay.ReadBundleFile(bytes.NewReader(mustRead(t, b.records)), func(r io.Reader) error {
				return crawlreplay.ReadRecords(r, func(rec crawlreplay.Record) error {
					if rec.Site == attackSite && rec.Episode != "" && (onset == 0 || rec.T < onset) {
						onset, episode = rec.T, rec.Episode
					}
					return nil
				})
			})
			if err != nil || onset == 0 {
				t.Fatalf("episode origin: onset %d, error %v", onset, err)
			}
			if err = run(b.args(), testEnv()); err != nil {
				t.Fatal(err)
			}
			rep := readReport(t, b.out)
			if got := rep.Coverage[0].CoveredMinutes; got != 80-(tc.to-tc.from+1) {
				t.Fatalf("covered minutes = %d", got)
			}
			result := rep.Runs[0]
			if len(result.Episodes) != 1 {
				t.Fatalf("episodes = %+v; excluded episodes must remain visible", result.Episodes)
			}
			ep := result.Episodes[0]
			if ep.Site != attackSite || ep.Episode != episode || ep.Label != crawlreplay.LabelAttack || ep.Onset != onset || ep.Detected != tc.detected {
				t.Fatalf("episode = %+v; want onset %d, detected %t", ep, onset, tc.detected)
			}
			if tc.detected {
				if want := (ep.DetectMinute+1)*60 - onset; ep.DelaySeconds != want {
					t.Fatalf("delay = %d, want %d from the original onset", ep.DelaySeconds, want)
				}
			} else if ep.DelaySeconds != 0 || ep.DetectMinute != 0 || ep.Best != (crawlreplay.Margin{}) || result.Anomalous != 0 {
				t.Fatalf("excluded traffic entered replay: %+v", result)
			}
		})
	}
}

func TestCalibrateEmptySiteNeedsCertifiedCoverage(t *testing.T) {
	for _, certified := range []bool{false, true} {
		name := "unqualified"
		if certified {
			name = "certified"
		}
		t.Run(name, func(t *testing.T) {
			b := writeBundle(t, bundleOptions{})
			m, err := crawlreplay.DecodeManifest(mustRead(t, b.manifest))
			if err != nil {
				t.Fatal(err)
			}
			const emptySite = "dom-000002.example"
			emptyDigest := sha256.Sum256(nil)
			digest := hex.EncodeToString(emptyDigest[:])
			m.Inputs = append(m.Inputs, crawlreplay.Input{Site: emptySite, SHA256: digest, ContentSHA256: digest})
			m.Sites = append(m.Sites, crawlreplay.SiteManifest{Site: emptySite, Account: "acct-000002",
				Labels: map[string]int64{}, Untimed: []crawlreplay.UntimedLoss{}})
			raw, err := crawlreplay.EncodeManifest(m)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(b.manifest, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			args := []string{"--manifest", b.manifest, "--records", b.records, "--volume", b.volume, "--window", "10", "--out", b.out}
			if certified {
				proof, proofErr := crawlreplay.DecodeCoverageProof(mustRead(t, b.coverage))
				if proofErr != nil {
					t.Fatal(proofErr)
				}
				sum := sha256.Sum256(raw)
				proof.ManifestSHA256 = hex.EncodeToString(sum[:])
				proof.Sites = append(proof.Sites, crawlreplay.ProofSite{Site: emptySite, Spans: []crawlreplay.Span{m.Period}})
				raw, err = json.Marshal(proof)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(b.coverage, raw, 0o600); err != nil {
					t.Fatal(err)
				}
				args = append(args, "--coverage", b.coverage)
			}
			if err = run(args, testEnv()); err != nil {
				t.Fatal(err)
			}
			rep := readReport(t, b.out)
			if rep.Sites != 3 || len(rep.Coverage) != 3 || len(rep.Silences) != 3 {
				t.Fatalf("empty site lost: %+v", rep)
			}
			sc := rep.Coverage[2]
			wantMinutes, wantWindows := int64(0), 142
			if certified {
				wantMinutes, wantWindows = 80, 213
			}
			if sc.Site != emptySite || sc.Extent != nil || sc.CertifiedMinutes != wantMinutes || sc.CoveredMinutes != wantMinutes || sc.Lines["records"] != 0 {
				t.Fatalf("empty site coverage = %+v", sc)
			}
			found := false
			for _, silence := range rep.Silences {
				if silence.Site == emptySite {
					found = true
					if silence.Minutes != wantMinutes {
						t.Fatalf("empty site silence = %+v", silence)
					}
				}
			}
			if !found {
				t.Fatal("empty site missing from silence diagnostics")
			}
			if rep.Shape.WindowBindings.N != wantWindows {
				t.Fatalf("shape windows = %+v, want %d samples", rep.Shape.WindowBindings, wantWindows)
			}
		})
	}
}

func TestCalibrationLatenessIncludesExcludedRecords(t *testing.T) {
	for _, tc := range []struct {
		name     string
		coverage []crawlreplay.Span
	}{
		{name: "newer witness excluded", coverage: []crawlreplay.Span{{From: 100, To: 100}}},
		{name: "late record excluded", coverage: []crawlreplay.Span{{From: 103, To: 103}}},
		{name: "all records excluded"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newCalibration(1, grid{}, true)
			if err := c.sites([]crawlreplay.BundleSite{{Site: attackSite, Coverage: tc.coverage}}); err != nil {
				t.Fatal(err)
			}
			// File 0 has a three-minute inversion. File 1 starts with an
			// earlier timestamp but must not inherit file 0's watermark.
			for i, minute := range []int64{103, 100, 99} {
				r := crawlreplay.NewSynth(attackSite, 1).Pool(crawlreplay.Traffic{From: minute, To: minute, PerMinute: 1}, 1)[0]
				r.T, r.Seq = minute*60+10, int64(i+1)
				if i == 2 {
					r.File = 1
				}
				if err := c.record(r); err != nil {
					t.Fatal(err)
				}
			}
			if err := c.flush(); err != nil {
				t.Fatal(err)
			}
			sh := c.shapes.report()
			if want := (crawlreplay.Quantiles{N: 3, P50: 0, P99: 180, Max: 180}); sh.Lateness != want {
				t.Errorf("lateness = %+v, want %+v", sh.Lateness, want)
			}
			want := crawlreplay.Quantiles{}
			if len(tc.coverage) > 0 {
				want = crawlreplay.Quantiles{N: 1, P50: 1, P99: 1, Max: 1}
			}
			if sh.WindowBindings != want || sh.WindowKeys[3] != want {
				t.Fatalf("excluded records entered shape windows: %+v", sh)
			}
		})
	}
}
