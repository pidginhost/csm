package main

import (
	"bytes"
	"cmp"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/crawlreplay"
)

const (
	attackSite    = "dom-000000.example" // the site crawlreplay.Fixture generates
	quietSite     = "dom-000001.example"
	attackAccount = "acct-000000"
	quietAccount  = "acct-000001"
	attackEpisode = "e-00000000000000e1"
)

func calibratorTool() crawlreplay.ToolRevision {
	return crawlreplay.ToolRevision{Revision: strings.Repeat("d", 40), GoVersion: "go-test"}
}

func testEnv() env { return env{revision: calibratorTool} }

type bundle struct {
	dir, manifest, records, volume, coverage, out string
	period                                        crawlreplay.Span
}

// bundleOptions shape a synthetic bundle: split the attack site around the
// quiet one in the stream, pad the period before the first request, or
// replace the coverage proof's spans for the attack site.
type bundleOptions struct {
	swapOrder bool
	pad       int64
	spans     func(period crawlreplay.Span) ([]crawlreplay.Span, []crawlreplay.Exclusion)
}

// writeBundle stores two synthetic sites the way domlog-stream would, one
// quiet healthy site and one with a labeled attack, with a canonical
// manifest and a proof that certifies the whole period.
func writeBundle(t *testing.T, o bundleOptions) bundle {
	t.Helper()
	attack := crawlreplay.Fixture{Name: attackEpisode, Train: 60, Background: 2, Pool: 5, Minutes: 20, PerMinute: 200, Q: 3, Seed: 1}.Site()
	period := crawlreplay.Span{From: attack.Coverage[0].From - o.pad, To: attack.Coverage[0].To}
	quiet := crawlreplay.NewSynth(quietSite, 2).Pool(crawlreplay.Traffic{
		From: attack.Coverage[0].From, To: period.To, PerMinute: 1, Label: crawlreplay.LabelHealthy}, 3)
	sites := []siteRecords{{attackSite, attackAccount, attack.Records}, {quietSite, quietAccount, quiet}}
	return encodeBundle(t, t.TempDir(), period, sites, o)
}

type siteRecords struct {
	name, account string
	recs          []crawlreplay.Record
}

// encodeBundle writes sites the way domlog-stream would, each site's
// records in time order under one input, with a canonical manifest that
// declares their identities and a proof certifying the whole period. Only
// o.swapOrder (split the first site around the second in the stream) and
// o.spans (the first site's certified spans) apply.
func encodeBundle(t *testing.T, dir string, period crawlreplay.Span, sites []siteRecords, o bundleOptions) bundle {
	t.Helper()
	b := bundle{dir: dir, manifest: filepath.Join(dir, "manifest.json"), records: filepath.Join(dir, "records.jsonl.gz"),
		volume: filepath.Join(dir, "volume.jsonl.gz"), coverage: filepath.Join(dir, "coverage.json"), out: filepath.Join(dir, "report.json"),
		period: period}
	// A copy lists requests in completion order; write each site's records
	// in time order, as the converter would, so the copies show no disorder.
	for _, s := range sites {
		slices.SortStableFunc(s.recs, func(a, b crawlreplay.Record) int { return cmp.Compare(a.T, b.T) })
		for i := range s.recs {
			s.recs[i].Seq, s.recs[i].Account = int64(i+1), s.account
		}
	}
	stream := make([][]crawlreplay.Record, 0, len(sites)+1)
	for _, s := range sites {
		stream = append(stream, s.recs)
	}
	if o.swapOrder {
		stream = append([][]crawlreplay.Record{sites[0].recs[:10], sites[1].recs, sites[0].recs[10:]}, stream[2:]...)
	}
	var recBuf, volBuf bytes.Buffer
	rz, vz := gzip.NewWriter(&recBuf), gzip.NewWriter(&volBuf)
	type siteMinute struct {
		site   string
		minute int64
	}
	lines := map[siteMinute]int64{}
	var order []siteMinute
	var records int64
	for _, recs := range stream {
		for _, r := range recs {
			if err := crawlreplay.WriteRow(rz, r); err != nil {
				t.Fatal(err)
			}
			key := siteMinute{r.Site, r.T / 60}
			if lines[key] == 0 {
				order = append(order, key)
			}
			lines[key]++
			records++
		}
	}
	for _, key := range order {
		if err := crawlreplay.WriteRow(vz, crawlreplay.Volume{Site: key.site, Minute: key.minute, Lines: lines[key], Bytes: lines[key] * 100}); err != nil {
			t.Fatal(err)
		}
	}
	if err := errors.Join(rz.Close(), vz.Close()); err != nil {
		t.Fatal(err)
	}
	digest := func(data []byte) string { s := sha256.Sum256(data); return hex.EncodeToString(s[:]) }
	m := crawlreplay.Manifest{
		FormatVersion: crawlreplay.ManifestVersion, StreamVersion: crawlreplay.StreamVersion, IdentityVersion: 1,
		Tool:            crawlreplay.ToolRevision{Revision: strings.Repeat("a", 40), GoVersion: "go-test"},
		SaltFingerprint: "0123456789ab", Period: period, Inventory: crawlreplay.Digest{SHA256: strings.Repeat("1", 64), Bytes: 10},
		Outputs: []crawlreplay.Output{
			{Kind: "records", SHA256: digest(recBuf.Bytes()), Bytes: int64(recBuf.Len()), Rows: records},
			{Kind: "volume", SHA256: digest(volBuf.Bytes()), Bytes: int64(volBuf.Len()), Rows: int64(len(order))},
		},
	}
	named := map[string]bool{}
	proof := crawlreplay.CoverageProof{FormatVersion: crawlreplay.ProofVersion, LatenessSeconds: 60,
		Evidence: []crawlreplay.ProofEvidence{{Kind: crawlreplay.EvidenceCollection, SHA256: strings.Repeat("6", 64)},
			{Kind: crawlreplay.EvidenceLiveness, SHA256: strings.Repeat("7", 64)}, {Kind: crawlreplay.EvidenceLateness, SHA256: strings.Repeat("8", 64)}}}
	for i, s := range sites {
		sm := crawlreplay.SiteManifest{Site: s.name, Account: s.account, Labels: map[string]int64{}, Untimed: []crawlreplay.UntimedLoss{}}
		in := crawlreplay.Input{Site: s.name, SHA256: strings.Repeat(fmt.Sprintf("%x", 2*i+2), 64), Bytes: 1,
			ContentSHA256: strings.Repeat(fmt.Sprintf("%x", 2*i+3), 64), ContentBytes: int64(len(s.recs)) * 100}
		named[s.name], named[s.account] = true, true
		for _, r := range s.recs {
			sm.Records++
			sm.Labels[r.Label]++
			if r.Episode != "" {
				named[r.Episode] = true
			}
			minute := r.T / 60
			if sm.Extent == nil {
				sm.Extent = &crawlreplay.Span{From: minute, To: minute}
			}
			sm.Extent.From, sm.Extent.To = min(sm.Extent.From, minute), max(sm.Extent.To, minute)
		}
		sm.Lines, sm.Bytes = sm.Records, sm.Records*100
		// Each site has one input, so its extent is the site's.
		if sm.Extent != nil {
			extent := *sm.Extent
			in.Extent = &extent
		}
		m.Sites, m.Inputs = append(m.Sites, sm), append(m.Inputs, in)
		ps := crawlreplay.ProofSite{Site: s.name, Spans: []crawlreplay.Span{period}}
		if i == 0 && o.spans != nil {
			ps.Spans, ps.Excluded = o.spans(period)
		}
		proof.Sites = append(proof.Sites, ps)
	}
	for _, name := range slices.Sorted(maps.Keys(named)) {
		m.Identities = append(m.Identities, testIdentity(name))
	}
	raw, err := crawlreplay.EncodeManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	proof.ManifestSHA256 = digest(raw)
	proofRaw, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	for path, data := range map[string][]byte{b.records: recBuf.Bytes(), b.volume: volBuf.Bytes(), b.manifest: raw, b.coverage: proofRaw} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return b
}

// testIdentity pads a pseudonym's hexadecimal part into its digest.
func testIdentity(pseudonym string) crawlreplay.Identity {
	hexPart := strings.TrimSuffix(pseudonym, ".example")
	for _, prefix := range []string{"dom-", "acct-", "e-"} {
		hexPart = strings.TrimPrefix(hexPart, prefix)
	}
	return crawlreplay.Identity{Pseudonym: pseudonym, Digest: hexPart + strings.Repeat("f", 64-len(hexPart))}
}

// attackKeys are the fixture attack's L1 key and its ancestors: the truth
// of a detection.
var attackKeys = []crawlreplay.KeyID{
	{Level: 1, Key: crawlreplay.SynthKey(3), Parent: crawlreplay.SynthKey(1)}, {Level: 2, Key: crawlreplay.SynthKey(1)}, {Level: 3},
}

// entry is the bundle in an experiment, declared normal for its whole
// period and, when scoring, scored over all of it.
func (b bundle) entry(role string) experimentBundle {
	e := experimentBundle{Manifest: b.manifest, Records: b.records, Volume: b.volume, Coverage: b.coverage, Role: role,
		States: []experimentState{{From: b.period.From, To: b.period.To, State: crawlreplay.StateNormal}}}
	if role == roleScoring {
		e.Score = []crawlreplay.Span{b.period}
	}
	return e
}

// experiment replays the bundle alone, scored, with one sketch run, one
// synthetic fixture and the attack's truth.
func (b bundle) experiment() experiment {
	return experiment{FormatVersion: experimentVersion, IdentityVersion: 1, Window: 10,
		Runs: []gridRun{{Params: crawlreplay.Params{W: 10, R: 3, F: 5, K: 20, D: 50, C: 80,
			Baseline: crawlreplay.BaselineParams{Alpha: 0.1, MinObs: 1, MinAge: 10080, FloorPerMin: 1}},
			Sketch: &crawlreplay.SketchParams{M: 64, H: 128, Seed: 7}, Shuffle: 3}},
		Fixtures: []crawlreplay.Fixture{{Name: "q20", Train: 60, Background: 2, Pool: 5, Minutes: 20, PerMinute: 300, Q: 20,
			PaddingSources: 20, PaddingPerSource: 100, Churn: true, Seed: 4}},
		Bundles: []experimentBundle{b.entry(roleScoring)},
		Truth:   []crawlreplay.EpisodeTruth{{Episode: attackEpisode, Label: crawlreplay.LabelAttack, Site: attackSite, Keys: attackKeys}},
	}
}

// with writes x beside the bundle and returns arguments that replay it.
func (b bundle) with(t *testing.T, x experiment) []string {
	t.Helper()
	raw, err := json.Marshal(x)
	if err != nil {
		t.Fatal(err)
	}
	return b.withRaw(t, raw)
}

func (b bundle) withRaw(t *testing.T, raw []byte) []string {
	t.Helper()
	f, err := os.CreateTemp(b.dir, "experiment-*.json")
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := f.Write(raw)
	if err := errors.Join(writeErr, f.Close()); err != nil {
		t.Fatal(err)
	}
	return []string{"--experiment", f.Name(), "--out", b.out}
}

func (b bundle) args(t *testing.T) []string { return b.with(t, b.experiment()) }

func readReport(t *testing.T, path string) report {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rep report
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatal(err)
	}
	return rep
}

func TestCalibrateReport(t *testing.T) {
	b := writeBundle(t, bundleOptions{})
	if err := run(b.args(t), testEnv()); err != nil {
		t.Fatal(err)
	}
	rep := readReport(t, b.out)
	if rep.Sites != 2 || rep.Volume.LinesPerMinute.N != 80 || rep.Shape.WindowKeys[1].N == 0 {
		t.Fatalf("volume/shape = %+v %+v", rep.Volume, rep.Shape)
	}
	if rep.Provenance.Coverage != coverageCertified || len(rep.Coverage) != 2 || rep.Coverage[0].CoveredMinutes != 80 {
		t.Fatalf("coverage = %+v %+v", rep.Provenance, rep.Coverage)
	}
	if len(rep.Silences) != 2 || rep.Silences[0].Minutes < rep.Silences[1].Minutes {
		t.Fatalf("silences = %+v", rep.Silences)
	}
	if len(rep.Runs) != 1 {
		t.Fatalf("runs = %d", len(rep.Runs))
	}
	r := rep.Runs[0]
	if len(r.Scoring.Episodes) != 1 || !r.Scoring.Episodes[0].Detected || r.Scoring.Episodes[0].Site != attackSite ||
		r.Exact == nil || len(r.Exact.Episodes) != 1 || !r.Exact.Episodes[0].Detected {
		t.Fatalf("episodes = %+v, exact %+v", r.Scoring.Episodes, r.Exact)
	}
	if r.Sketch == nil || r.Sketch.Exceeded != 0 || r.FootprintBytes <= 0 {
		t.Fatalf("sketch = %+v footprint %d", r.Sketch, r.FootprintBytes)
	}
	if len(r.Fixtures) != 1 || r.Fixtures[0].Fixture != "q20" || r.Fixtures[0].Episode.Episode != "q20" {
		t.Fatalf("fixtures = %+v", r.Fixtures)
	}
	for _, e := range r.Scoring.Events {
		if e.Site != attackSite || len(e.Credited) != 1 {
			t.Fatalf("healthy traffic raised a finding: %+v", e)
		}
	}
	for _, d := range r.Scoring.SiteDays {
		if d.Site == quietSite && (d.Events != 0 || d.Requests[crawlreplay.LabelHealthy] == 0) {
			t.Fatalf("quiet site day %+v", d)
		}
	}
}

func TestCalibrateSilenceAcrossCoverageSpans(t *testing.T) {
	for _, tc := range []struct {
		name string
		gap  bool
		want []siteSilence
	}{
		{name: "adjacent", want: []siteSilence{{Site: attackSite, Minutes: 7}, {Site: quietSite, Minutes: 7}}},
		{name: "gap", gap: true, want: []siteSilence{{Site: quietSite, Minutes: 7}, {Site: attackSite, Minutes: 4}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Seven unlogged minutes precede the first row. Splitting those
			// minutes must not shorten the silence unless a minute is unknown.
			b := writeBundle(t, bundleOptions{pad: 7, spans: func(p crawlreplay.Span) ([]crawlreplay.Span, []crawlreplay.Exclusion) {
				spans := []crawlreplay.Span{{From: p.From, To: p.From + 3}, {From: p.From + 4, To: p.From + 5}, {From: p.From + 6, To: p.To}}
				if !tc.gap {
					return spans, nil
				}
				spans[1].From++
				return spans, []crawlreplay.Exclusion{{From: p.From + 4, To: p.From + 4, Reason: crawlreplay.ExcludedLivenessUnknown}}
			}})
			if err := run(b.args(t), testEnv()); err != nil {
				t.Fatal(err)
			}
			if rep := readReport(t, b.out); !slices.Equal(rep.Silences, tc.want) {
				t.Fatalf("silences = %+v, want %+v", rep.Silences, tc.want)
			}
		})
	}
}

// A manifest is operator-editable. Its site list must hold the same closed
// pseudonyms as the records, or a hand-edited raw name would reach the report.
func TestCalibrateRefusesNonPseudonymManifestSites(t *testing.T) {
	for name, site := range map[string]string{
		"raw name":  "secret-customer.example",
		"duplicate": quietSite,
	} {
		t.Run(name, func(t *testing.T) {
			b := writeBundle(t, bundleOptions{})
			m, err := crawlreplay.DecodeManifest(mustRead(t, b.manifest))
			if err != nil {
				t.Fatal(err)
			}
			m.Sites[0].Site = site
			raw, err := json.MarshalIndent(m, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(b.manifest, append(raw, '\n'), 0o600); err != nil {
				t.Fatal(err)
			}
			if err = run(b.args(t), testEnv()); !errors.Is(err, errManifest) {
				t.Fatalf("manifest site %q: %v, want errManifest", site, err)
			}
			if _, err = os.Stat(b.out); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("refused manifest still wrote a report: %v", err)
			}
		})
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCalibrateRefusals(t *testing.T) {
	b := writeBundle(t, bundleOptions{})
	if err := os.WriteFile(b.records, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(b.args(t), testEnv()); !errors.Is(err, errBundle) {
		t.Fatalf("tampered bundle: %v", err)
	}
	split := writeBundle(t, bundleOptions{swapOrder: true})
	if err := run(split.args(t), testEnv()); !errors.Is(err, errBundle) {
		t.Fatalf("site split across the stream: %v", err)
	}
	g := writeBundle(t, bundleOptions{})
	x := g.experiment()
	x.Runs[0].Params.R = 1
	if err := run(g.with(t, x), testEnv()); !errors.Is(err, errGrid) {
		t.Fatalf("R <= 1: %v", err)
	}
	o := writeBundle(t, bundleOptions{})
	if err := os.WriteFile(o.out, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(o.args(t), testEnv()); !errors.Is(err, errOutput) {
		t.Fatalf("existing report: %v", err)
	}
	for _, args := range [][]string{{"--experiment", "x"}, {"--out", "x"}, {"--window", "10"}} {
		if err := run(args, testEnv()); !errors.Is(err, errUsage) {
			t.Fatalf("usage %v: %v", args, err)
		}
	}
	d := writeBundle(t, bundleOptions{})
	if err := run(d.args(t), env{revision: func() crawlreplay.ToolRevision { return crawlreplay.ToolRevision{Dirty: true} }}); !errors.Is(err, errDirtyBuild) {
		t.Fatalf("dirty build: %v", err)
	}
}

func TestExperimentRejectsTrailingJSON(t *testing.T) {
	b := writeBundle(t, bundleOptions{})
	raw, err := json.Marshal(b.experiment())
	if err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"null", "{}", "]"} {
		if err := run(b.withRaw(t, append(append([]byte{}, raw...), suffix...)), testEnv()); !errors.Is(err, errExperiment) {
			t.Fatalf("trailing JSON accepted: %v", err)
		}
	}
}
