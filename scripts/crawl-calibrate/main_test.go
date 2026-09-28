package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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
)

func calibratorTool() crawlreplay.ToolRevision {
	return crawlreplay.ToolRevision{Revision: strings.Repeat("d", 40), GoVersion: "go-test"}
}

func testEnv() env { return env{revision: calibratorTool} }

type bundle struct{ dir, manifest, records, volume, coverage, grid, out string }

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
	dir := t.TempDir()
	b := bundle{dir: dir, manifest: filepath.Join(dir, "manifest.json"), records: filepath.Join(dir, "records.jsonl.gz"),
		volume: filepath.Join(dir, "volume.jsonl.gz"), coverage: filepath.Join(dir, "coverage.json"),
		grid: filepath.Join(dir, "grid.json"), out: filepath.Join(dir, "report.json")}
	attack := crawlreplay.Fixture{Name: "e1", Train: 60, Background: 2, Pool: 5, Minutes: 20, PerMinute: 200, Q: 3, Seed: 1}.Site()
	period := crawlreplay.Span{From: attack.Coverage[0].From - o.pad, To: attack.Coverage[0].To}
	quiet := crawlreplay.NewSynth(quietSite, 2).Pool(crawlreplay.Traffic{
		From: attack.Coverage[0].From, To: period.To, PerMinute: 1, Label: crawlreplay.LabelHealthy}, 3)
	for i := range attack.Records {
		attack.Records[i].Account = attackAccount
	}
	for i := range quiet {
		quiet[i].Seq, quiet[i].Account = int64(i+1), quietAccount
	}
	sites := [][]crawlreplay.Record{attack.Records, quiet}
	if o.swapOrder {
		sites = [][]crawlreplay.Record{attack.Records[:10], quiet, attack.Records[10:]}
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
	for _, recs := range sites {
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
		Inputs: []crawlreplay.Input{
			{Site: attackSite, SHA256: strings.Repeat("2", 64), Bytes: 1, ContentSHA256: strings.Repeat("3", 64), ContentBytes: int64(len(attack.Records)) * 100},
			{Site: quietSite, SHA256: strings.Repeat("4", 64), Bytes: 1, ContentSHA256: strings.Repeat("5", 64), ContentBytes: int64(len(quiet)) * 100},
		},
		Outputs: []crawlreplay.Output{
			{Kind: "records", SHA256: digest(recBuf.Bytes()), Bytes: int64(recBuf.Len()), Rows: records},
			{Kind: "volume", SHA256: digest(volBuf.Bytes()), Bytes: int64(volBuf.Len()), Rows: int64(len(order))},
		},
	}
	for _, s := range []struct {
		name, account string
		recs          []crawlreplay.Record
	}{{attackSite, attackAccount, attack.Records}, {quietSite, quietAccount, quiet}} {
		sm := crawlreplay.SiteManifest{Site: s.name, Account: s.account, Labels: map[string]int64{}, Untimed: []crawlreplay.UntimedLoss{}}
		for _, r := range s.recs {
			sm.Records++
			sm.Labels[r.Label]++
			minute := r.T / 60
			if sm.Extent == nil {
				sm.Extent = &crawlreplay.Span{From: minute, To: minute}
			}
			sm.Extent.From, sm.Extent.To = min(sm.Extent.From, minute), max(sm.Extent.To, minute)
		}
		sm.Lines, sm.Bytes = sm.Records, sm.Records*100
		m.Sites = append(m.Sites, sm)
	}
	// Each site has one input, so its extent is the site's.
	for i, s := range m.Sites {
		extent := *s.Extent
		m.Inputs[i].Extent = &extent
	}
	raw, err := crawlreplay.EncodeManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	proof := crawlreplay.CoverageProof{FormatVersion: crawlreplay.ProofVersion, ManifestSHA256: digest(raw), LatenessSeconds: 60,
		Evidence: []crawlreplay.ProofEvidence{{Kind: crawlreplay.EvidenceCollection, SHA256: strings.Repeat("6", 64)},
			{Kind: crawlreplay.EvidenceLiveness, SHA256: strings.Repeat("7", 64)}, {Kind: crawlreplay.EvidenceLateness, SHA256: strings.Repeat("8", 64)}},
		Sites: []crawlreplay.ProofSite{{Site: attackSite, Spans: []crawlreplay.Span{period}}, {Site: quietSite, Spans: []crawlreplay.Span{period}}}}
	if o.spans != nil {
		proof.Sites[0].Spans, proof.Sites[0].Excluded = o.spans(period)
	}
	proofRaw, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	g := `{"runs":[{"params":{"w":10,"r":3,"f":5,"k":20,"d":50,"c":80,"baseline":{"alpha":0.1,"min_obs":1,"min_age":10080,"floor_per_min":1}},
	  "sketch":{"m":64,"h":128,"seed":7},"shuffle":3}],
	  "fixtures":[{"name":"q20","train":60,"background":2,"pool":5,"minutes":20,"per_minute":300,"q":20,"padding_sources":20,"padding_per_source":100,"churn":true,"seed":4}]}`
	for path, data := range map[string][]byte{b.records: recBuf.Bytes(), b.volume: volBuf.Bytes(), b.manifest: raw, b.coverage: proofRaw, b.grid: []byte(g)} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return b
}

func (b bundle) args() []string {
	return []string{"--manifest", b.manifest, "--records", b.records, "--volume", b.volume, "--coverage", b.coverage,
		"--window", "10", "--grid", b.grid, "--out", b.out}
}

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
	if err := run(b.args(), testEnv()); err != nil {
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
	if len(r.Episodes) != 1 || !r.Episodes[0].Detected || r.Episodes[0].Site != attackSite {
		t.Fatalf("episodes = %+v", r.Episodes)
	}
	if r.Sketch == nil || r.Sketch.Exceeded != 0 || r.FootprintBytes <= 0 {
		t.Fatalf("sketch = %+v footprint %d", r.Sketch, r.FootprintBytes)
	}
	if len(r.Fixtures) != 1 || r.Fixtures[0].Fixture != "q20" || r.Fixtures[0].Episode.Episode != "q20" {
		t.Fatalf("fixtures = %+v", r.Fixtures)
	}
	if r.Transitions[crawlreplay.LabelHealthy] != 0 || len(r.FalsePositives) != 0 {
		t.Fatalf("quiet healthy site raised findings: %+v", r.FalsePositives)
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
			if err := run(b.args(), testEnv()); err != nil {
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
			if err = run(b.args(), testEnv()); !errors.Is(err, errManifest) {
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
	if err := run(b.args(), testEnv()); !errors.Is(err, errBundle) {
		t.Fatalf("tampered bundle: %v", err)
	}
	split := writeBundle(t, bundleOptions{swapOrder: true})
	if err := run(split.args(), testEnv()); !errors.Is(err, errBundle) {
		t.Fatalf("site split across the stream: %v", err)
	}
	g := writeBundle(t, bundleOptions{})
	if err := os.WriteFile(g.grid, []byte(`{"runs":[{"params":{"w":10,"r":1,"f":5,"k":20,"d":50,"c":80,"baseline":{"alpha":0.1,"min_obs":1,"floor_per_min":1}}}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(g.args(), testEnv()); !errors.Is(err, errGrid) {
		t.Fatalf("R <= 1: %v", err)
	}
	o := writeBundle(t, bundleOptions{})
	if err := os.WriteFile(o.out, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(o.args(), testEnv()); !errors.Is(err, errOutput) {
		t.Fatalf("existing report: %v", err)
	}
	if err := run([]string{"--window", "0"}, testEnv()); !errors.Is(err, errUsage) {
		t.Fatalf("usage: %v", err)
	}
	d := writeBundle(t, bundleOptions{})
	if err := run(d.args(), env{revision: func() crawlreplay.ToolRevision { return crawlreplay.ToolRevision{Dirty: true} }}); !errors.Is(err, errDirtyBuild) {
		t.Fatalf("dirty build: %v", err)
	}
}

func TestGridRejectsTrailingJSON(t *testing.T) {
	b := writeBundle(t, bundleOptions{})
	data, err := os.ReadFile(b.grid)
	if err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"null", "{}", "]"} {
		if err := os.WriteFile(b.grid, append(append([]byte{}, data...), suffix...), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadGrid(b.grid); !errors.Is(err, errGrid) {
			t.Fatalf("trailing JSON accepted: %v", err)
		}
	}
}
