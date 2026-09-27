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
	"testing"

	"github.com/pidginhost/csm/internal/crawlreplay"
)

type bundle struct{ dir, manifest, records, volume, grid, out string }

// writeBundle stores two synthetic sites the way domlog-stream would: one
// quiet healthy site and one with a labeled attack.
func writeBundle(t *testing.T, swapOrder bool) bundle {
	t.Helper()
	dir := t.TempDir()
	b := bundle{dir: dir, manifest: filepath.Join(dir, "manifest.json"), records: filepath.Join(dir, "records.jsonl.gz"),
		volume: filepath.Join(dir, "volume.jsonl.gz"), grid: filepath.Join(dir, "grid.json"), out: filepath.Join(dir, "report.json")}
	attackSite := crawlreplay.Fixture{Name: "e1", Train: 60, Background: 2, Pool: 5, Minutes: 20, PerMinute: 200, Q: 3, Seed: 1}.Site()
	quiet := crawlreplay.NewSynth("dom-000001.example", 2).Pool(crawlreplay.Traffic{
		From: attackSite.Coverage[0].From, To: attackSite.Coverage[0].To, PerMinute: 1, Label: crawlreplay.LabelHealthy}, 3)
	for i := range quiet {
		quiet[i].Seq = int64(i + 1)
	}
	sites := [][]crawlreplay.Record{attackSite.Records, quiet}
	if swapOrder {
		sites = [][]crawlreplay.Record{attackSite.Records[:10], quiet, attackSite.Records[10:]}
	}
	var recBuf, volBuf bytes.Buffer
	rz, vz := gzip.NewWriter(&recBuf), gzip.NewWriter(&volBuf)
	volume := map[string]map[int64]int64{}
	for _, recs := range sites {
		for _, r := range recs {
			if err := crawlreplay.WriteRow(rz, r); err != nil {
				t.Fatal(err)
			}
			if volume[r.Site] == nil {
				volume[r.Site] = map[int64]int64{}
			}
			volume[r.Site][r.T/60]++
		}
	}
	for site, minutes := range volume {
		for m, n := range minutes {
			if err := crawlreplay.WriteRow(vz, crawlreplay.Volume{Site: site, Minute: m, Lines: n, Bytes: n * 100}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := errors.Join(rz.Close(), vz.Close()); err != nil {
		t.Fatal(err)
	}
	for path, data := range map[string][]byte{b.records: recBuf.Bytes(), b.volume: volBuf.Bytes()} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	digest := func(data []byte) string { s := sha256.Sum256(data); return hex.EncodeToString(s[:]) }
	m := map[string]any{
		"format_version": 1, "stream_version": crawlreplay.StreamVersion,
		"outputs": []map[string]string{{"kind": "records", "sha256": digest(recBuf.Bytes())}, {"kind": "volume", "sha256": digest(volBuf.Bytes())}},
		"sites": []map[string]any{
			{"site": "dom-000000.example", "coverage": attackSite.Coverage},
			{"site": "dom-000001.example", "coverage": attackSite.Coverage},
		},
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b.manifest, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	g := `{"runs":[{"params":{"w":10,"r":3,"f":5,"k":20,"d":50,"c":80,"baseline":{"alpha":0.1,"min_obs":1,"min_age":10080,"floor_per_min":1}},
	  "sketch":{"m":64,"h":128,"seed":7},"shuffle":3}],
	  "fixtures":[{"name":"q20","train":60,"background":2,"pool":5,"minutes":20,"per_minute":300,"q":20,"padding_sources":20,"padding_per_source":100,"churn":true,"seed":4}]}`
	if err := os.WriteFile(b.grid, []byte(g), 0o600); err != nil {
		t.Fatal(err)
	}
	return b
}

func (b bundle) args() []string {
	return []string{"--manifest", b.manifest, "--records", b.records, "--volume", b.volume, "--window", "10", "--grid", b.grid, "--out", b.out}
}

func TestCalibrateReport(t *testing.T) {
	b := writeBundle(t, false)
	if err := run(b.args()); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(b.out)
	if err != nil {
		t.Fatal(err)
	}
	var rep report
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Sites != 2 || rep.Volume.LinesPerMinute.N != 80 || rep.Shape.WindowKeys[1].N == 0 {
		t.Fatalf("volume/shape = %+v %+v", rep.Volume, rep.Shape)
	}
	if len(rep.Silences) != 2 || rep.Silences[0].Minutes < rep.Silences[1].Minutes {
		t.Fatalf("silences = %+v", rep.Silences)
	}
	if len(rep.Runs) != 1 {
		t.Fatalf("runs = %d", len(rep.Runs))
	}
	r := rep.Runs[0]
	if len(r.Episodes) != 1 || !r.Episodes[0].Detected || r.Episodes[0].Site != "dom-000000.example" {
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
		want int64
	}{
		{name: "adjacent", want: 7},
		{name: "gap", gap: true, want: 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := writeBundle(t, false)
			m, err := loadManifest(b.manifest, map[string]string{"records": b.records, "volume": b.volume})
			if err != nil {
				t.Fatal(err)
			}
			original := m.Sites[0].Coverage[0]
			// Seven unlogged minutes precede the first row. Splitting those
			// minutes must not shorten the silence unless a minute is unknown.
			m.Sites[0].Coverage = []crawlreplay.Span{
				{From: original.From - 7, To: original.From - 4},
				{From: original.From - 3, To: original.From - 2},
				{From: original.From - 1, To: original.To},
			}
			if tc.gap {
				m.Sites[0].Coverage[1].From++
			}
			raw, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(b.manifest, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if err = run(b.args()); err != nil {
				t.Fatal(err)
			}
			raw, err = os.ReadFile(b.out)
			if err != nil {
				t.Fatal(err)
			}
			var rep report
			if err := json.Unmarshal(raw, &rep); err != nil {
				t.Fatal(err)
			}
			want := []siteSilence{{Site: m.Sites[0].Site, Minutes: tc.want}, {Site: m.Sites[1].Site}}
			if !slices.Equal(rep.Silences, want) {
				t.Fatalf("silences = %+v, want %+v", rep.Silences, want)
			}
		})
	}
}

func TestCalibrateRefusals(t *testing.T) {
	b := writeBundle(t, false)
	if err := os.WriteFile(b.records, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(b.args()); !errors.Is(err, errManifest) {
		t.Fatalf("tampered bundle: %v", err)
	}
	split := writeBundle(t, true)
	if err := run(split.args()); !errors.Is(err, errBundle) {
		t.Fatalf("site split across the stream: %v", err)
	}
	g := writeBundle(t, false)
	if err := os.WriteFile(g.grid, []byte(`{"runs":[{"params":{"w":10,"r":1,"f":5,"k":20,"d":50,"c":80,"baseline":{"alpha":0.1,"min_obs":1,"floor_per_min":1}}}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(g.args()); !errors.Is(err, errGrid) {
		t.Fatalf("R <= 1: %v", err)
	}
	o := writeBundle(t, false)
	if err := os.WriteFile(o.out, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(o.args()); !errors.Is(err, errOutput) {
		t.Fatalf("existing report: %v", err)
	}
	if err := run([]string{"--window", "0"}); !errors.Is(err, errUsage) {
		t.Fatalf("usage: %v", err)
	}
}

func TestGridRejectsTrailingJSON(t *testing.T) {
	b := writeBundle(t, false)
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
