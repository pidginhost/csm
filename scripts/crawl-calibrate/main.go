// Command crawl-calibrate replays a domlog-stream bundle through the exact
// crawl-detector models and writes an aggregate calibration report.
//
//	crawl-calibrate --manifest manifest.json --records records.jsonl.gz \
//	    --volume volume.jsonl.gz --window 10 [--grid grid.json] --out report.json
//
// It refuses a bundle whose files do not match the manifest digests. The
// report holds load and key-churn distributions, lateness, and for every
// grid run the per-episode detection delay and margins, healthy false
// positives per site-day, key and binding peaks, sketch accuracy and the
// synthetic fixture outcomes. Sites appear only as their pseudonyms. A
// replay is a hypothesis about the detector: phase 1's ledger turns these
// numbers into frozen values, it does not take them as proof of protection.
package main

import (
	"bufio"
	"bytes"
	"cmp"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"

	"github.com/pidginhost/csm/internal/crawlreplay"
)

type cliError string

func (e cliError) Error() string { return string(e) }

const (
	errUsage    cliError = "usage: crawl-calibrate --manifest FILE --records FILE --volume FILE --window MINUTES [--grid FILE] --out FILE"
	errManifest cliError = "manifest is missing, unsupported or does not match the bundle"
	errBundle   cliError = "bundle rows are invalid or out of site order"
	errGrid     cliError = "grid is invalid"
	errOutput   cliError = "report cannot be written or already exists"
)

type bundleManifest struct {
	FormatVersion int `json:"format_version"`
	StreamVersion int `json:"stream_version"`
	Outputs       []struct {
		Kind   string `json:"kind"`
		SHA256 string `json:"sha256"`
	} `json:"outputs"`
	Sites []struct {
		Site     string             `json:"site"`
		Coverage []crawlreplay.Span `json:"coverage"`
	} `json:"sites"`
}

type gridRun struct {
	Params  crawlreplay.Params        `json:"params"`
	Sketch  *crawlreplay.SketchParams `json:"sketch,omitempty"`
	Shuffle uint64                    `json:"shuffle,omitempty"`
}

type grid struct {
	Runs     []gridRun             `json:"runs"`
	Fixtures []crawlreplay.Fixture `json:"fixtures"`
}

type siteEpisode struct {
	Site string `json:"site"`
	crawlreplay.EpisodeResult
}

type siteDay struct {
	Site  string `json:"site"`
	Day   int64  `json:"day"`
	Count int    `json:"count"`
}

type fixtureResult struct {
	Fixture string                      `json:"fixture"`
	Episode crawlreplay.EpisodeResult   `json:"episode"`
	Sketch  *crawlreplay.SketchAccuracy `json:"sketch,omitempty"`
}

type runResult struct {
	Run            gridRun                     `json:"run"`
	FootprintBytes int64                       `json:"footprint_bytes,omitempty"`
	Episodes       []siteEpisode               `json:"episodes"`
	Transitions    map[string]int              `json:"transitions"`
	FalsePositives []siteDay                   `json:"false_positives"`
	Evaluations    int64                       `json:"evaluations"`
	Anomalous      int64                       `json:"anomalous"`
	ScopeLevels    map[uint8]int               `json:"scope_levels"`
	MaxActive      map[uint8]int               `json:"max_active"`
	Keys           map[uint8]int               `json:"keys"`
	MaxBindings    int64                       `json:"max_bindings"`
	Sketch         *crawlreplay.SketchAccuracy `json:"sketch,omitempty"`
	Fixtures       []fixtureResult             `json:"fixtures"`
}

type shapeReport struct {
	Lateness       crawlreplay.Quantiles           `json:"lateness_seconds"`
	WindowKeys     map[uint8]crawlreplay.Quantiles `json:"window_keys"`
	WindowBindings crawlreplay.Quantiles           `json:"window_bindings"`
	NewKeysPerHour map[uint8]crawlreplay.Quantiles `json:"new_keys_per_hour"`
}

type siteSilence struct {
	Site    string `json:"site"`
	Minutes int64  `json:"minutes"`
}

type report struct {
	Window int                    `json:"window"`
	Sites  int                    `json:"sites"`
	Volume crawlreplay.HostVolume `json:"volume"`
	// Silences is each site's longest covered run without a logged line,
	// longest first, for review as possible missing data.
	Silences []siteSilence `json:"silences"`
	Shape    shapeReport   `json:"shape"`
	Runs     []runResult   `json:"runs"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "crawl-calibrate:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("crawl-calibrate", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	manifestPath := fs.String("manifest", "", "")
	recordsPath := fs.String("records", "", "")
	volumePath := fs.String("volume", "", "")
	gridPath := fs.String("grid", "", "")
	outPath := fs.String("out", "", "")
	window := fs.Int("window", 0, "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *manifestPath == "" || *recordsPath == "" ||
		*volumePath == "" || *outPath == "" || *window < 1 {
		return errUsage
	}
	if _, err := os.Lstat(*outPath); !errors.Is(err, os.ErrNotExist) {
		return errOutput
	}
	m, err := loadManifest(*manifestPath, map[string]string{"records": *recordsPath, "volume": *volumePath})
	if err != nil {
		return err
	}
	var g grid
	if *gridPath != "" {
		if g, err = loadGrid(*gridPath); err != nil {
			return err
		}
	}
	rep := report{Window: *window, Sites: len(m.Sites)}
	var volume []crawlreplay.Volume
	if volErr := readGzipRows(*volumePath, func(r io.Reader) error {
		return crawlreplay.ReadVolume(r, func(v crawlreplay.Volume) error { volume = append(volume, v); return nil })
	}); volErr != nil {
		return errBundle
	}
	rep.Volume = crawlreplay.SummarizeVolume(volume)
	logged := map[string][]int64{}
	for _, v := range volume {
		logged[v.Site] = append(logged[v.Site], v.Minute)
	}
	for _, site := range m.Sites {
		minutes := logged[site.Site]
		slices.Sort(minutes)
		var longest int64
		for i := 0; i < len(site.Coverage); i++ {
			span := site.Coverage[i]
			// Only an unknown minute interrupts a continuous observed span.
			for i+1 < len(site.Coverage) && site.Coverage[i+1].From-1 == span.To {
				i++
				span.To = site.Coverage[i].To
			}
			longest = max(longest, crawlreplay.LongestSilence(minutes, span))
		}
		rep.Silences = append(rep.Silences, siteSilence{Site: site.Site, Minutes: longest})
	}
	slices.SortFunc(rep.Silences, func(a, b siteSilence) int {
		return cmp.Or(cmp.Compare(b.Minutes, a.Minutes), cmp.Compare(a.Site, b.Site))
	})
	results := make([]runResult, len(g.Runs))
	for i, gr := range g.Runs {
		results[i] = newRunResult(gr)
	}
	shapes := &shapeAccumulator{lateness: map[int64]int64{}, keys: map[uint8][]float64{}, newKeys: map[uint8][]float64{}}
	coverage := map[string][]crawlreplay.Span{}
	for _, s := range m.Sites {
		coverage[s.Site] = s.Coverage
	}
	done := map[string]bool{}
	var current []crawlreplay.Record
	flush := func() error {
		if len(current) == 0 {
			return nil
		}
		name := current[0].Site
		if done[name] {
			return errBundle
		}
		done[name] = true
		cov, ok := coverage[name]
		if !ok {
			return errBundle
		}
		site := crawlreplay.Site{Records: current, Coverage: cov}
		shapes.add(crawlreplay.ShapeSite(site, *window))
		for i := range g.Runs {
			if siteErr := results[i].addSite(name, site); siteErr != nil {
				return siteErr
			}
		}
		current = nil
		return nil
	}
	err = readGzipRows(*recordsPath, func(r io.Reader) error {
		return crawlreplay.ReadRecords(r, func(rec crawlreplay.Record) error {
			if len(current) > 0 && rec.Site != current[0].Site {
				if flushErr := flush(); flushErr != nil {
					return flushErr
				}
			}
			current = append(current, rec)
			return nil
		})
	})
	if err == nil {
		err = flush()
	}
	if err != nil {
		if errors.Is(err, crawlreplay.ErrParams) {
			return errGrid
		}
		return errBundle
	}
	rep.Shape = shapes.report()
	for i := range results {
		if fixErr := results[i].addFixtures(g.Fixtures); fixErr != nil {
			return errGrid
		}
		results[i].finish()
	}
	rep.Runs = results
	return writeReport(*outPath, rep)
}

func loadManifest(path string, files map[string]string) (bundleManifest, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-chosen private bundle
	if err != nil {
		return bundleManifest{}, errManifest
	}
	var m bundleManifest
	if err := json.Unmarshal(raw, &m); err != nil || m.FormatVersion != 1 || m.StreamVersion != crawlreplay.StreamVersion {
		return bundleManifest{}, errManifest
	}
	// Site names reach the report, so they obey the stream's pseudonym rule.
	seen := map[string]bool{}
	for _, s := range m.Sites {
		if !crawlreplay.ValidSite(s.Site) || seen[s.Site] {
			return bundleManifest{}, errManifest
		}
		seen[s.Site] = true
	}
	for kind, path := range files {
		want := ""
		for _, o := range m.Outputs {
			if o.Kind == kind {
				want = o.SHA256
			}
		}
		f, err := os.Open(path) // #nosec G304 -- operator-chosen private bundle
		if err != nil {
			return bundleManifest{}, errManifest
		}
		h := sha256.New()
		_, copyErr := io.Copy(h, f)
		f.Close()
		if copyErr != nil || want == "" || hex.EncodeToString(h.Sum(nil)) != want {
			return bundleManifest{}, errManifest
		}
	}
	return m, nil
}

func loadGrid(path string) (grid, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-chosen grid
	if err != nil {
		return grid{}, errGrid
	}
	var g grid
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&g); err != nil || len(g.Runs) == 0 {
		return grid{}, errGrid
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return grid{}, errGrid
	}
	for _, r := range g.Runs {
		if r.Params.Validate() != nil || (r.Sketch != nil && (r.Sketch.M <= r.Params.K || r.Sketch.H < r.Params.D+r.Params.K)) {
			return grid{}, errGrid
		}
	}
	for _, f := range g.Fixtures {
		if f.Validate() != nil {
			return grid{}, errGrid
		}
	}
	return g, nil
}

func readGzipRows(path string, fn func(io.Reader) error) error {
	f, err := os.Open(path) // #nosec G304 -- operator-chosen private bundle
	if err != nil {
		return err
	}
	defer f.Close()
	zr, err := gzip.NewReader(bufio.NewReader(f))
	if err != nil {
		return err
	}
	return fn(zr)
}

func newRunResult(g gridRun) runResult {
	r := runResult{Run: g, Transitions: map[string]int{}, ScopeLevels: map[uint8]int{}, MaxActive: map[uint8]int{}, Keys: map[uint8]int{}}
	if g.Sketch != nil {
		r.FootprintBytes = crawlreplay.Footprint(g.Params, *g.Sketch)
		r.Sketch = &crawlreplay.SketchAccuracy{}
	}
	return r
}

func (r *runResult) options() crawlreplay.Options {
	return crawlreplay.Options{Sketch: r.Run.Sketch, Shuffle: r.Run.Shuffle}
}

func (r *runResult) addSite(name string, site crawlreplay.Site) error {
	rep, err := crawlreplay.EvaluateSite(site, r.Run.Params, r.options())
	if err != nil {
		return err
	}
	for _, ep := range rep.Episodes {
		r.Episodes = append(r.Episodes, siteEpisode{Site: name, EpisodeResult: ep})
	}
	for class, n := range rep.Transitions {
		r.Transitions[class] += n
	}
	for day, n := range rep.FalsePositives {
		r.FalsePositives = append(r.FalsePositives, siteDay{Site: name, Day: day, Count: n})
	}
	r.Evaluations += rep.Evaluations
	r.Anomalous += rep.Anomalous
	for level, n := range rep.ScopeLevels {
		r.ScopeLevels[level] += n
	}
	for level, n := range rep.MaxActive {
		r.MaxActive[level] = max(r.MaxActive[level], n)
	}
	for level, n := range rep.Keys {
		r.Keys[level] += n
	}
	r.MaxBindings = max(r.MaxBindings, rep.MaxBindings)
	if rep.Sketch != nil {
		r.Sketch.MaxResidualError = max(r.Sketch.MaxResidualError, rep.Sketch.MaxResidualError)
		r.Sketch.MaxDistinctError = max(r.Sketch.MaxDistinctError, rep.Sketch.MaxDistinctError)
		r.Sketch.LostDecisions += rep.Sketch.LostDecisions
		r.Sketch.Exceeded += rep.Sketch.Exceeded
	}
	return nil
}

func (r *runResult) addFixtures(fixtures []crawlreplay.Fixture) error {
	for _, f := range fixtures {
		rep, err := crawlreplay.EvaluateSite(f.Site(), r.Run.Params, r.options())
		if err != nil {
			return err
		}
		fr := fixtureResult{Fixture: f.Name, Sketch: rep.Sketch}
		for _, ep := range rep.Episodes {
			if ep.Episode == f.Name {
				fr.Episode = ep
			}
		}
		r.Fixtures = append(r.Fixtures, fr)
	}
	return nil
}

func (r *runResult) finish() {
	slices.SortFunc(r.FalsePositives, func(a, b siteDay) int {
		return cmp.Or(cmp.Compare(a.Site, b.Site), cmp.Compare(a.Day, b.Day))
	})
}

type shapeAccumulator struct {
	lateness      map[int64]int64
	bindings      []float64
	keys, newKeys map[uint8][]float64
}

func (s *shapeAccumulator) add(sh crawlreplay.SiteShape) {
	for v, n := range sh.Lateness {
		s.lateness[v] += n
	}
	s.bindings = append(s.bindings, sh.WindowBindings...)
	for level, v := range sh.WindowKeys {
		s.keys[level] = append(s.keys[level], v...)
	}
	for level, v := range sh.NewKeys {
		s.newKeys[level] = append(s.newKeys[level], v...)
	}
}

func (s *shapeAccumulator) report() shapeReport {
	out := shapeReport{Lateness: crawlreplay.SummarizeCounts(s.lateness), WindowBindings: crawlreplay.Summarize(s.bindings),
		WindowKeys: map[uint8]crawlreplay.Quantiles{}, NewKeysPerHour: map[uint8]crawlreplay.Quantiles{}}
	for level, v := range s.keys {
		out.WindowKeys[level] = crawlreplay.Summarize(v)
	}
	for level, v := range s.newKeys {
		out.NewKeysPerHour[level] = crawlreplay.Summarize(v)
	}
	return out
}

func writeReport(path string, rep report) error {
	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return errOutput
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) // #nosec G304 -- operator-chosen private report
	if err != nil {
		return errOutput
	}
	_, writeErr := f.Write(append(b, '\n'))
	if err := errors.Join(writeErr, f.Close()); err != nil {
		os.Remove(path)
		return errOutput
	}
	return nil
}
