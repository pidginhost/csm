// Command crawl-calibrate validates a domlog-stream bundle and replays it
// through the exact crawl-detector models into an aggregate report.
//
//	crawl-calibrate --manifest manifest.json --records records.jsonl.gz \
//	    --volume volume.jsonl.gz [--coverage coverage.json] --window 10 \
//	    [--grid grid.json] --out report.json
//
// Every run reads each bundle file once and checks every row against the
// manifest, whose bytes must be exactly what domlog-stream wrote. Without a
// coverage proof the report holds only volume, silence and shape
// diagnostics over each site's observed extent and says its coverage is
// unqualified; a grid replay needs a proof bound to the manifest, and then
// uses only certified minutes without unknown loss. The report records the
// bundle's provenance, per-site coverage and line counts, load and key
// churn, lateness and, for every grid run, the per-episode detection delay
// and margins, healthy false positives per site-day, key and binding
// peaks, sketch accuracy and synthetic fixture outcomes. Sites appear only
// as pseudonyms. A replay is a hypothesis about the detector; its numbers
// feed a private review and approve no setting.
package main

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"slices"
	"syscall"

	"github.com/pidginhost/csm/internal/crawlid"
	"github.com/pidginhost/csm/internal/crawlreplay"
)

// cliError is a fixed message: a refusal never repeats a path or input bytes.
type cliError string

func (e cliError) Error() string { return string(e) }

const (
	errUsage      cliError = "usage: crawl-calibrate --manifest FILE --records FILE --volume FILE [--coverage FILE] --window MINUTES [--grid FILE] --out FILE"
	errManifest   cliError = "manifest is missing, not canonical or unsupported"
	errCoverage   cliError = "a grid replay needs a coverage proof, and the proof must match the manifest"
	errBundle     cliError = "bundle files or rows do not match the manifest"
	errGrid       cliError = "grid is invalid"
	errOutput     cliError = "report cannot be written or already exists"
	errDirtyBuild cliError = "tool revision unknown or modified: build from a clean checkout with go build"
)

// Coverage kinds a report can rest on.
const (
	coverageCertified   = "certified"
	coverageUnqualified = "unqualified_extent"
)

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

// provenance names what a report rests on: the bundle, both tools, the
// salt's fingerprint and whether minutes were certified.
type provenance struct {
	ManifestSHA256  string                      `json:"manifest_sha256"`
	StreamVersion   int                         `json:"stream_version"`
	IdentityVersion int                         `json:"identity_version"`
	Converter       crawlreplay.ToolRevision    `json:"converter"`
	Calibrator      crawlreplay.ToolRevision    `json:"calibrator"`
	SaltFingerprint string                      `json:"salt_fingerprint"`
	Period          crawlreplay.Span            `json:"period"`
	BotEvidence     *crawlreplay.BotEvidenceRef `json:"bot_evidence,omitempty"`
	Coverage        string                      `json:"coverage"`
	ProofSHA256     string                      `json:"proof_sha256,omitempty"`
	LatenessSeconds int64                       `json:"lateness_seconds,omitempty"`
}

// siteCoverage is one site's minutes and line accounting.
type siteCoverage struct {
	Site             string            `json:"site"`
	Extent           *crawlreplay.Span `json:"extent,omitempty"`
	CertifiedMinutes int64             `json:"certified_minutes"`
	CoveredMinutes   int64             `json:"covered_minutes"`
	Excluded         map[string]int64  `json:"excluded,omitempty"`
	Lines            map[string]int64  `json:"lines"`
	UnplacedBytes    int64             `json:"unplaced_bytes"`
}

type report struct {
	Provenance provenance             `json:"provenance"`
	Window     int                    `json:"window"`
	Sites      int                    `json:"sites"`
	Coverage   []siteCoverage         `json:"coverage"`
	Volume     crawlreplay.HostVolume `json:"volume"`
	// Silences is each site's longest run without a logged line within the
	// minutes the report rests on, longest first. Without a proof that is
	// the observed extent, and silence there proves nothing.
	Silences []siteSilence `json:"silences"`
	Shape    shapeReport   `json:"shape"`
	Runs     []runResult   `json:"runs"`
}

// env is what tests replace: the build stamp the report records.
type env struct {
	revision func() crawlreplay.ToolRevision
}

func defaultEnv() env { return env{revision: readBuildRevision} }

func readBuildRevision() crawlreplay.ToolRevision {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return crawlreplay.ToolRevision{Dirty: true}
	}
	t := crawlreplay.ToolRevision{GoVersion: info.GoVersion, Dirty: true}
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			t.Revision = s.Value
		case "vcs.modified":
			t.Dirty = s.Value != "false"
		}
	}
	return t
}

// cli runs the command and reports a refusal, always a fixed message, on
// stderr. It returns the process exit status.
func cli(args []string, stderr io.Writer, e env) int {
	if err := run(args, e); err != nil {
		fmt.Fprintln(stderr, "crawl-calibrate:", err)
		return 1
	}
	return 0
}

func main() { os.Exit(cli(os.Args[1:], os.Stderr, defaultEnv())) }

type options struct {
	manifest, records, volume, coverage, grid, out string
	window                                         int
}

func run(args []string, e env) error {
	var o options
	fs := flag.NewFlagSet("crawl-calibrate", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&o.manifest, "manifest", "", "")
	fs.StringVar(&o.records, "records", "", "")
	fs.StringVar(&o.volume, "volume", "", "")
	fs.StringVar(&o.coverage, "coverage", "", "")
	fs.StringVar(&o.grid, "grid", "", "")
	fs.StringVar(&o.out, "out", "", "")
	fs.IntVar(&o.window, "window", 0, "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || o.manifest == "" || o.records == "" ||
		o.volume == "" || o.out == "" || o.window < 1 {
		return errUsage
	}
	if o.grid != "" && o.coverage == "" {
		return errCoverage
	}
	tool := e.revision()
	if !tool.Clean() {
		return errDirtyBuild
	}
	if _, err := os.Lstat(o.out); !errors.Is(err, os.ErrNotExist) {
		return errOutput
	}
	raw, err := readInput(o.manifest)
	if err != nil {
		return errManifest
	}
	m, err := crawlreplay.DecodeManifest(raw)
	if err != nil {
		return errManifest
	}
	rep := report{Window: o.window, Sites: len(m.Sites), Provenance: provenance{
		ManifestSHA256: m.Digest(), StreamVersion: m.StreamVersion, IdentityVersion: m.IdentityVersion,
		Converter: m.Tool, Calibrator: tool, SaltFingerprint: m.SaltFingerprint, Period: m.Period,
		BotEvidence: m.BotEvidence, Coverage: coverageUnqualified,
	}}
	var proof *crawlreplay.CoverageProof
	if o.coverage != "" {
		b, readErr := readInput(o.coverage)
		if readErr != nil {
			return errCoverage
		}
		if proof, err = crawlreplay.DecodeCoverageProof(b); err != nil {
			return errCoverage
		}
		rep.Provenance.Coverage, rep.Provenance.ProofSHA256, rep.Provenance.LatenessSeconds = coverageCertified, proof.Digest(), proof.LatenessSeconds
	}
	var g grid
	if o.grid != "" {
		if g, err = loadGrid(o.grid); err != nil {
			return err
		}
	}
	volumeFile, err := openInput(o.volume)
	if err != nil {
		return errBundle
	}
	defer volumeFile.Close()
	recordsFile, err := openInput(o.records)
	if err != nil {
		return errBundle
	}
	defer recordsFile.Close()

	c := newCalibration(o.window, g, proof != nil)
	sites, err := crawlreplay.ValidateBundle(crawlreplay.BundleInput{Manifest: m, Proof: proof, Volume: volumeFile, Records: recordsFile},
		crawlid.Version, crawlreplay.BundleVisitor{Volume: c.volume, Sites: c.sites, Record: c.record})
	if err == nil {
		err = c.flush()
	}
	switch {
	case errors.Is(err, crawlreplay.ErrProof):
		return errCoverage
	case errors.Is(err, crawlreplay.ErrManifest):
		return errManifest
	case errors.Is(err, crawlreplay.ErrParams):
		return errGrid
	case err != nil:
		return errBundle
	}
	if err = c.quietSites(); err != nil {
		return errGrid
	}
	for i := range c.runs {
		if err = c.runs[i].addFixtures(g.Fixtures); err != nil {
			return errGrid
		}
	}
	c.finish(&rep, m, sites)
	return writeReport(o.out, rep)
}

// openInput opens a private input without following a symlink or blocking
// on a FIFO, and refuses anything but a regular file.
func openInput(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) // #nosec G304 -- operator-chosen private bundle; symlinks refused
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		f.Close()
		return nil, errBundle
	}
	return f, nil
}

func readInput(path string) ([]byte, error) {
	f, err := openInput(path)
	if err != nil {
		return nil, err
	}
	b, readErr := io.ReadAll(f)
	if closeErr := f.Close(); readErr != nil || closeErr != nil {
		return nil, errBundle
	}
	return b, nil
}

// calibration accumulates the report while ValidateBundle streams the
// bundle. Nothing it holds is written unless validation succeeds.
type calibration struct {
	window    int
	grid      grid
	certified bool
	volumes   []crawlreplay.Volume
	coverage  map[string][]crawlreplay.Span
	seen      map[string]bool
	current   []crawlreplay.Record
	shapes    *shapeAccumulator
	runs      []runResult
}

func newCalibration(window int, g grid, certified bool) *calibration {
	c := &calibration{window: window, grid: g, certified: certified, coverage: map[string][]crawlreplay.Span{}, seen: map[string]bool{},
		shapes: &shapeAccumulator{lateness: map[int64]int64{}, keys: map[uint8][]float64{}, newKeys: map[uint8][]float64{}}}
	for _, gr := range g.Runs {
		c.runs = append(c.runs, newRunResult(gr))
	}
	return c
}

func (c *calibration) volume(v crawlreplay.Volume) error {
	c.volumes = append(c.volumes, v)
	return nil
}

// sites picks the minutes each site's replay may use: its certified
// coverage, or, without a proof, its observed extent for diagnostics only.
func (c *calibration) sites(sites []crawlreplay.BundleSite) error {
	for _, s := range sites {
		switch {
		case c.certified:
			c.coverage[s.Site] = s.Coverage
		case s.Extent != nil:
			c.coverage[s.Site] = []crawlreplay.Span{*s.Extent}
		}
	}
	return nil
}

func (c *calibration) record(r crawlreplay.Record) error {
	if len(c.current) > 0 && r.Site != c.current[0].Site {
		if err := c.flush(); err != nil {
			return err
		}
	}
	c.current = append(c.current, r)
	return nil
}

func (c *calibration) flush() error {
	if len(c.current) == 0 {
		return nil
	}
	name := c.current[0].Site
	err := c.replay(name, c.current)
	c.current = nil
	return err
}

func (c *calibration) replay(name string, records []crawlreplay.Record) error {
	c.seen[name] = true
	cov := c.coverage[name]
	site := crawlreplay.Site{Records: crawlreplay.RestrictToCoverage(records, cov), Coverage: cov}
	// Timestamp disorder and episode origins describe the source stream;
	// excluding minutes must not erase evidence or shorten detection delay.
	c.shapes.add(crawlreplay.ShapeSite(crawlreplay.Site{Records: records, Coverage: cov}, c.window))
	origins := episodeOrigins(records)
	for i := range c.runs {
		if err := c.runs[i].addSite(name, site, origins); err != nil {
			return err
		}
	}
	return nil
}

// quietSites adds the shape of certified sites that logged nothing.
func (c *calibration) quietSites() error {
	names := make([]string, 0, len(c.coverage))
	for name := range c.coverage {
		if !c.seen[name] {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	for _, name := range names {
		if err := c.replay(name, nil); err != nil {
			return err
		}
	}
	return nil
}

func (c *calibration) finish(rep *report, m crawlreplay.Manifest, sites []crawlreplay.BundleSite) {
	rep.Volume = crawlreplay.SummarizeVolume(c.volumes)
	logged := map[string][]int64{}
	for _, v := range c.volumes {
		logged[v.Site] = append(logged[v.Site], v.Minute)
	}
	for i, s := range sites {
		sm := m.Sites[i]
		sc := siteCoverage{Site: s.Site, Extent: s.Extent, Excluded: s.Excluded, UnplacedBytes: sm.UnplacedBytes, Lines: map[string]int64{
			"records": sm.Records, "oversized": sm.Oversized, "rejected": sm.Rejected, "time_invalid": sm.TimeInvalid,
			"time_future": sm.TimeFuture, "out_of_period": sm.OutOfPeriod, "incomplete": sm.Incomplete,
			"no_target": sm.NoTarget, "attribution_loss": sm.AttributionLoss, "invalid_client": sm.InvalidClient,
			"infrastructure": sm.Infrastructure,
		}}
		sc.CertifiedMinutes, sc.CoveredMinutes = minutes(s.Certified), minutes(s.Coverage)
		rep.Coverage = append(rep.Coverage, sc)
		minutesLogged := logged[s.Site]
		slices.Sort(minutesLogged)
		var longest int64
		spans := c.coverage[s.Site]
		for j := 0; j < len(spans); j++ {
			span := spans[j]
			// Only an unknown minute interrupts a continuous span.
			for j+1 < len(spans) && spans[j+1].From-1 == span.To {
				j++
				span.To = spans[j].To
			}
			longest = max(longest, crawlreplay.LongestSilence(minutesLogged, span))
		}
		rep.Silences = append(rep.Silences, siteSilence{Site: s.Site, Minutes: longest})
	}
	slices.SortFunc(rep.Silences, func(a, b siteSilence) int {
		return cmp.Or(cmp.Compare(b.Minutes, a.Minutes), cmp.Compare(a.Site, b.Site))
	})
	rep.Shape = c.shapes.report()
	for i := range c.runs {
		c.runs[i].finish()
	}
	rep.Runs = c.runs
	if rep.Runs == nil {
		rep.Runs = []runResult{}
	}
}

func minutes(spans []crawlreplay.Span) int64 {
	var n int64
	for _, s := range spans {
		n += s.To - s.From + 1
	}
	return n
}

func loadGrid(path string) (grid, error) {
	raw, err := readInput(path)
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

func episodeOrigins(records []crawlreplay.Record) []crawlreplay.EpisodeResult {
	byName := map[string]crawlreplay.EpisodeResult{}
	for _, rec := range records {
		if rec.Episode == "" {
			continue
		}
		if ep, ok := byName[rec.Episode]; !ok || rec.T < ep.Onset {
			byName[rec.Episode] = crawlreplay.EpisodeResult{Episode: rec.Episode, Label: rec.Label, Onset: rec.T}
		}
	}
	origins := make([]crawlreplay.EpisodeResult, 0, len(byName))
	for _, ep := range byName {
		origins = append(origins, ep)
	}
	slices.SortFunc(origins, func(a, b crawlreplay.EpisodeResult) int { return cmp.Compare(a.Episode, b.Episode) })
	return origins
}

func (r *runResult) addSite(name string, site crawlreplay.Site, origins []crawlreplay.EpisodeResult) error {
	rep, err := crawlreplay.EvaluateSite(site, r.Run.Params, r.options())
	if err != nil {
		return err
	}
	outcomes := map[string]crawlreplay.EpisodeResult{}
	for _, ep := range rep.Episodes {
		outcomes[ep.Episode] = ep
	}
	for _, origin := range origins {
		ep, ok := outcomes[origin.Episode]
		if !ok {
			ep = origin
		}
		ep.Onset = origin.Onset
		if ep.Detected {
			ep.DelaySeconds = (ep.DetectMinute+1)*60 - ep.Onset
		}
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
