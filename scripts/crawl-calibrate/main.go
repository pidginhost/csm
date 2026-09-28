// Command crawl-calibrate replays a private experiment through replay
// sessions of the exact crawl-detector models into an aggregate report.
//
//	crawl-calibrate --experiment experiment.json --out report.json
//
// The experiment lists domlog-stream bundles in chronological order, each
// with its coverage proof, a training or scoring role and the learning
// states the operator declares for its minutes, plus the parameter sets to
// replay and the predeclared truth of every scored episode. Every bundle is
// read once and checked against its manifest; bundles must share one salt
// and identity contract, follow one another in time and agree on every
// identity digest. Without parameter sets the report holds only volume,
// silence and shape diagnostics, over each site's observed extent where a
// bundle has no proof. A replay needs a proof bound to every manifest and
// uses only certified minutes without unknown loss.
//
// Each parameter set runs one session over all bundles, so scored minutes
// are judged against history learned only from earlier minutes, with
// windows running on across adjacent bundles. The report records the
// experiment's and every bundle's provenance, per-bundle coverage and line
// counts, load and key churn, and for every run the scored High
// transitions, per-site and per-day denominators, episode outcomes against
// the truth, findings already active when scoring began and, with a sketch,
// how an independent exact session's decisions compare. Sites appear only
// as pseudonyms. A replay is a hypothesis about the detector; its numbers
// feed a private review and approve no setting.
package main

import (
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

	"github.com/pidginhost/csm/internal/crawlreplay"
)

// cliError is a fixed message: a refusal never repeats a path or input bytes.
type cliError string

func (e cliError) Error() string { return string(e) }

const (
	errUsage      cliError = "usage: crawl-calibrate --experiment FILE --out FILE"
	errExperiment cliError = "experiment is invalid"
	errManifest   cliError = "manifest is missing, not canonical or unsupported"
	errCoverage   cliError = "a replay needs a coverage proof for every bundle, and each proof must match its manifest"
	errBundle     cliError = "bundle files or rows do not match the manifest"
	errSequence   cliError = "bundles must share one salt and follow one another in time"
	errIdentity   cliError = "bundles disagree on an identity digest: their registries forked or were restored"
	errTruth      cliError = "episode truth is invalid or disagrees with the labeled records"
	errGrid       cliError = "grid is invalid"
	errOutput     cliError = "report cannot be written or already exists"
	errDirtyBuild cliError = "tool revision unknown or modified: build from a clean checkout with go build"
)

// Coverage kinds a report can rest on.
const (
	coverageCertified   = "certified"
	coverageUnqualified = "unqualified_extent"
)

type fixtureResult struct {
	Fixture string                      `json:"fixture"`
	Episode crawlreplay.EpisodeResult   `json:"episode"`
	Sketch  *crawlreplay.SketchAccuracy `json:"sketch,omitempty"`
}

type runResult struct {
	Run            gridRun             `json:"run"`
	FootprintBytes int64               `json:"footprint_bytes,omitempty"`
	Scoring        crawlreplay.Scoring `json:"scoring"`
	// Exact is the independent exact session's scoring when a sketch
	// decides, so the two end-to-end outcomes can be compared.
	Exact       *crawlreplay.Scoring        `json:"exact,omitempty"`
	Evaluations int64                       `json:"evaluations"` // scored minutes only, as below
	Anomalous   int64                       `json:"anomalous"`
	ScopeLevels map[uint8]int               `json:"scope_levels"` // selected level at minutes with anomalies
	MaxActive   map[uint8]int               `json:"max_active"`   // most keys judged in one minute, per level
	Keys        map[uint8]int               `json:"keys"`         // distinct site keys judged, per level
	MaxBindings int64                       `json:"max_bindings"` // most distinct bindings in one key's window
	Sketch      *crawlreplay.SketchAccuracy `json:"sketch,omitempty"`
	Fixtures    []fixtureResult             `json:"fixtures"`
}

type shapeReport struct {
	Lateness       crawlreplay.Quantiles           `json:"lateness_seconds"`
	WindowKeys     map[uint8]crawlreplay.Quantiles `json:"window_keys"`
	WindowBindings crawlreplay.Quantiles           `json:"window_bindings"`
	NewKeysPerHour map[uint8]crawlreplay.Quantiles `json:"new_keys_per_hour"`
}

type siteSilence struct {
	Bundle  int    `json:"bundle"`
	Site    string `json:"site"`
	Minutes int64  `json:"minutes"`
}

// bundleProvenance names what one bundle contributed.
type bundleProvenance struct {
	Role            string                      `json:"role"`
	Score           []crawlreplay.Span          `json:"score,omitempty"`
	ManifestSHA256  string                      `json:"manifest_sha256"`
	Converter       crawlreplay.ToolRevision    `json:"converter"`
	Period          crawlreplay.Span            `json:"period"`
	BotEvidence     *crawlreplay.BotEvidenceRef `json:"bot_evidence,omitempty"`
	Coverage        string                      `json:"coverage"`
	ProofSHA256     string                      `json:"proof_sha256,omitempty"`
	LatenessSeconds int64                       `json:"lateness_seconds,omitempty"`
}

// provenance names what a report rests on: the experiment, the calibrator,
// the shared salt and identity contract, and every bundle.
type provenance struct {
	ExperimentSHA256 string                   `json:"experiment_sha256"`
	Calibrator       crawlreplay.ToolRevision `json:"calibrator"`
	StreamVersion    int                      `json:"stream_version"`
	IdentityVersion  int                      `json:"identity_version"`
	SaltFingerprint  string                   `json:"salt_fingerprint"`
	Coverage         string                   `json:"coverage"`
	Bundles          []bundleProvenance       `json:"bundles"`
}

// siteCoverage is one bundle site's minutes and line accounting.
type siteCoverage struct {
	Bundle           int               `json:"bundle"`
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
	// Silences is each bundle site's longest run without a logged line
	// within the minutes the report rests on, longest first. Without a
	// proof that is the observed extent, and silence there proves nothing.
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

func run(args []string, e env) error {
	var path, out string
	fs := flag.NewFlagSet("crawl-calibrate", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&path, "experiment", "", "")
	fs.StringVar(&out, "out", "", "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || path == "" || out == "" {
		return errUsage
	}
	tool := e.revision()
	if !tool.Clean() {
		return errDirtyBuild
	}
	if _, err := os.Lstat(out); !errors.Is(err, os.ErrNotExist) {
		return errOutput
	}
	x, err := loadExperiment(path)
	if err != nil {
		return err
	}
	c, err := newCalibration(x)
	if err != nil {
		return err
	}
	for _, b := range x.Bundles {
		if err = c.bundle(b); err != nil {
			return err
		}
	}
	for _, r := range c.runs {
		if err = r.addFixtures(x.Fixtures); err != nil {
			return errGrid
		}
	}
	return writeReport(out, c.report(tool))
}

// openInput opens a private input without following a symlink or blocking
// on a FIFO, and refuses anything but a regular file.
func openInput(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) // #nosec G304 -- operator-chosen private input; symlinks refused
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

// runState is one parameter set's sessions and scorers across all bundles.
type runState struct {
	result      runResult
	session     *crawlreplay.ReplaySession
	scorer      *crawlreplay.Scorer
	exact       *crawlreplay.ReplaySession // with a sketch: the independent exact session
	exactScorer *crawlreplay.Scorer
	pairing     *crawlreplay.Pairing
	keys        map[siteKey]bool
}

type siteKey struct {
	site string
	key  crawlreplay.KeyID
}

// calibration accumulates the report while bundles stream through
// validation. Nothing it holds is written unless every bundle validates.
type calibration struct {
	x         experiment
	salt      string
	lastTo    int64
	certified bool
	identity  map[string]string // pseudonym -> digest across bundles
	sites     map[string]bool
	volumes   []crawlreplay.Volume
	shapes    shapeTrackers
	coverage  []siteCoverage
	silences  []siteSilence
	bundles   []bundleProvenance
	runs      []*runState
	// The bundle being read.
	spec     experimentBundle
	index    int
	minutes  map[string][]crawlreplay.Span // what each site's replay may use
	logged   map[string][]int64
	current  []crawlreplay.Record
	replayed map[string]bool
}

func newCalibration(x experiment) (*calibration, error) {
	c := &calibration{x: x, certified: true, identity: map[string]string{}, sites: map[string]bool{},
		shapes: shapeTrackers{}}
	for _, g := range x.Runs {
		r := &runState{result: newRunResult(g), keys: map[siteKey]bool{}}
		var err error
		if r.session, err = crawlreplay.NewReplaySession(crawlreplay.SessionConfig{Params: g.Params, Sketch: g.Sketch,
			Shuffle: g.Shuffle, IdentityVersion: x.IdentityVersion}); err != nil {
			return nil, errGrid
		}
		if r.scorer, err = crawlreplay.NewScorer(g.Params, x.Truth); err != nil {
			return nil, errTruth
		}
		if g.Sketch != nil {
			if r.exact, err = crawlreplay.NewReplaySession(crawlreplay.SessionConfig{Params: g.Params, Shuffle: g.Shuffle,
				IdentityVersion: x.IdentityVersion}); err != nil {
				return nil, errGrid
			}
			if r.exactScorer, err = crawlreplay.NewScorer(g.Params, x.Truth); err != nil {
				return nil, errTruth
			}
			r.pairing = crawlreplay.NewPairing()
		}
		c.runs = append(c.runs, r)
	}
	return c, nil
}

// bundle validates one bundle and replays its sites through every run.
func (c *calibration) bundle(b experimentBundle) error {
	raw, err := readInput(b.Manifest)
	if err != nil {
		return errManifest
	}
	m, err := crawlreplay.DecodeManifest(raw)
	if err != nil {
		return errManifest
	}
	switch {
	case c.salt != "" && m.SaltFingerprint != c.salt,
		c.salt != "" && m.Period.From <= c.lastTo:
		return errSequence
	}
	c.salt, c.lastTo = m.SaltFingerprint, m.Period.To
	if err = checkBundle(b, m); err != nil {
		return err
	}
	for _, id := range m.Identities {
		if d, ok := c.identity[id.Pseudonym]; ok && d != id.Digest {
			return errIdentity
		}
		c.identity[id.Pseudonym] = id.Digest
	}
	prov := bundleProvenance{Role: b.Role, Score: b.Score, ManifestSHA256: m.Digest(), Converter: m.Tool, Period: m.Period,
		BotEvidence: m.BotEvidence, Coverage: coverageUnqualified}
	var proof *crawlreplay.CoverageProof
	if b.Coverage != "" {
		pb, readErr := readInput(b.Coverage)
		if readErr != nil {
			return errCoverage
		}
		if proof, err = crawlreplay.DecodeCoverageProof(pb); err != nil {
			return errCoverage
		}
		prov.Coverage, prov.ProofSHA256, prov.LatenessSeconds = coverageCertified, proof.Digest(), proof.LatenessSeconds
	} else {
		c.certified = false
	}
	volumeFile, err := openInput(b.Volume)
	if err != nil {
		return errBundle
	}
	defer volumeFile.Close()
	recordsFile, err := openInput(b.Records)
	if err != nil {
		return errBundle
	}
	defer recordsFile.Close()
	c.begin(b)
	sites, err := crawlreplay.ValidateBundle(crawlreplay.BundleInput{Manifest: m, Proof: proof, Volume: volumeFile, Records: recordsFile},
		c.x.IdentityVersion, crawlreplay.BundleVisitor{Volume: c.volume, Sites: c.bundleSites, Record: c.record})
	if err == nil {
		err = c.flush()
	}
	if err == nil {
		err = c.quietSites(sites)
	}
	switch {
	case errors.Is(err, crawlreplay.ErrProof):
		return errCoverage
	case errors.Is(err, crawlreplay.ErrManifest):
		return errManifest
	case errors.Is(err, crawlreplay.ErrTruth):
		return errTruth
	case errors.Is(err, crawlreplay.ErrSession):
		return errExperiment
	case err != nil:
		return errBundle
	}
	c.bundles = append(c.bundles, prov)
	c.finishBundle(m, sites)
	return nil
}

// begin starts reading one bundle.
func (c *calibration) begin(b experimentBundle) {
	c.spec, c.index, c.minutes, c.logged, c.current, c.replayed = b, len(c.bundles), map[string][]crawlreplay.Span{},
		map[string][]int64{}, nil, map[string]bool{}
}

func (c *calibration) volume(v crawlreplay.Volume) error {
	c.volumes = append(c.volumes, v)
	c.logged[v.Site] = append(c.logged[v.Site], v.Minute)
	return nil
}

// bundleSites picks the minutes each site's replay may use: its certified
// coverage, or, without a proof, its observed extent for diagnostics only.
func (c *calibration) bundleSites(sites []crawlreplay.BundleSite) error {
	for _, s := range sites {
		c.sites[s.Site] = true
		switch {
		case c.spec.Coverage != "":
			c.minutes[s.Site] = s.Coverage
		case s.Extent != nil:
			c.minutes[s.Site] = []crawlreplay.Span{*s.Extent}
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
	err := c.replaySite(c.current[0].Site, c.current)
	c.current = nil
	return err
}

// quietSites replays the sites that logged nothing in this bundle, so keys
// learned earlier see their covered silent minutes.
func (c *calibration) quietSites(sites []crawlreplay.BundleSite) error {
	for _, s := range sites {
		if !c.replayed[s.Site] {
			if err := c.replaySite(s.Site, nil); err != nil {
				return err
			}
		}
	}
	return nil
}

// replaySite feeds one site's validated records, including those in
// excluded minutes, to every run: the scorers take onsets from all of them,
// the sessions replay the covered ones.
func (c *calibration) replaySite(name string, records []crawlreplay.Record) error {
	c.replayed[name] = true
	cov := c.minutes[name]
	// Timestamp disorder describes the source stream; excluded minutes
	// must not hide it.
	tracker := c.shapes[name]
	if tracker == nil {
		tracker = crawlreplay.NewShapeTracker(c.x.Window)
		c.shapes[name] = tracker
	}
	tracker.Add(crawlreplay.Site{Records: records, Coverage: cov})
	if len(c.runs) == 0 {
		return nil
	}
	seg := crawlreplay.ReplaySegment{Site: name, Records: crawlreplay.RestrictToCoverage(records, cov), Coverage: cov,
		Score: c.spec.Score, States: statesFor(c.spec, name)}
	for _, r := range c.runs {
		if err := r.feed(seg, records); err != nil {
			return err
		}
	}
	return nil
}

func (r *runState) feed(seg crawlreplay.ReplaySegment, all []crawlreplay.Record) error {
	if err := r.scorer.Observe(seg.Site, all, seg.Score); err != nil {
		return err
	}
	if r.exact != nil {
		if err := r.exactScorer.Observe(seg.Site, all, seg.Score); err != nil {
			return err
		}
		if err := r.exact.Feed(seg, func(t crawlreplay.Tick) error {
			if t.Scored {
				r.pairing.Exact(t)
			}
			r.exactScorer.Tick(t)
			return nil
		}); err != nil {
			return err
		}
	}
	return r.session.Feed(seg, func(t crawlreplay.Tick) error {
		r.scorer.Tick(t)
		if r.pairing != nil && t.Scored {
			r.pairing.Sketch(t)
		}
		if t.Scored {
			r.count(t)
		}
		return nil
	})
}

// count adds one scored tick to the run's load figures.
func (r *runState) count(t crawlreplay.Tick) {
	perLevel := map[uint8]int{}
	anomalous := false
	for _, e := range t.Evaluations {
		r.result.Evaluations++
		perLevel[e.Key.Level]++
		if k := (siteKey{t.Site, e.Key}); !r.keys[k] {
			r.keys[k] = true
			r.result.Keys[e.Key.Level]++
		}
		r.result.MaxBindings = max(r.result.MaxBindings, e.Bindings)
		if e.Anomalous {
			r.result.Anomalous++
			anomalous = true
		}
	}
	for level, n := range perLevel {
		r.result.MaxActive[level] = max(r.result.MaxActive[level], n)
	}
	if anomalous {
		r.result.ScopeLevels[t.Scope.Level]++
	}
}

func (c *calibration) finishBundle(m crawlreplay.Manifest, sites []crawlreplay.BundleSite) {
	for i, s := range sites {
		sm := m.Sites[i]
		sc := siteCoverage{Bundle: c.index, Site: s.Site, Extent: s.Extent, Excluded: s.Excluded, UnplacedBytes: sm.UnplacedBytes, Lines: map[string]int64{
			"records": sm.Records, "oversized": sm.Oversized, "rejected": sm.Rejected, "time_invalid": sm.TimeInvalid,
			"time_future": sm.TimeFuture, "out_of_period": sm.OutOfPeriod, "incomplete": sm.Incomplete,
			"no_target": sm.NoTarget, "attribution_loss": sm.AttributionLoss, "invalid_client": sm.InvalidClient,
			"infrastructure": sm.Infrastructure,
		}}
		sc.CertifiedMinutes, sc.CoveredMinutes = minutes(s.Certified), minutes(s.Coverage)
		c.coverage = append(c.coverage, sc)
		logged := c.logged[s.Site]
		slices.Sort(logged)
		var longest int64
		spans := c.minutes[s.Site]
		for j := 0; j < len(spans); j++ {
			span := spans[j]
			// Only an unknown minute interrupts a continuous span.
			for j+1 < len(spans) && spans[j+1].From-1 == span.To {
				j++
				span.To = spans[j].To
			}
			longest = max(longest, crawlreplay.LongestSilence(logged, span))
		}
		c.silences = append(c.silences, siteSilence{Bundle: c.index, Site: s.Site, Minutes: longest})
	}
}

func (c *calibration) report(tool crawlreplay.ToolRevision) report {
	rep := report{Window: c.x.Window, Sites: len(c.sites), Coverage: c.coverage, Silences: c.silences, Provenance: provenance{
		ExperimentSHA256: c.x.digest, Calibrator: tool, StreamVersion: crawlreplay.StreamVersion, IdentityVersion: c.x.IdentityVersion,
		SaltFingerprint: c.salt, Coverage: coverageUnqualified, Bundles: c.bundles,
	}}
	if c.certified {
		rep.Provenance.Coverage = coverageCertified
	}
	periods := make([]crawlreplay.Span, 0, len(c.bundles))
	for _, b := range c.bundles {
		periods = append(periods, b.Period)
	}
	rep.Volume = crawlreplay.SummarizeVolumePeriods(c.volumes, periods)
	slices.SortStableFunc(rep.Silences, func(a, b siteSilence) int {
		return cmp.Or(cmp.Compare(b.Minutes, a.Minutes), cmp.Compare(a.Bundle, b.Bundle), cmp.Compare(a.Site, b.Site))
	})
	rep.Shape = c.shapes.report()
	rep.Runs = []runResult{}
	for _, r := range c.runs {
		r.result.Scoring = r.scorer.Report()
		if r.exact != nil {
			exact := r.exactScorer.Report()
			acc := r.pairing.Accuracy()
			r.result.Exact, r.result.Sketch = &exact, &acc
		}
		rep.Runs = append(rep.Runs, r.result)
	}
	return rep
}

func minutes(spans []crawlreplay.Span) int64 {
	var n int64
	for _, s := range spans {
		n += s.To - s.From + 1
	}
	return n
}

func newRunResult(g gridRun) runResult {
	r := runResult{Run: g, ScopeLevels: map[uint8]int{}, MaxActive: map[uint8]int{}, Keys: map[uint8]int{}, Fixtures: []fixtureResult{}}
	if g.Sketch != nil {
		r.FootprintBytes = crawlreplay.Footprint(g.Params, *g.Sketch)
	}
	return r
}

// addFixtures replays the synthetic fixtures cold, scored by suggestion.
func (r *runState) addFixtures(fixtures []crawlreplay.Fixture) error {
	for _, f := range fixtures {
		rep, err := crawlreplay.EvaluateSite(f.Site(), r.result.Run.Params,
			crawlreplay.Options{Sketch: r.result.Run.Sketch, Shuffle: r.result.Run.Shuffle})
		if err != nil {
			return err
		}
		fr := fixtureResult{Fixture: f.Name, Sketch: rep.Sketch}
		for _, ep := range rep.Episodes {
			if ep.Episode == f.Name {
				fr.Episode = ep
			}
		}
		r.result.Fixtures = append(r.result.Fixtures, fr)
	}
	return nil
}

type shapeTrackers map[string]*crawlreplay.ShapeTracker

func (s shapeTrackers) report() shapeReport {
	all := &shapeAccumulator{lateness: map[int64]int64{}, keys: map[uint8][]float64{}, newKeys: map[uint8][]float64{}}
	for _, tracker := range s {
		all.add(tracker.Report())
	}
	return all.report()
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
