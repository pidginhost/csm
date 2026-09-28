package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/crawlreplay"
)

const (
	crossEpisode = "e-00000000000000c1"
	lateEpisode  = "e-00000000000000a2"
)

func synthKey(n uint64) string { return crawlreplay.SynthKey(n) }

// sessionSeries is one UTC hour split into a training bundle (minutes 0 to
// 39) and a scoring bundle (40 to 59). A busy key carries three requests a
// minute throughout; an attack that starts in training runs on into
// scoring; a later attack on a new key under the busy key's parent is
// strong only against the trained parent, not against the cold floor.
type sessionSeries struct {
	train, score bundle
	x            experiment
}

func newSessionSeries(t *testing.T) sessionSeries {
	t.Helper()
	start := int64(29_900_000) - int64(29_900_000)%60
	train, score := crawlreplay.Span{From: start, To: start + 39}, crawlreplay.Span{From: start + 40, To: start + 59}
	whole := crawlreplay.Span{From: train.From, To: score.To}
	syn := crawlreplay.NewSynth(attackSite, 5)
	recs := syn.Pool(crawlreplay.Traffic{From: whole.From, To: whole.To, PerMinute: 3, L2: synthKey(1), L1: synthKey(2), Label: crawlreplay.LabelHealthy}, 300)
	recs = append(recs, syn.Rotating(crawlreplay.Traffic{From: train.To - 9, To: score.From + 9, PerMinute: 200, L2: synthKey(5), L1: synthKey(6),
		Label: crawlreplay.LabelAttack, Episode: crossEpisode}, 1)...)
	recs = append(recs, syn.Rotating(crawlreplay.Traffic{From: score.From + 2, To: score.From + 12, PerMinute: 20, L2: synthKey(1), L1: synthKey(8),
		Label: crawlreplay.LabelAttack, Episode: lateEpisode}, 1)...)
	quiet := crawlreplay.NewSynth(quietSite, 6).Pool(crawlreplay.Traffic{From: whole.From, To: whole.To, PerMinute: 1, Label: crawlreplay.LabelHealthy}, 3)
	part := func(span crawlreplay.Span) []siteRecords {
		return []siteRecords{{attackSite, attackAccount, crawlreplay.RestrictToCoverage(recs, []crawlreplay.Span{span})},
			{quietSite, quietAccount, crawlreplay.RestrictToCoverage(quiet, []crawlreplay.Span{span})}}
	}
	s := sessionSeries{train: encodeBundle(t, t.TempDir(), train, part(train), bundleOptions{}),
		score: encodeBundle(t, t.TempDir(), score, part(score), bundleOptions{})}
	s.x = experiment{FormatVersion: experimentVersion, IdentityVersion: 1, Window: 10,
		// A small weight keeps each attack minute from raising the
		// parent's slot before the next window judges it.
		Runs: []gridRun{{Params: crawlreplay.Params{W: 10, R: 3, F: 1, K: 5, D: 10, C: 80,
			Baseline: crawlreplay.BaselineParams{Alpha: 1.0 / 64, MinObs: 1, MinAge: 30, FloorPerMin: 10}}}},
		Fixtures: []crawlreplay.Fixture{},
		Bundles:  []experimentBundle{s.train.entry(roleTraining), s.score.entry(roleScoring)},
		Truth: []crawlreplay.EpisodeTruth{
			{Episode: crossEpisode, Label: crawlreplay.LabelAttack, Site: attackSite,
				Keys: []crawlreplay.KeyID{{Level: 1, Key: synthKey(6), Parent: synthKey(5)}, {Level: 2, Key: synthKey(5)}}},
			{Episode: lateEpisode, Label: crawlreplay.LabelAttack, Site: attackSite,
				Keys: []crawlreplay.KeyID{{Level: 1, Key: synthKey(8), Parent: synthKey(1)}, {Level: 2, Key: synthKey(1)}}},
		},
	}
	return s
}

func episodeOf(t *testing.T, sc crawlreplay.Scoring, episode string) crawlreplay.EpisodeResult {
	t.Helper()
	for _, ep := range sc.Episodes {
		if ep.Episode == episode {
			return ep
		}
	}
	t.Fatalf("no outcome for %s", episode)
	return crawlreplay.EpisodeResult{}
}

func TestCalibrateExperimentSessions(t *testing.T) {
	s := newSessionSeries(t)
	if err := run(s.score.with(t, s.x), testEnv()); err != nil {
		t.Fatal(err)
	}
	rep := readReport(t, s.score.out)
	if p := rep.Provenance; len(p.Bundles) != 2 || p.Bundles[0].Role != roleTraining || p.Bundles[1].Role != roleScoring ||
		p.Coverage != coverageCertified || p.SaltFingerprint != "0123456789ab" || p.ExperimentSHA256 == "" {
		t.Fatalf("provenance = %+v", p)
	}
	if rep.Sites != 2 || len(rep.Coverage) != 4 || rep.Coverage[2].Bundle != 1 {
		t.Fatalf("per-bundle coverage = %+v", rep.Coverage)
	}
	warm := rep.Runs[0].Scoring
	for _, e := range warm.Events {
		if e.Minute < s.score.period.From {
			t.Fatalf("training transition %+v was scored", e)
		}
		if e.Key.Key == synthKey(6) || e.Key.Key == synthKey(5) {
			t.Fatalf("the attack active since training transitioned again: %+v", e)
		}
	}
	crossKey := crawlreplay.KeyID{Level: 1, Key: synthKey(6), Parent: synthKey(5)}
	if !slices.ContainsFunc(warm.ScoreStarts, func(st crawlreplay.ScoreStart) bool {
		return st.Site == attackSite && st.Key == crossKey && st.Since < s.score.period.From
	}) {
		t.Fatalf("findings active when scoring began: %+v", warm.ScoreStarts)
	}
	if ep := episodeOf(t, warm, crossEpisode); ep.Status != crawlreplay.OutcomeUnscored || ep.Detected {
		t.Fatalf("attack from training %+v, want not scored", ep)
	}
	late := episodeOf(t, warm, lateEpisode)
	if !late.Detected || *late.Key != (crawlreplay.KeyID{Level: 2, Key: synthKey(1)}) {
		t.Fatalf("warm replay %+v, want the trained parent to detect the later attack", late)
	}
	// Windows run on across adjacent bundles: every scored minute is judged.
	for _, d := range warm.SiteDays {
		if d.Minutes != 20 || d.Judged != 20 {
			t.Fatalf("warm site day %+v, want 20 scored minutes, all judged", d)
		}
	}

	cold := s.x
	cold.Bundles = cold.Bundles[1:]
	out := s.score.out + ".cold"
	args := s.score.with(t, cold)
	args[3] = out
	if err := run(args, testEnv()); err != nil {
		t.Fatal(err)
	}
	coldRep := readReport(t, out).Runs[0].Scoring
	if ep := episodeOf(t, coldRep, lateEpisode); ep.Detected || ep.Status != crawlreplay.OutcomeMissed {
		t.Fatalf("cold replay %+v, want the later attack missed against the floor", ep)
	}
	for _, d := range coldRep.SiteDays {
		if d.Minutes != 20 || d.Judged != 20-int64(s.x.Runs[0].Params.W-1) {
			t.Fatalf("cold site day %+v, want the first W-1 minutes unjudged", d)
		}
	}
}

// rewrite re-encodes a bundle's manifest after edit and binds its proof to
// the new bytes, as the operator would after reconverting.
func rewrite(t *testing.T, b bundle, edit func(*crawlreplay.Manifest)) {
	t.Helper()
	m, err := crawlreplay.DecodeManifest(mustRead(t, b.manifest))
	if err != nil {
		t.Fatal(err)
	}
	edit(&m)
	raw, err := crawlreplay.EncodeManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := crawlreplay.DecodeCoverageProof(mustRead(t, b.coverage))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	proof.ManifestSHA256 = hex.EncodeToString(sum[:])
	proofRaw, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	if err = errors.Join(os.WriteFile(b.manifest, raw, 0o600), os.WriteFile(b.coverage, proofRaw, 0o600)); err != nil {
		t.Fatal(err)
	}
}

func TestCalibrateExperimentRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		edit func(t *testing.T, s sessionSeries, x *experiment)
		want cliError
	}{
		"bundles out of order": {func(_ *testing.T, _ sessionSeries, x *experiment) {
			x.Bundles[0], x.Bundles[1] = x.Bundles[1], x.Bundles[0]
			x.Bundles[0].Role, x.Bundles[1].Role, x.Bundles[0].Score, x.Bundles[1].Score = roleTraining, roleScoring, nil, x.Bundles[0].Score
		}, errSequence},
		"bundle repeated": {func(_ *testing.T, _ sessionSeries, x *experiment) {
			x.Bundles[0] = x.Bundles[1]
			x.Bundles[0].Role, x.Bundles[0].Score = roleTraining, nil
		}, errSequence},
		"another salt": {func(t *testing.T, s sessionSeries, _ *experiment) {
			rewrite(t, s.score, func(m *crawlreplay.Manifest) { m.SaltFingerprint = "ba9876543210" })
		}, errSequence},
		"forked registry": {func(t *testing.T, s sessionSeries, _ *experiment) {
			rewrite(t, s.score, func(m *crawlreplay.Manifest) {
				for i := range m.Identities {
					if m.Identities[i].Pseudonym == quietSite {
						m.Identities[i].Digest = m.Identities[i].Digest[:6] + strings.Repeat("0", 58)
					}
				}
			})
		}, errIdentity},
		"unknown format":        {func(_ *testing.T, _ sessionSeries, x *experiment) { x.FormatVersion = 2 }, errExperiment},
		"other identity":        {func(_ *testing.T, _ sessionSeries, x *experiment) { x.IdentityVersion = 2 }, errExperiment},
		"no window":             {func(_ *testing.T, _ sessionSeries, x *experiment) { x.Window = 0 }, errExperiment},
		"no bundles":            {func(_ *testing.T, _ sessionSeries, x *experiment) { x.Bundles = []experimentBundle{} }, errExperiment},
		"no truth table":        {func(_ *testing.T, _ sessionSeries, x *experiment) { x.Truth = nil }, errExperiment},
		"unknown role":          {func(_ *testing.T, _ sessionSeries, x *experiment) { x.Bundles[0].Role = "warmup" }, errExperiment},
		"training scored":       {func(_ *testing.T, _ sessionSeries, x *experiment) { x.Bundles[0].Score = x.Bundles[1].Score }, errExperiment},
		"scoring without spans": {func(_ *testing.T, _ sessionSeries, x *experiment) { x.Bundles[1].Score = nil }, errExperiment},
		"score outside period":  {func(_ *testing.T, s sessionSeries, x *experiment) { x.Bundles[1].Score[0].To = s.score.period.To + 1 }, errExperiment},
		"state outside period":  {func(_ *testing.T, s sessionSeries, x *experiment) { x.Bundles[0].States[0].To = s.score.period.To }, errExperiment},
		"state for another site": {func(_ *testing.T, _ sessionSeries, x *experiment) {
			x.Bundles[0].States[0].Site = "dom-00000f.example"
		}, errExperiment},
		"key state without site": {func(_ *testing.T, _ sessionSeries, x *experiment) {
			x.Bundles[0].States[0].Key = &crawlreplay.KeyID{Level: 3}
		}, errExperiment},
		"unknown state": {func(_ *testing.T, _ sessionSeries, x *experiment) { x.Bundles[0].States[0].State = "quiet" }, errExperiment},
		"overlapping states": {func(_ *testing.T, _ sessionSeries, x *experiment) {
			x.Bundles[0].States = append(x.Bundles[0].States, experimentState{From: x.Bundles[0].States[0].To, To: x.Bundles[0].States[0].To,
				State: crawlreplay.StateProtected})
		}, errExperiment},
		"diagnostic unknown state": {func(_ *testing.T, _ sessionSeries, x *experiment) {
			x.Runs = []gridRun{}
			x.Bundles[0].States[0].State = "quiet"
		}, errExperiment},
		"diagnostic invalid key": {func(_ *testing.T, _ sessionSeries, x *experiment) {
			x.Runs = []gridRun{}
			x.Bundles[0].States[0].Site = attackSite
			x.Bundles[0].States[0].Key = &crawlreplay.KeyID{Level: 4}
		}, errExperiment},
		"diagnostic overlapping states": {func(_ *testing.T, _ sessionSeries, x *experiment) {
			x.Runs = []gridRun{}
			x.Bundles[0].States = append(x.Bundles[0].States, x.Bundles[0].States[0])
		}, errExperiment},
		"diagnostic invalid truth": {func(_ *testing.T, _ sessionSeries, x *experiment) {
			x.Runs = []gridRun{}
			x.Truth[0].Label = crawlreplay.LabelHealthy
		}, errTruth},
		"missing coverage":             {func(_ *testing.T, _ sessionSeries, x *experiment) { x.Bundles[0].Coverage = "" }, errCoverage},
		"bad fixture":                  {func(_ *testing.T, _ sessionSeries, x *experiment) { x.Fixtures = []crawlreplay.Fixture{{Name: "Bad"}} }, errGrid},
		"healthy truth":                {func(_ *testing.T, _ sessionSeries, x *experiment) { x.Truth[0].Label = crawlreplay.LabelHealthy }, errTruth},
		"scored episode without truth": {func(_ *testing.T, _ sessionSeries, x *experiment) { x.Truth = x.Truth[:1] }, errTruth},
	} {
		t.Run(name, func(t *testing.T) {
			s := newSessionSeries(t)
			x := s.x
			x.Bundles = slices.Clone(s.x.Bundles)
			for i := range x.Bundles {
				x.Bundles[i].States = slices.Clone(x.Bundles[i].States)
				x.Bundles[i].Score = slices.Clone(x.Bundles[i].Score)
			}
			x.Truth = slices.Clone(s.x.Truth)
			tc.edit(t, s, &x)
			if err := run(s.score.with(t, x), testEnv()); !errors.Is(err, tc.want) {
				t.Fatalf("%v, want %v", err, tc.want)
			}
			if _, err := os.Stat(s.score.out); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("a refused experiment wrote a report")
			}
		})
	}

	t.Run("closed form", func(t *testing.T) {
		s := newSessionSeries(t)
		raw, err := json.Marshal(s.x)
		if err != nil {
			t.Fatal(err)
		}
		for kind, edited := range map[string]string{
			"unknown member":   strings.Replace(string(raw), `"window"`, `"windows"`, 1),
			"duplicate member": strings.Replace(string(raw), `"window":10`, `"window":10,"window":10`, 1),
			"member case":      strings.Replace(string(raw), `"window"`, `"Window"`, 1),
			"null member":      strings.Replace(string(raw), `"fixtures":[]`, `"fixtures":null`, 1),
		} {
			if edited == string(raw) {
				t.Fatalf("%s: edit did not apply", kind)
			}
			if err := run(s.score.withRaw(t, []byte(edited)), testEnv()); !errors.Is(err, errExperiment) {
				t.Fatalf("%s: %v, want errExperiment", kind, err)
			}
		}
	})
}
