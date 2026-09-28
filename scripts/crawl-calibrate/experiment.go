package main

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"

	"github.com/pidginhost/csm/internal/crawlid"
	"github.com/pidginhost/csm/internal/crawlreplay"
)

// experimentVersion is the experiment file format.
const experimentVersion = 1

// Roles a bundle plays: training bundles only teach the sessions, scoring
// bundles are also judged over their scoring spans.
const (
	roleTraining = "training"
	roleScoring  = "scoring"
)

// experiment is the private, operator-written description of one replay:
// the parameter sets, the chronological bundles with their roles and
// learning states, and the predeclared episode truth. Its digest in the
// report fixes all of it.
type experiment struct {
	FormatVersion   int                        `json:"format_version"`
	IdentityVersion int                        `json:"identity_version"`
	Window          int                        `json:"window"` // diagnostic shape window, minutes
	Runs            []gridRun                  `json:"runs"`
	Fixtures        []crawlreplay.Fixture      `json:"fixtures"`
	Bundles         []experimentBundle         `json:"bundles"`
	Truth           []crawlreplay.EpisodeTruth `json:"truth"`

	digest string
}

type gridRun struct {
	Params  crawlreplay.Params        `json:"params"`
	Sketch  *crawlreplay.SketchParams `json:"sketch,omitempty"`
	Shuffle uint64                    `json:"shuffle,omitempty"`
}

// experimentBundle names one bundle's files, relative to the experiment
// file's directory unless absolute.
type experimentBundle struct {
	Manifest string             `json:"manifest"`
	Records  string             `json:"records"`
	Volume   string             `json:"volume"`
	Coverage string             `json:"coverage,omitempty"`
	Role     string             `json:"role"`
	Score    []crawlreplay.Span `json:"score,omitempty"`
	States   []experimentState  `json:"states"`
}

// experimentState declares a learning state over inclusive minutes for one
// site, one key of it, or, with no site, every site of the bundle.
type experimentState struct {
	Site  string             `json:"site,omitempty"`
	Key   *crawlreplay.KeyID `json:"key,omitempty"`
	From  int64              `json:"from"`
	To    int64              `json:"to"`
	State string             `json:"state"`
}

// loadExperiment reads the experiment file once, in its closed form, and
// checks everything that needs no bundle: versions, parameter sets, roles,
// scoring spans and the shape of state declarations.
func loadExperiment(path string) (experiment, error) {
	raw, err := readInput(path)
	if err != nil {
		return experiment{}, errExperiment
	}
	var x experiment
	if err = crawlreplay.DecodeStrictJSON(raw, &x); err != nil {
		return experiment{}, errExperiment
	}
	sum := sha256.Sum256(raw)
	x.digest = hex.EncodeToString(sum[:])
	switch {
	case x.FormatVersion != experimentVersion, x.IdentityVersion != crawlid.Version, x.Window < 1,
		len(x.Bundles) == 0, x.Runs == nil, x.Fixtures == nil, x.Truth == nil:
		return experiment{}, errExperiment
	}
	if crawlreplay.ValidateTruth(x.Truth) != nil {
		return experiment{}, errTruth
	}
	for _, r := range x.Runs {
		if r.Params.Validate() != nil || (r.Sketch != nil && (r.Sketch.M <= r.Params.K || r.Sketch.H < r.Params.D+r.Params.K)) {
			return experiment{}, errGrid
		}
	}
	for _, f := range x.Fixtures {
		if f.Validate() != nil {
			return experiment{}, errGrid
		}
	}
	dir := filepath.Dir(path)
	for i := range x.Bundles {
		b := &x.Bundles[i]
		if b.Manifest == "" || b.Records == "" || b.Volume == "" || b.States == nil {
			return experiment{}, errExperiment
		}
		for _, p := range []*string{&b.Manifest, &b.Records, &b.Volume, &b.Coverage} {
			if *p != "" && !filepath.IsAbs(*p) {
				*p = filepath.Join(dir, *p)
			}
		}
		switch {
		case b.Role == roleTraining && b.Score != nil,
			b.Role == roleScoring && len(b.Score) == 0,
			b.Role != roleTraining && b.Role != roleScoring:
			return experiment{}, errExperiment
		}
		for j, s := range b.Score {
			if s.From <= 0 || s.To < s.From || (j > 0 && s.From <= b.Score[j-1].To) {
				return experiment{}, errExperiment
			}
		}
		for _, st := range b.States {
			if st.From <= 0 || st.To < st.From || (st.Site != "" && !crawlreplay.ValidSite(st.Site)) || (st.Key != nil && st.Site == "") {
				return experiment{}, errExperiment
			}
		}
		if len(x.Runs) > 0 && b.Coverage == "" {
			return experiment{}, errCoverage
		}
	}
	return x, nil
}

// checkBundle holds a bundle's roles and declarations to its manifest:
// scoring spans and states lie in its period and name its sites.
func checkBundle(b experimentBundle, m crawlreplay.Manifest) error {
	within := func(from, to int64) bool { return from >= m.Period.From && to <= m.Period.To }
	sites := map[string]bool{}
	for _, s := range m.Sites {
		sites[s.Site] = true
		if crawlreplay.ValidateStates(statesFor(b, s.Site)) != nil {
			return errExperiment
		}
	}
	for _, s := range b.Score {
		if !within(s.From, s.To) {
			return errExperiment
		}
	}
	for _, st := range b.States {
		if !within(st.From, st.To) || (st.Site != "" && !sites[st.Site]) {
			return errExperiment
		}
	}
	return nil
}

// statesFor lists the declarations that apply to one site's segment.
func statesFor(b experimentBundle, site string) []crawlreplay.StateSpan {
	var out []crawlreplay.StateSpan
	for _, st := range b.States {
		if st.Site == "" || st.Site == site {
			out = append(out, crawlreplay.StateSpan{Key: st.Key, From: st.From, To: st.To, State: st.State})
		}
	}
	return out
}
