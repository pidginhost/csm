package attackcorpus

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Counts summarizes one category on one path. Samples counts every result.
// Every other kind counts results, not failures: a result counts once toward
// each kind its failures name, however many failures of that kind it has.
//
//   - Detected: a malicious result with no failures on a path without a gap,
//     so its expected findings arrived at their severity.
//   - Gaps: a result on a path with a gap and no "gap closed:" failure.
//   - Missed: a "missed:" or "severity:" failure; an expected finding absent
//     and one below its minimum both leave the path short of its contract.
//   - FalsePositives, ClosedGaps, RemediationMismatches, Errors: a "false
//     positive:", "gap closed:", "remediation:" or "error:" failure.
type Counts struct {
	Samples               int `json:"samples"`
	Detected              int `json:"detected"`
	Gaps                  int `json:"gaps"`
	Missed                int `json:"missed"`
	FalsePositives        int `json:"false_positives"`
	ClosedGaps            int `json:"closed_gaps"`
	RemediationMismatches int `json:"remediation_mismatches"`
	Errors                int `json:"errors"`
}

// Summarize counts results per category.
func Summarize(results []Result) map[Category]Counts {
	out := map[Category]Counts{}
	for _, r := range results {
		has := func(kinds ...string) int {
			for _, f := range r.Failures {
				if slices.ContainsFunc(kinds, func(k string) bool { return strings.HasPrefix(f, k+":") }) {
					return 1
				}
			}
			return 0
		}
		c := out[Category(r.Category)]
		c.Samples++
		if r.Kind == "malicious" && len(r.Failures) == 0 && r.Gap == "" {
			c.Detected++
		}
		if r.Gap != "" {
			c.Gaps += 1 - has("gap closed")
		}
		c.Missed += has("missed", "severity")
		c.FalsePositives += has("false positive")
		c.ClosedGaps += has("gap closed")
		c.RemediationMismatches += has("remediation")
		c.Errors += has("error")
		out[Category(r.Category)] = c
	}
	return out
}

// WriteReport writes <dir>/<path>.json with the results and their summary.
// Nothing in a Result carries sample content; finding text stays out through
// its JSON tag.
func WriteReport(dir string, p Path, results []Result) error {
	if len(results) == 0 {
		return errors.New("cannot report an empty corpus run")
	}
	data, err := json.MarshalIndent(struct {
		Path    Path                `json:"path"`
		Results []Result            `json:"results"`
		Summary map[Category]Counts `json:"summary"`
	}{p, results, Summarize(results)}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, string(p)+".json"), append(data, '\n'), 0o600)
}
