// Package selftest runs CSM's detection over a small bundle of samples whose
// verdicts are known, so an operator can see what the shipped rules catch
// without pointing the scanner at a production account.
//
// The bundle carries adversarial samples and benign controls. The controls are
// the half that matters when judging a scanner: a rule set that flags an
// ordinary WordPress plugin is worse than one that misses a shell.
//
// Every sample is stored base64-encoded and only decoded in memory. Endpoint
// antivirus on a developer machine, or on the server an operator runs this on,
// deletes files that look like web shells; a decoded copy on disk would make
// the bundle disappear.
package selftest

import (
	"encoding/base64"
	"fmt"
)

// Sample is one file with a known verdict.
type Sample struct {
	Name string
	// Ext is the extension the scanner is told about, including the dot.
	Ext string
	// Malicious is what the sample is, not what the rules do with it.
	Malicious   bool
	Description string
	// RealtimeGap and YaraGap record that the shipped rule set does not fire
	// on this sample today. They are measurements, not permissions: the gates
	// fail when a gap closes as well as when one opens, so closing one is a
	// deliberate edit here rather than a silent change in behaviour.
	//
	// A gap is a gap in the signature engines only. Taint analysis, the
	// behavioural checks and PHP Shield are separate layers and are not
	// measured by this bundle.
	RealtimeGap bool
	YaraGap     bool
	// Encoded is the sample content, base64-encoded at rest.
	Encoded string
}

// Content decodes the sample.
func (s Sample) Content() ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(s.Encoded)
	if err != nil {
		return nil, fmt.Errorf("sample %s: %w", s.Name, err)
	}
	return data, nil
}

// Result is one sample's outcome.
type Result struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Malicious   bool     `json:"malicious"`
	Detected    bool     `json:"detected"`
	KnownGap    bool     `json:"known_gap"`
	Rules       []string `json:"rules,omitempty"`
	Pass        bool     `json:"pass"`
	Error       string   `json:"error,omitempty"`
}

// ScanFunc is the detection under test: it returns the names of the rules that
// fired on the content.
type ScanFunc func(content []byte, ext string) []string

// Engine names the rule set being measured, so a sample's recorded gap is
// compared against the engine that has it.
type Engine string

const (
	// Realtime is the YAML rule set the real-time watchers use.
	Realtime Engine = "realtime"
	// Yara is the YARA-X rule set used by scheduled and email scanning. It is
	// present only in builds compiled with the yara tag.
	Yara Engine = "yara"
)

func (s Sample) gap(engine Engine) bool {
	if engine == Yara {
		return s.YaraGap
	}
	return s.RealtimeGap
}

// Run scans every sample with one engine and reports whether the outcome
// matched what is recorded for it. A sample that cannot be decoded is a
// failure, not a skip: a bundle that silently shrinks proves nothing.
func Run(engine Engine, scan ScanFunc) []Result {
	results := make([]Result, 0, len(samples))
	for _, sample := range samples {
		result := Result{
			Name:        sample.Name,
			Description: sample.Description,
			Malicious:   sample.Malicious,
			KnownGap:    sample.Malicious && sample.gap(engine),
		}
		content, err := sample.Content()
		if err != nil {
			result.Error = err.Error()
			results = append(results, result)
			continue
		}
		result.Rules = scan(content, sample.Ext)
		result.Detected = len(result.Rules) > 0
		result.Pass = result.Detected == (sample.Malicious && !result.KnownGap)
		results = append(results, result)
	}
	return results
}

// Summary counts outcomes. The three failure kinds mean different things and
// are never added together: a newly missed sample is a regression, a flagged
// control is a false positive, and a recorded gap that now fires is good news
// that needs the bundle updated.
type Summary struct {
	Detected       int `json:"detected"`
	KnownGaps      int `json:"known_gaps"`
	Clean          int `json:"clean"`
	Missed         int `json:"missed"`
	FalsePositives int `json:"false_positives"`
	ClosedGaps     int `json:"closed_gaps"`
}

// Failed reports whether the run found anything that needs attention.
func (s Summary) Failed() bool {
	return s.Missed > 0 || s.FalsePositives > 0 || s.ClosedGaps > 0
}

// Summarize counts the results.
func Summarize(results []Result) Summary {
	var out Summary
	for _, r := range results {
		switch {
		case r.KnownGap && r.Detected:
			out.ClosedGaps++
		case r.KnownGap:
			out.KnownGaps++
		case r.Malicious && r.Detected:
			out.Detected++
		case r.Malicious:
			out.Missed++
		case r.Detected:
			out.FalsePositives++
		default:
			out.Clean++
		}
	}
	return out
}

// Samples returns the bundle.
func Samples() []Sample { return append([]Sample(nil), samples...) }
