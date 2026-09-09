package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/pidginhost/csm/internal/selftest"
	"github.com/pidginhost/csm/internal/signatures"
	"github.com/pidginhost/csm/internal/yara"
)

// packagedRulesDir is where the package installs the shipped rule files.
const packagedRulesDir = "/opt/csm/rules"

// engineRun is one rule set's results.
type engineRun struct {
	Engine    selftest.Engine   `json:"engine"`
	RuleCount int               `json:"rule_count"`
	Skipped   string            `json:"skipped,omitempty"`
	Summary   selftest.Summary  `json:"summary"`
	Results   []selftest.Result `json:"results"`
}

// runSelfTest scans a bundle of samples with known verdicts and reports what
// the installed rules catch. It reads no account data and writes nothing, so
// it is safe on a production host, and it answers the question an evaluator
// actually has: what does this detect, and what does it miss.
func runSelfTest() {
	asJSON := false
	for _, arg := range os.Args[2:] {
		if arg == "--json" {
			asJSON = true
		}
	}

	// Fall back to the packaged rules directory so the command still answers
	// on a host whose config is missing or broken, which is exactly when an
	// operator wants to know whether detection works.
	rulesDir := packagedRulesDir
	if cfg, err := tryLoadConfigLite(); err == nil && cfg != nil && cfg.Signatures.RulesDir != "" {
		rulesDir = cfg.Signatures.RulesDir
	}

	runs, err := selfTestRuns(rulesDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	if err := writeSelfTest(os.Stdout, rulesDir, runs, asJSON); err != nil {
		fmt.Fprintf(os.Stderr, "Cannot write self-test results: %v\n", err)
		os.Exit(1)
	}
	for _, run := range runs {
		if run.Skipped == "" && run.Summary.Failed() {
			os.Exit(1)
		}
	}
}

// selfTestRuns measures every rule set this build has. A build without YARA-X
// explicitly reports YARA-X as skipped so partial coverage stays visible.
func selfTestRuns(rulesDir string) ([]engineRun, error) {
	scanner := signatures.NewScanner(rulesDir)
	if loadErr := scanner.LoadError(); loadErr != nil {
		return nil, fmt.Errorf("loading realtime rules: %w", loadErr)
	}
	if scanner.RuleCount() == 0 {
		return nil, fmt.Errorf("no signature rules loaded from %q; run `csm update-rules` or check signatures.rules_dir", rulesDir)
	}

	results := selftest.Run(selftest.Realtime, func(content []byte, ext string) ([]string, error) {
		var names []string
		for _, m := range scanner.ScanContent(content, ext) {
			names = append(names, m.RuleName)
		}
		return names, nil
	})
	runs := []engineRun{{
		Engine:    selftest.Realtime,
		RuleCount: scanner.RuleCount(),
		Summary:   selftest.Summarize(results),
		Results:   results,
	}}

	if !yara.Available() {
		return append(runs, engineRun{
			Engine:  selftest.Yara,
			Skipped: "YARA-X is not compiled into this build; YARA coverage was not tested",
		}), nil
	}
	yaraScanner, err := yara.NewScanner(rulesDir)
	if err != nil {
		return nil, fmt.Errorf("loading YARA rules: %w", err)
	}
	if yaraScanner.RuleCount() == 0 {
		return nil, fmt.Errorf("no YARA rules loaded from %q; run `csm update-rules` or check signatures.rules_dir", rulesDir)
	}
	yaraResults := selftest.Run(selftest.Yara, func(content []byte, _ string) ([]string, error) {
		matches, err := yaraScanner.ScanBytesChecked(content)
		if err != nil {
			return nil, err
		}
		var names []string
		for _, m := range matches {
			names = append(names, m.RuleName)
		}
		return names, nil
	})
	return append(runs, engineRun{
		Engine:    selftest.Yara,
		RuleCount: yaraScanner.RuleCount(),
		Summary:   selftest.Summarize(yaraResults),
		Results:   yaraResults,
	}), nil
}

func writeSelfTest(w io.Writer, rulesDir string, runs []engineRun, asJSON bool) error {
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]any{"rules_dir": rulesDir, "engines": runs})
	}

	for _, run := range runs {
		if run.Skipped != "" {
			if _, err := fmt.Fprintf(w, "%s: SKIPPED - %s\n\n", run.Engine, run.Skipped); err != nil {
				return err
			}
			continue
		}
		if _, err := fmt.Fprintf(w, "%s rules (%d loaded from %s)\n", run.Engine, run.RuleCount, rulesDir); err != nil {
			return err
		}
		for _, r := range run.Results {
			if _, err := fmt.Fprintf(w, "  %-26s %-16s %s\n", r.Name, selfTestVerdict(r), r.Description); err != nil {
				return err
			}
			if len(r.Rules) > 0 {
				if _, err := fmt.Fprintf(w, "  %-26s   %v\n", "", r.Rules); err != nil {
					return err
				}
			}
			if r.Error != "" {
				if _, err := fmt.Fprintf(w, "  %-26s   %s\n", "", r.Error); err != nil {
					return err
				}
			}
		}
		s := run.Summary
		if _, err := fmt.Fprintf(w, "  %d detected, %d clean, %d known gap(s), %d missed, %d false positive(s), %d closed gap(s), %d error(s)\n\n",
			s.Detected, s.Clean, s.KnownGaps, s.Missed, s.FalsePositives, s.ClosedGaps, s.Errors); err != nil {
			return err
		}
	}
	return nil
}

// selfTestVerdict names the outcome in the terms an operator judges it by.
func selfTestVerdict(r selftest.Result) string {
	switch {
	case r.Error != "":
		return "ERROR"
	case r.KnownGap && r.Detected:
		return "GAP CLOSED"
	case r.KnownGap:
		return "known gap"
	case r.Malicious && r.Detected:
		return "detected"
	case r.Malicious:
		return "MISSED"
	case r.Detected:
		return "FALSE POSITIVE"
	default:
		return "clean"
	}
}
