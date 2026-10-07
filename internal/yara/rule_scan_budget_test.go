//go:build yara

package yara_test

import (
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	yara_x "github.com/VirusTotal/yara-x/go"
	csmyara "github.com/pidginhost/csm/internal/yara"
)

// scanBudgetPerFile is the wall-clock ceiling for scanning one adversarial
// file with the shipped ruleset.
//
// A pattern with no literal atom gives the engine nothing to prefilter on, so
// it runs the regex across every byte of every file. That is invisible in rule
// review and in match-correctness tests: the rule still matches what it should.
// It surfaces only as time. A rule shipped without this gate took 60s on a
// 900KB base64 string where the rest of the ruleset took 0.4s, which stalled
// mail delivery host-wide until the scan budget in the spool watcher cut it off.
//
// The ceiling leaves headroom above healthy sub-second scans. Only warmed-up
// repeats are scored; a cold scan or scheduler pause can exceed any threshold.
const scanBudgetPerFile = 5 * time.Second

// Bound pathological scans without confusing one timeout with a regression.
// This is a cancellation limit, not a relaxation of the scored budget.
const scanBudgetTimeout = 2 * scanBudgetPerFile

// scanBudgetRepeats is how many scored runs follow the discarded warm-up.
const scanBudgetRepeats = 2

const missingAtomHint = "Check for a missing prefilter atom with `yr scan --profiling` or by bisecting recent rule changes."

// adversarialInputs are clean files shaped like the content that makes an
// atom-less pattern expensive: long uninterrupted runs over a character class.
// None of them is malware; they exist to be scanned, not matched.
func adversarialInputs(t *testing.T) map[string][]byte {
	t.Helper()
	rnd := rand.New(rand.NewSource(20260916)) // #nosec G404 -- deterministic test fixture, not security.

	run := func(alphabet string, n int) string {
		b := make([]byte, n)
		for i := range b {
			b[i] = alphabet[rnd.Intn(len(alphabet))]
		}
		return string(b)
	}
	const (
		base64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
		hexAlphabet    = "0123456789abcdef"
		wordAlphabet   = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_"
	)

	inputs := map[string][]byte{
		// A plugin shipping an inline data URI: one very long base64 run.
		"base64_blob.php": []byte("<?php\n$img = '" + run(base64Alphabet, 900_000) + "';\n"),
		// A minified asset: long hex and word runs, no line breaks.
		"minified_hex.js": []byte("var d=\"" + run(hexAlphabet, 600_000) + "\";var w=\"" + run(wordAlphabet, 300_000) + "\";"),
		// Dense variable-call syntax, the shape dynamic-call patterns scan for.
		"many_calls.php": []byte("<?php\n" + repeatLines("$fn%[1]d( $a%[1]d ); $v%[1]d = 'literal%[1]d';", 40_000)),
		// A PDF-shaped body: many long base64-ish streams.
		"streams.pdf": []byte("%PDF-1.7\n" + repeatStreams(run(base64Alphabet, 60_000), 40)),
		// Download command names on one line, the literal that download and
		// miner signatures anchor on.
		"download_words.txt": []byte(strings.Repeat("curl wget ", 30_000)),
	}
	return inputs
}

func repeatLines(format string, n int) string {
	var out strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&out, format, i)
		out.WriteByte('\n')
	}
	return out.String()
}

func repeatStreams(body string, n int) string {
	var out strings.Builder
	for i := 0; i < n; i++ {
		out.WriteString("stream\n" + body + "\nendstream\n")
	}
	return out.String()
}

func measureScanBudget(scan func() (time.Duration, error)) (warmup, best time.Duration, err error) {
	warmup, err = scan()
	if err != nil && !errors.Is(err, yara_x.ErrTimeout) {
		return warmup, 0, err
	}
	completed := 0
	for i := 0; i < scanBudgetRepeats; i++ {
		elapsed, scanErr := scan()
		if errors.Is(scanErr, yara_x.ErrTimeout) {
			continue
		}
		if scanErr != nil {
			return warmup, best, scanErr
		}
		if completed == 0 || elapsed < best {
			best = elapsed
		}
		completed++
	}
	if completed == 0 {
		return warmup, 0, fmt.Errorf("all %d scored scans exceeded the %s timeout: %w", scanBudgetRepeats, scanBudgetTimeout, yara_x.ErrTimeout)
	}
	return warmup, best, nil
}

func scanWithBudgetTimeout(rules *yara_x.Rules, content []byte) (time.Duration, error) {
	start := time.Now()
	// Match Rules.Scan's fresh scanner and default (non-fast) scan mode. Use
	// the engine directly to set its timeout and avoid any content-policy skip.
	scanner := yara_x.NewScanner(rules)
	defer scanner.Destroy()
	scanner.SetTimeout(scanBudgetTimeout)
	_, err := scanner.Scan(content)
	return time.Since(start), err
}

// TestShippedRulesScanWithinBudget is the standing guard against a rule that
// is correct but unscannable. Every shipped rule is measured against content
// built to starve a missing prefilter atom.
func TestShippedRulesScanWithinBudget(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	configsDir := filepath.Join(filepath.Dir(thisFile), "..", "..", "configs")
	scanner, err := csmyara.NewScanner(configsDir)
	if err != nil {
		t.Fatalf("loading YARA rules: %v", err)
	}
	if scanner.RuleCount() == 0 {
		t.Fatal("scanner loaded zero rules")
	}

	for name, content := range adversarialInputs(t) {
		t.Run(name, func(t *testing.T) {
			// Always discard the warm-up, even if it times out. Two scored
			// attempts give an isolated scheduler stall a chance to recover.
			warmup, best, err := measureScanBudget(func() (time.Duration, error) {
				return scanWithBudgetTimeout(scanner.GlobalRules(), content)
			})
			if err != nil {
				t.Fatalf("scan failed: %v (warm-up %s). %s", err, warmup.Round(time.Millisecond), missingAtomHint)
			}
			t.Logf("%d bytes  best %s (warm-up %s)", len(content), best.Round(time.Millisecond), warmup.Round(time.Millisecond))
			if best > scanBudgetPerFile {
				t.Errorf("scan took %s, budget is %s. %s", best.Round(time.Millisecond), scanBudgetPerFile, missingAtomHint)
			}
		})
	}
}

// shippedRule compiles one rule out of the shipped malware.yar on its own.
func shippedRule(t *testing.T, name string) *yara_x.Rules {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	path := filepath.Join(filepath.Dir(thisFile), "..", "..", "configs", "malware.yar")
	source, err := os.ReadFile(path) // #nosec G304 -- fixed repository rule file
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	block := regexp.MustCompile(`(?ms)^rule ` + regexp.QuoteMeta(name) + ` \{.*?^\}`).Find(source)
	if block == nil {
		t.Fatalf("rule %s not found in %s", name, path)
	}
	rules, err := yara_x.Compile(string(block))
	if err != nil {
		t.Fatalf("compiling %s: %v", name, err)
	}
	return rules
}

// requireRuleScanBudget scans each input against one shipped rule compiled on
// its own, so a slow rule cannot hide inside the whole-ruleset budget.
func requireRuleScanBudget(t *testing.T, rule string, inputs map[string][]byte) {
	t.Helper()
	rules := shippedRule(t, rule)
	for name, content := range inputs {
		t.Run(name, func(t *testing.T) {
			warmup, best, err := measureScanBudget(func() (time.Duration, error) {
				return scanWithBudgetTimeout(rules, content)
			})
			if err != nil {
				t.Fatalf("scan failed: %v (warm-up %s)", err, warmup.Round(time.Millisecond))
			}
			t.Logf("%d bytes  best %s (warm-up %s)", len(content), best.Round(time.Millisecond), warmup.Round(time.Millisecond))
			if best > scanBudgetPerFile {
				t.Errorf("scan took %s, budget is %s", best.Round(time.Millisecond), scanBudgetPerFile)
			}
		})
	}
}

// A frequent literal between two unbounded gaps makes the engine verify every
// literal hit to the end of its line, so one long crafted line costs time
// quadratic in its length.
func TestRuleScanBudgetCronDownloaderLines(t *testing.T) {
	requireRuleScanBudget(t, "backdoor_cron_downloader", map[string][]byte{
		"download_words.txt": []byte("*/5 * * * * " + strings.Repeat("curl wget ", 100_000)),
		"cron_prefixes.txt":  []byte(strings.Repeat("*/5 * * * * wget x ", 55_000)),
		"pipe_targets.txt":   []byte(strings.Repeat("* * curl x | sh ", 65_000)),
	})
}

// The download, miner and startup-file rules share the cron rule's shape. The
// Markdown checks in two of them also compared every command with every fenced
// block or link, which is quadratic in the number of commands even when each
// line is short.
func TestRuleScanBudgetDownloadAndMinerLines(t *testing.T) {
	downloadWords := []byte(strings.Repeat("curl wget ", 60_000))
	downloadArgs := []byte(strings.Repeat("wget x ", 85_000))
	tests := []struct {
		rule   string
		inputs map[string][]byte
	}{
		{"miner_shell_downloader", map[string][]byte{
			"download_words.txt": downloadWords,
			"download_args.txt":  downloadArgs,
		}},
		{"miner_cron_persistence", map[string][]byte{
			"cron_prefixes.txt":  []byte(strings.Repeat("*/5 * * * * ", 50_000)),
			"cron_downloads.txt": []byte(strings.Repeat("*/5 * * * * wget x ", 32_000)),
		}},
		{"dropper_wget_exec", map[string][]byte{
			"download_words.txt":    downloadWords,
			"download_args.txt":     downloadArgs,
			"pipe_targets.txt":      []byte(strings.Repeat("curl x | sh ", 50_000)),
			"versioned_targets.txt": []byte(strings.Repeat("curl x | python3.13t ", 30_000)),
			"long_version.txt":      []byte("curl x | python" + strings.Repeat("3.", 300_000)),
			"fenced_commands.md":    []byte(strings.Repeat("```sh\ncurl x | sh\n```\n", 27_000)),
			"linked_commands.md":    []byte(strings.Repeat("[curl x | sh](https://a.test/)\n", 20_000)),
			"backtick_runs.txt":     []byte(strings.Repeat("`", 600_000)),
			"fence_lines.md":        []byte(strings.Repeat("```\n", 150_000)),
		}},
		{"backdoor_bashrc_injection", map[string][]byte{
			"download_words.txt":      downloadWords,
			"download_args.txt":       downloadArgs,
			"background_words.txt":    []byte(strings.Repeat("nohup ", 100_000)),
			"fenced_startup_lines.md": []byte(strings.Repeat("```sh\necho 'curl x | sh' >> ~/.bashrc\n```\n", 15_000)),
			"startup_lines_in_fences.md": []byte(strings.Repeat(
				"```sh\n"+strings.Repeat("echo 'curl x | sh' >> ~/.bashrc\n", 100)+"```\n", 180)),
		}},
	}
	for _, tc := range tests {
		t.Run(tc.rule, func(t *testing.T) {
			requireRuleScanBudget(t, tc.rule, tc.inputs)
		})
	}
}
