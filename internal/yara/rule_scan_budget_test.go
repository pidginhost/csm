//go:build yara

package yara_test

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

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
// The ceiling is deliberately far above a healthy ruleset (sub-second on these
// inputs) so ordinary CI noise cannot trip it. Anything approaching it is a
// missing atom, not slow hardware.
const scanBudgetPerFile = 5 * time.Second

// decisivelyOverBudget is where a single run settles the question by itself:
// no warm-up artifact turns a sub-second scan into this.
const decisivelyOverBudget = 2 * scanBudgetPerFile

// scanBudgetRepeats is how many scored runs follow the discarded warm-up.
const scanBudgetRepeats = 2

const missingAtomHint = "A pattern is missing a literal atom to prefilter on; find it with `yr compile --profile` or by bisecting recent rule changes."

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

	dir := t.TempDir()
	for name, content := range adversarialInputs(t) {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}

		scanOnce := func() time.Duration {
			start := time.Now()
			if _, err := csmyara.ScanBytesChecked(scanner, path, content); err != nil {
				t.Fatalf("%s: scan failed: %v", name, err)
			}
			return time.Since(start)
		}

		// One cold run is not a measurement. A warm-up is discarded and the
		// best of the repeats is scored, because a single slow sample is how
		// both a bad rule and a bad rule-removal decision got made on this
		// ruleset. A warm-up far past the budget is decisive on its own, so
		// bail there rather than repeat a scan that takes minutes.
		warmup := scanOnce()
		if warmup > decisivelyOverBudget {
			t.Errorf("%s: scan took %s, budget is %s. %s", name, warmup.Round(time.Millisecond), scanBudgetPerFile, missingAtomHint)
			continue
		}
		best := scanOnce()
		for i := 1; i < scanBudgetRepeats; i++ {
			if e := scanOnce(); e < best {
				best = e
			}
		}

		t.Logf("%-16s %8d bytes  best %s (warm-up %s)", name, len(content), best.Round(time.Millisecond), warmup.Round(time.Millisecond))
		if best > scanBudgetPerFile {
			t.Errorf("%s: scan took %s, budget is %s. %s", name, best.Round(time.Millisecond), scanBudgetPerFile, missingAtomHint)
		}
	}
}
