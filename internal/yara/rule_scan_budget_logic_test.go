//go:build yara

package yara_test

import (
	"bytes"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	yara_x "github.com/VirusTotal/yara-x/go"
)

func TestRuleScanBudgetMeasurement(t *testing.T) {
	if scanBudgetPerFile != 5*time.Second || scanBudgetRepeats < 2 {
		t.Fatal("keep the five-second budget and at least two scored samples")
	}
	scanErr := errors.New("scan failed")
	for _, tc := range []struct {
		name      string
		samples   []time.Duration
		errors    []error
		wantBest  time.Duration
		wantError error
	}{
		{"cold outlier", []time.Duration{time.Minute, time.Second, 2 * time.Second}, nil, time.Second, nil},
		{"scored outlier", []time.Duration{time.Second, time.Minute, time.Second}, nil, time.Second, nil},
		{"last outlier", []time.Duration{time.Second, time.Second, time.Minute}, nil, time.Second, nil},
		{"near budget", []time.Duration{time.Second, 4900 * time.Millisecond, 6 * time.Second}, nil, 4900 * time.Millisecond, nil},
		{"at budget", []time.Duration{time.Second, 5 * time.Second, 6 * time.Second}, nil, 5 * time.Second, nil},
		{"over budget", []time.Duration{time.Second, 5100 * time.Millisecond, 6 * time.Second}, nil, 5100 * time.Millisecond, nil},
		{"slow throughout", []time.Duration{time.Minute, time.Minute, time.Minute}, nil, time.Minute, nil},
		{"cold timeout", []time.Duration{time.Minute, time.Second, 2 * time.Second}, []error{yara_x.ErrTimeout, nil, nil}, time.Second, nil},
		{"first timeout", []time.Duration{time.Second, time.Minute, time.Second}, []error{nil, yara_x.ErrTimeout, nil}, time.Second, nil},
		{"last timeout", []time.Duration{time.Second, time.Second, time.Minute}, []error{nil, nil, yara_x.ErrTimeout}, time.Second, nil},
		{"all scored time out", []time.Duration{time.Second, time.Minute, time.Minute}, []error{nil, yara_x.ErrTimeout, yara_x.ErrTimeout}, 0, yara_x.ErrTimeout},
		{"cold error", []time.Duration{time.Second}, []error{scanErr}, 0, scanErr},
		{"first error", []time.Duration{time.Second, time.Second}, []error{nil, scanErr}, 0, scanErr},
		{"last error", []time.Duration{time.Second, time.Second, time.Second}, []error{nil, nil, scanErr}, 0, scanErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			warmup, best, err := measureScanBudget(func() (time.Duration, error) {
				if calls >= len(tc.samples) {
					t.Fatal("unexpected extra scan")
				}
				i := calls
				calls++
				if tc.errors != nil {
					return tc.samples[i], tc.errors[i]
				}
				return tc.samples[i], nil
			})
			if !errors.Is(err, tc.wantError) {
				t.Fatalf("error = %v, want %v", err, tc.wantError)
			}
			if err == nil && best != tc.wantBest {
				t.Errorf("best = %s, want %s", best, tc.wantBest)
			}
			if warmup != tc.samples[0] || calls != len(tc.samples) {
				t.Errorf("warm-up = %s, calls = %d; want %s, %d", warmup, calls, tc.samples[0], len(tc.samples))
			}
		})
	}
}

func TestRuleScanBudgetFixtures(t *testing.T) {
	inputs := adversarialInputs(t)
	if len(inputs) != 4 {
		t.Fatalf("fixture count = %d, want 4", len(inputs))
	}
	for name, want := range adversarialInputs(t) {
		if !bytes.Equal(inputs[name], want) {
			t.Errorf("%s is not deterministic", name)
		}
	}
	// Length alone is insufficient: punctuation/newlines inside a class run
	// let the regex fail early at every offset, hiding the quadratic work.
	for _, tc := range []struct {
		name, prefix, alphabet string
		minimum                int
	}{
		{"base64_blob.php", "$img = '", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", 900_000},
		{"minified_hex.js", `var d="`, "0123456789abcdef", 600_000},
		{"minified_hex.js", `var w="`, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_", 300_000},
	} {
		_, body, found := bytes.Cut(inputs[tc.name], []byte(tc.prefix))
		if !found {
			t.Fatalf("%s: missing %q", tc.name, tc.prefix)
		}
		longest, current := 0, 0
		for _, b := range body {
			if strings.IndexByte(tc.alphabet, b) < 0 {
				current = 0
				continue
			}
			current++
			if current > longest {
				longest = current
			}
		}
		if longest < tc.minimum {
			t.Errorf("%s longest class run = %d, want >= %d", tc.name, longest, tc.minimum)
		}
	}
	// Check actual variable calls, not just the number of lines.
	calls := regexp.MustCompile(`(?m)^\$fn[0-9]+\( \$a[0-9]+ \); \$v[0-9]+ = 'literal[0-9]+';$`)
	if count := len(calls.FindAll(inputs["many_calls.php"], -1)); count != 40_000 {
		t.Errorf("variable calls = %d, want 40000", count)
	}
	pdf := inputs["streams.pdf"]
	if !bytes.HasPrefix(pdf, []byte("%PDF-1.7\n")) {
		t.Error("missing PDF header")
	}
	streams := regexp.MustCompile(`(?m)^stream\n([A-Za-z0-9+/]+)\nendstream\n`).FindAllSubmatch(pdf, -1)
	if len(streams) != 40 {
		t.Fatalf("PDF streams = %d, want 40", len(streams))
	}
	for i, stream := range streams {
		if len(stream[1]) < 60_000 {
			t.Errorf("PDF stream %d has only %d uninterrupted bytes", i, len(stream[1]))
		}
	}
}
