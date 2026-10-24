package signatures

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestArchiveLoaderFixtures(t *testing.T) {
	data, err := os.ReadFile("testdata/archive_loader.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct {
		Name   string
		Rule   string
		Want   bool
		Sample string
	}
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	if len(fixtures) == 0 {
		t.Fatal("no archive loader fixtures")
	}
	scanner := loadRepoScanner(t)
	for _, tc := range fixtures {
		t.Run(tc.Name, func(t *testing.T) {
			got := hasRule(scanner.ScanContent([]byte(tc.Sample), ".php"), tc.Rule)
			if got != tc.Want {
				t.Fatalf("%s match = %v, want %v", tc.Rule, got, tc.Want)
			}
		})
	}
}

// Reverification scans whole files, so the realtime prefix limit cannot keep
// the archive proximity check cheap when both tokens occur far apart.
func TestArchiveLoaderScanBudget(t *testing.T) {
	repo := loadRepoScanner(t)
	var rules []Rule
	for _, rule := range repo.rules {
		if rule.Name == "backdoor_archive_loader" {
			rules = append(rules, rule)
		}
	}
	if len(rules) != 1 {
		t.Fatalf("archive rules = %d, want 1", len(rules))
	}
	scanner := &Scanner{rules: rules}
	// Compare with the same rule's other branches so race instrumentation and
	// slower CI CPUs do not turn the scan-cost regression into a timing flake.
	controlRule := rules[0]
	controlRule.compiledRegexPairs = nil
	controlRule.compiledRegexes = nil
	for _, re := range rules[0].compiledRegexes {
		if !strings.Contains(re.String(), `\?>`) {
			controlRule.compiledRegexes = append(controlRule.compiledRegexes, re)
		}
	}
	control := &Scanner{rules: []Rule{controlRule}}
	for _, size := range []int{32 << 10, 64 << 10, 1 << 20} {
		t.Run(fmt.Sprintf("%d_bytes", size), func(t *testing.T) {
			part := "eval('?>' . $t); "
			content := []byte("<?php\n" + strings.Repeat(part, (size-2048)/len(part)) + strings.Repeat(" ", 2000) + "$z->getFromName('data');")
			var elapsed, baseline time.Duration
			for run := 0; run < 3; run++ {
				start := time.Now()
				if hits := control.ScanContent(content, ".php"); len(hits) != 0 {
					t.Fatalf("control matched: %v", hits)
				}
				controlTime := time.Since(start)
				start = time.Now()
				if hits := scanner.ScanContent(content, ".php"); len(hits) != 0 {
					t.Fatalf("unrelated archive read matched: %v", hits)
				}
				scanTime := time.Since(start)
				if run == 1 || run == 2 && scanTime < elapsed {
					elapsed = scanTime
				}
				if run == 1 || run == 2 && controlTime < baseline {
					baseline = controlTime
				}
			}
			t.Logf("%d bytes: %s, other branches: %s", len(content), elapsed, baseline)
			if elapsed > 3*baseline {
				t.Errorf("archive scan took %s, budget is three times the other branches (%s)", elapsed, baseline)
			}
		})
	}
}
