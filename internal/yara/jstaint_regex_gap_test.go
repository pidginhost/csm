//go:build yara

package yara

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/pidginhost/csm/internal/jstaint"
)

type regexGapFixture struct {
	Name   string `json:"name"`
	Source string `json:"source"`
}

func loadRegexGapFixtures(t *testing.T) []regexGapFixture {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	path := filepath.Join(filepath.Dir(thisFile), "..", "jstaint", "testdata", "regex_gap_cases.json")
	data, err := os.ReadFile(path) // #nosec G304 -- path is anchored at this test source file
	if err != nil {
		t.Fatalf("reading regex-gap fixtures: %v", err)
	}
	var fixtures []regexGapFixture
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatalf("parsing regex-gap fixtures: %v", err)
	}
	if len(fixtures) == 0 {
		t.Fatal("regex-gap fixture set is empty")
	}
	return fixtures
}

// TestExfilKeyloggerRegexGap_YARA is the YARA half of the analyzer's
// justification: each variable-indirection keylogger is missed by the YARA
// exfil_keylogger_js rule yet detected by the analyzer. Together with the YAML
// half in internal/signatures it proves each shape is missed by both regex
// engines.
func TestExfilKeyloggerRegexGap_YARA(t *testing.T) {
	scanner := loadRepoYaraScanner(t)
	for _, fixture := range loadRegexGapFixtures(t) {
		t.Run(fixture.Name, func(t *testing.T) {
			matches, err := scanner.ScanBytesChecked([]byte(fixture.Source))
			if err != nil {
				t.Fatalf("scanning fixture with YARA-X: %v", err)
			}
			if hasYaraRule(matches, "exfil_keylogger_js") {
				t.Errorf("YARA exfil_keylogger_js matched %s; fixture no longer proves the regex gap", fixture.Name)
			}
			rep := jstaint.Analyze(context.Background(), []byte(fixture.Source))
			if rep.Status != jstaint.StatusAnalyzed || len(rep.Results) == 0 {
				t.Errorf("analyzer missed %s: status=%v results=%d", fixture.Name, rep.Status, len(rep.Results))
			}
		})
	}
}
