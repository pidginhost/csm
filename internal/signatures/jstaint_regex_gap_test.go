package signatures

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

// TestExfilKeyloggerRegexGap_YAML is the justification for the data-flow
// analyzer: each variable-indirection keylogger is missed by the YAML
// exfil_keylogger_js rule yet detected by the analyzer. If the rule ever starts
// matching one of these, the fixture no longer proves the gap and must be
// revisited rather than silently passing.
func TestExfilKeyloggerRegexGap_YAML(t *testing.T) {
	scanner := loadRepoScanner(t)
	if err := scanner.LoadError(); err != nil {
		t.Fatalf("loading repository signature rules: %v", err)
	}
	for _, fixture := range loadRegexGapFixtures(t) {
		t.Run(fixture.Name, func(t *testing.T) {
			if hasRule(scanner.ScanContent([]byte(fixture.Source), ".js"), "exfil_keylogger_js") {
				t.Errorf("YAML exfil_keylogger_js matched %s; fixture no longer proves the regex gap", fixture.Name)
			}
			rep := jstaint.Analyze(context.Background(), []byte(fixture.Source))
			if rep.Status != jstaint.StatusAnalyzed || len(rep.Results) == 0 {
				t.Errorf("analyzer missed %s: status=%v results=%d", fixture.Name, rep.Status, len(rep.Results))
			}
		})
	}
}
