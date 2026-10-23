package signatures

import (
	"encoding/json"
	"os"
	"testing"
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
