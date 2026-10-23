//go:build yara

package yara_test

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/signatures"
	csmyara "github.com/pidginhost/csm/internal/yara"
)

// Both engines must agree on every malicious and benign archive fixture.
func TestArchiveLoaderFixtureParity(t *testing.T) {
	data, err := os.ReadFile("../signatures/testdata/archive_loader.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct {
		Name   string
		Rule   string
		Want   bool
		Sample string
	}
	if err = json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	if len(fixtures) == 0 {
		t.Fatal("no archive loader fixtures")
	}
	yamlScanner := signatures.NewScanner("../../configs")
	if err = yamlScanner.LoadError(); err != nil {
		t.Fatal(err)
	}
	yaraScanner, err := csmyara.NewScanner("../../configs")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range fixtures {
		t.Run(tc.Name, func(t *testing.T) {
			yamlHit := false
			for _, m := range yamlScanner.ScanContent([]byte(tc.Sample), ".php") {
				yamlHit = yamlHit || m.RuleName == tc.Rule
			}
			rule := tc.Rule
			if rule == "dropper_php_stream_wrapper" {
				rule = "dropper_stream_wrapper_abuse"
			}
			matches := yaraScanner.ScanBytes([]byte(tc.Sample))
			yaraHit := false
			for _, m := range matches {
				yaraHit = yaraHit || m.RuleName == rule
			}
			if yamlHit != tc.Want || yaraHit != tc.Want {
				t.Fatalf("YAML = %v, YARA = %v, want %v", yamlHit, yaraHit, tc.Want)
			}
		})
	}
}

func TestArchiveLoaderProximityParity(t *testing.T) {
	yamlScanner := signatures.NewScanner("../../configs")
	if err := yamlScanner.LoadError(); err != nil {
		t.Fatal(err)
	}
	yaraScanner, err := csmyara.NewScanner("../../configs")
	if err != nil {
		t.Fatal(err)
	}
	for _, reverse := range []bool{false, true} {
		for _, offset := range []int{0, 6, 1000, 2000} {
			for _, distance := range []int{999, 1000, 1001, 1100} {
				t.Run(fmt.Sprintf("reverse=%v/offset=%d/distance=%d", reverse, offset, distance), func(t *testing.T) {
					first, second := "->getFromName('a');", "eval('?>' . $s);"
					if reverse {
						first, second = second, first
					}
					content := []byte(strings.Repeat(" ", offset) + first + strings.Repeat(" ", distance-len(first)) + second)
					want := distance <= 1000
					yamlHit := hasSignatureRule(yamlScanner.ScanContent(content, ".php"), "backdoor_archive_loader")
					yaraHit := hasRepositoryYaraRule(yaraScanner.ScanBytes(content), "backdoor_archive_loader")
					if yamlHit != want || yaraHit != want {
						t.Fatalf("YAML = %v, YARA = %v, want %v", yamlHit, yaraHit, want)
					}
				})
			}
		}
	}
}
