//go:build yara

package yara_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/pidginhost/csm/internal/signatures"
	csmyara "github.com/pidginhost/csm/internal/yara"
)

func TestCredentialMailerByteParity(t *testing.T) {
	yml := signatures.NewScanner("../../configs")
	if err := yml.LoadError(); err != nil {
		t.Fatal(err)
	}
	yar, err := csmyara.NewScanner("../../configs")
	if err != nil {
		t.Fatal(err)
	}
	var tests []struct {
		Name, Sample string
		Want         bool
	}
	data, err := os.ReadFile("../signatures/testdata/credential_mailer.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &tests); err != nil {
		t.Fatal(err)
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			yamlHit, yaraHit := false, false
			for _, m := range yml.ScanContent([]byte(tt.Sample), ".php") {
				yamlHit = yamlHit || m.RuleName == "credential_mailer"
			}
			matches, err := yar.ScanBytesChecked([]byte(tt.Sample))
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range matches {
				yaraHit = yaraHit || m.RuleName == "credential_harvester_php"
			}
			if yamlHit != tt.Want || yaraHit != tt.Want {
				t.Errorf("YAML=%v YARA=%v, want both %v", yamlHit, yaraHit, tt.Want)
			}
		})
	}
}
