package webui

import (
	"encoding/json"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func TestSettingsApplyPreservesAdmissionCeilingSource(t *testing.T) {
	live, err := config.LoadBytes(nil)
	if err != nil {
		t.Fatal(err)
	}
	section, ok := LookupSettingsSection("auto_response")
	if !ok {
		t.Fatal("missing auto_response section")
	}
	for _, tc := range []struct {
		value  string
		limit  uint32
		source string
	}{
		{"50", 50, config.CeilingConfigured},
		{"7", 7, config.CeilingConfigured},
		{"0", 2000, config.CeilingDefault},
		{"25000", 20000, config.CeilingClamped},
	} {
		disk, err := config.LoadBytes([]byte("auto_response:\n  max_blocks_per_hour: " + tc.value + "\n"))
		if err != nil {
			t.Fatal(err)
		}
		candidate := cloneConfigForSettingsApply(live)
		if err := copySettingsChangeValues(&candidate, disk, section, map[string]json.RawMessage{"max_blocks_per_hour": json.RawMessage(tc.value)}); err != nil {
			t.Fatal(err)
		}
		if limit, source := candidate.AdmissionCeiling(); limit != tc.limit || source != tc.source {
			t.Errorf("save %s: live ceiling %d (%s), want %d (%s)", tc.value, limit, source, tc.limit, tc.source)
		}
		live = &candidate
	}
}
