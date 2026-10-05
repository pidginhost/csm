package config

import (
	"testing"

	"github.com/pidginhost/csm/internal/admission"
)

// Ruling R4 (spec 5.6): the admission ceiling maps max_blocks_per_hour,
// with omitted or zero selecting its own default and values past the
// largest ceiling clamped. The legacy hourly counter keeps reading the
// same key with its own default until routing replaces it.
func TestAdmissionCeilingMapsMaxBlocksPerHour(t *testing.T) {
	for _, tc := range []struct {
		yaml   string
		limit  uint32
		source string
		legacy int
	}{
		{"", DefaultAdmissionCeiling, CeilingDefault, DefaultMaxBlocksPerHour},
		{"auto_response:\n  max_blocks_per_hour: 0\n", DefaultAdmissionCeiling, CeilingDefault, DefaultMaxBlocksPerHour},
		{"auto_response:\n  max_blocks_per_hour: 50\n", 50, CeilingConfigured, 50},
		{"auto_response:\n  max_blocks_per_hour: 200\n", 200, CeilingConfigured, 200},
		{"auto_response:\n  max_blocks_per_hour: 1\n", 1, CeilingConfigured, 1},
		{"auto_response:\n  max_blocks_per_hour: 25000\n", admission.MaxCeiling, CeilingClamped, 25000},
	} {
		cfg, err := LoadBytes([]byte(tc.yaml))
		if err != nil {
			t.Fatalf("%q: %v", tc.yaml, err)
		}
		if limit, source := cfg.AdmissionCeiling(); limit != tc.limit || source != tc.source {
			t.Errorf("%q: ceiling %d (%s), want %d (%s)", tc.yaml, limit, source, tc.limit, tc.source)
		}
		if cfg.AutoResponse.MaxBlocksPerHour != tc.legacy {
			t.Errorf("%q: legacy counter limit %d, want %d", tc.yaml, cfg.AutoResponse.MaxBlocksPerHour, tc.legacy)
		}
	}
	code := &Config{}
	if limit, source := code.AdmissionCeiling(); limit != DefaultAdmissionCeiling || source != CeilingDefault {
		t.Errorf("config built without the key: %d (%s)", limit, source)
	}
	code.AutoResponse.MaxBlocksPerHour = 7
	if limit, source := code.AdmissionCeiling(); limit != 7 || source != CeilingConfigured {
		t.Errorf("config built with 7: %d (%s)", limit, source)
	}
}

// Writing the old default explicitly changes the admission ceiling, so a
// reload that does it must report a change for the owner to apply.
func TestAdmissionCeilingSourceChangeIsAReload(t *testing.T) {
	omitted, err := LoadBytes(nil)
	if err != nil {
		t.Fatal(err)
	}
	explicit, err := LoadBytes([]byte("auto_response:\n  max_blocks_per_hour: 50\n"))
	if err != nil {
		t.Fatal(err)
	}
	changes := Diff(omitted, explicit)
	if len(changes) != 1 || changes[0].Field != "auto_response" || changes[0].Tag != TagSafe {
		t.Fatalf("changes = %+v, want one safe auto_response change", changes)
	}
}
