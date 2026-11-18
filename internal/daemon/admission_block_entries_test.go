package daemon

import (
	"slices"
	"testing"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/config"
)

// The entries whose automatic IP blocks admission may run follow the
// switches their legacy paths test. A central block lasts a day, so under
// a shorter block lease it stays on the legacy path and is not listed.
func TestAdmissionBlockEntriesFollowTheConfig(t *testing.T) {
	const on = "auto_response:\n  enabled: true\n  block_ips: true\n"
	central := "reputation:\n  central:\n    enabled: true\n    action: block_if_local_corroborated\n"
	scan := admission.EntryScan
	for _, tc := range []struct {
		name, yaml string
		want       []admission.Entry
	}{
		{"auto response off", "auto_response:\n  enabled: false\n  block_ips: true\n", nil},
		{"no ip blocks", "auto_response:\n  enabled: true\n", nil},
		{"scan", on, []admission.Entry{scan}},
		{"challenge", on + "challenge:\n  enabled: true\n", []admission.Entry{scan, admission.EntryChallengeTimeout}},
		{"incident", on + "incidents:\n  auto_block:\n    enabled: true\n    block_at_severity: high\n", []admission.Entry{scan, admission.EntryIncident}},
		{"incident detection only", on + "incidents:\n  auto_block:\n    enabled: true\n", []admission.Entry{scan}},
		{"spray", on + "incidents:\n  spray_suppression:\n    enabled: true\n    block_at_severity: critical\n", []admission.Entry{scan, admission.EntryIncidentSpray}},
		{"central", on + central, []admission.Entry{scan, admission.EntryCentral}},
		{"central under a short lease", on + "  block_expiry: 12h\n" + central, []admission.Entry{scan}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := config.LoadBytes([]byte(tc.yaml))
			if err != nil {
				t.Fatal(err)
			}
			if got := admissionBlockEntries(cfg); !slices.Equal(got, tc.want) {
				t.Fatalf("entries = %v, want %v", got, tc.want)
			}
		})
	}
}
