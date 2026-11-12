package daemon

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/config"
)

// Use the scheduled scan's corpus so neither caller can silently diverge.
func TestParseAccessLogLineEnhancedCountsOnlyAPIRequests(t *testing.T) {
	old := purgeTracker
	resetPurgeTrackerState()
	t.Cleanup(func() { purgeTracker = old })
	data, err := os.ReadFile("../checks/testdata/api_auth_rule.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name, Line string
		Counted    bool
		SourceIP   string `json:"source_ip"`
	}
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) == 0 {
		t.Fatal("empty API authentication corpus")
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			got := 0
			for _, f := range parseAccessLogLineEnhanced(tc.Line, &config.Config{}) {
				if f.Check == "api_auth_failure_realtime" {
					got++
					attribution := admission.AttributionPeer
					if tc.SourceIP == "" {
						attribution = admission.AttributionUnknown
					}
					if f.SourceIP != tc.SourceIP || f.Attribution != attribution {
						t.Fatalf("incorrect API attribution: %+v", f)
					}
				}
			}
			want := 0
			if tc.Counted {
				want = 1
			}
			if got != want {
				t.Fatalf("got %d API failures, want %d", got, want)
			}
		})
	}
}
