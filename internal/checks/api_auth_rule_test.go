package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/config"
)

// The realtime handler reads this same corpus. Counts and peer attribution
// must agree even when client text adds a request or status.
func TestCheckAPIAuthFailuresCountsOnlyAPIRequests(t *testing.T) {
	forceCPanelPlatform(t)
	data, err := os.ReadFile("testdata/api_auth_rule.json")
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
			access := make([]string, apiFailThreshold)
			for i := range access {
				access[i] = tc.Line
			}
			staleSessionLogs(t, access, nil)

			got := CheckAPIAuthFailures(context.Background(), &config.Config{}, nil)
			want := 0
			if tc.Counted {
				want = 1
			}
			if len(got) != want {
				t.Fatalf("got %+v, want %d API findings", got, want)
			}
			if want == 0 {
				return
			}
			source, attribution := tc.SourceIP, admission.AttributionPeer
			if source == "" {
				source, attribution = "a service subdomain (client address unverified)", admission.AttributionUnknown
			}
			message := fmt.Sprintf("cPanel API auth failures from %s: %d attempts", source, len(access))
			if got[0].Check != "api_auth_failure" || got[0].Message != message ||
				got[0].SourceIP != tc.SourceIP || got[0].Attribution != attribution {
				t.Fatalf("incorrect API count or attribution: %+v", got[0])
			}
		})
	}
}
