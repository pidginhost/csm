package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// The same records as the checks package's apiAuthRuleCases: the realtime
// handler must count exactly what the scheduled scan counts.
func TestParseAccessLogLineEnhancedCountsOnlyAPIRequests(t *testing.T) {
	cases := []struct {
		name, target, status, port string
		counted                    bool
	}{
		{"cpanel page on an expired session", "/cpsess0123456789/frontend/jupiter/index.html", "401", "2083", false},
		{"webmail page on an expired session", "/cpsess0123456789/3rdparty/roundcube/?_task=mail&_action=refresh", "401", "2096", false},
		{"legacy XML API call", "/xml-api/cpanel?cpanel_xmlapi_module=Email&cpanel_xmlapi_func=listpopswithdisk", "401", "2083", true},
		{"UAPI call", "/execute/Email/list_pops", "401", "2083", true},
		{"WHM API call", "/json-api/listaccts?api.version=1", "403", "2087", true},
		{"UAPI call on a session URL", "/cpsess0123456789/execute/Email/list_pops", "401", "2083", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetPurgeTrackerState()
			line := `203.0.113.50 - - [04/12/2026:07:00:05 -0000] "GET ` + tc.target + ` HTTP/1.1" ` + tc.status + ` 0 "-" "Mozilla/5.0" "-" "-" ` + tc.port
			got := false
			for _, f := range parseAccessLogLineEnhanced(line, &config.Config{}) {
				if f.Check == "api_auth_failure_realtime" {
					got = true
				}
			}
			if got != tc.counted {
				t.Fatalf("api_auth_failure_realtime reported = %v, want %v", got, tc.counted)
			}
		})
	}
}
