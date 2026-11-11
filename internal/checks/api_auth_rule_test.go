package checks

import (
	"context"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// apiAuthRuleCases are cpsrvd access_log records that the scheduled scan and
// the realtime handler must judge the same way. The daemon package holds the
// same cases for the realtime path.
var apiAuthRuleCases = []struct {
	name, target, status, port string
	counted                    bool
}{
	// A session URL carries no credential to guess, only a cookie and the
	// URL token cPanel purges after a few denials. These are expired tabs.
	{"cpanel page on an expired session", "/cpsess0123456789/frontend/jupiter/index.html", "401", "2083", false},
	{"webmail page on an expired session", "/cpsess0123456789/3rdparty/roundcube/?_task=mail&_action=refresh", "401", "2096", false},
	// cpsrvd still routes the deprecated XML API, so guessing through it
	// must count like the JSON API.
	{"legacy XML API call", "/xml-api/cpanel?cpanel_xmlapi_module=Email&cpanel_xmlapi_func=listpopswithdisk", "401", "2083", true},
	{"UAPI call", "/execute/Email/list_pops", "401", "2083", true},
	{"WHM API call", "/json-api/listaccts?api.version=1", "403", "2087", true},
	{"UAPI call on a session URL", "/cpsess0123456789/execute/Email/list_pops", "401", "2083", true},
}

func apiAuthRuleLine(ip, target, status, port string) string {
	return ip + ` - - [04/12/2026:07:00:05 -0000] "GET ` + target + ` HTTP/1.1" ` + status + ` 0 "-" "Mozilla/5.0" "-" "-" ` + port
}

func TestCheckAPIAuthFailuresCountsOnlyAPIRequests(t *testing.T) {
	forceCPanelPlatform(t)
	for _, tc := range apiAuthRuleCases {
		t.Run(tc.name, func(t *testing.T) {
			var access []string
			for i := 0; i <= apiFailThreshold; i++ {
				access = append(access, apiAuthRuleLine("203.0.113.50", tc.target, tc.status, tc.port))
			}
			staleSessionLogs(t, access, nil)

			got := false
			for _, f := range CheckAPIAuthFailures(context.Background(), &config.Config{}, nil) {
				if f.Check == "api_auth_failure" && strings.Contains(f.Message, "203.0.113.50") {
					got = true
				}
			}
			if got != tc.counted {
				t.Fatalf("api_auth_failure reported = %v, want %v", got, tc.counted)
			}
		})
	}
}
