package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func TestCpanelWHMAlertsIgnoreForgedUserRecords(t *testing.T) {
	for _, stamp := range []string{"11/09/2026:12:00:00 -0000", "bad -0000", "09/Nov/2026:12:00:00 +0000"} {
		for _, user := range []string{
			`x"`,
			`x [bad] "y`,
			`x [11/10/2026:09:00:00 -0000] "GET /index.html HTTP/1.1" 200 0 "-" "-" "-" "-" 2083`,
		} {
			for _, suffix := range []string{`"-" "agent" "-" "-" 2087`, `"-" "agent" "example.com:2086"`} {
				for request, check := range map[string]string{
					"GET /scripts2/listaccts":   "whm_unauth_scripts_realtime",
					"POST /login/?login_only=1": "whm_login_realtime",
				} {
					line := `192.0.2.66 - ` + user + ` [` + stamp + `] "` + request + ` HTTP/1.1" 401 0 ` + suffix
					got := parseAccessLogLineEnhanced(line, &config.Config{})
					if len(got) != 1 || got[0].Check != check || got[0].SourceIP != "192.0.2.66" {
						t.Errorf("%q: got %+v, want one %s", line, got, check)
					}
				}
			}
		}
	}
}
