package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// cpsrvd writes request, referer and user agent text without escaping
// quotes. A raw quote anywhere in client text must not hide a WHM request:
// the request is read from the left of its field and the port from the end
// of the line.
func TestParseAccessLogLineEnhanced_RawQuotesKeepWHMRequests(t *testing.T) {
	const stamp = `[11/09/2026:12:00:00 -0000]`
	for _, tc := range []struct{ name, line, check string }{
		{"query quote", `192.0.2.81 - - ` + stamp + ` "GET /scripts2/createacct?x="y HTTP/1.1" 401 0 "-" "curl/8.4.0" "-" "-" 2087`, "whm_unauth_scripts_realtime"},
		{"query quotes", `192.0.2.82 - - ` + stamp + ` "GET /scripts2/listaccts?q={"a":1}&b"c" HTTP/1.1" 401 0 "-" "curl/8.4.0" "-" "-" 2087`, "whm_unauth_scripts_realtime"},
		{"agent quote", `192.0.2.83 - - ` + stamp + ` "GET /scripts2/listaccts HTTP/1.1" 401 0 "-" "curl "8" x" "-" "-" 2087`, "whm_unauth_scripts_realtime"},
		{"referer quote", `192.0.2.84 - - ` + stamp + ` "GET /scripts2/listaccts HTTP/1.1" 401 0 "https://host.example.com/"a" "curl/8.4.0" "-" "-" 2087`, "whm_unauth_scripts_realtime"},
		{"agent fake record", `192.0.2.85 - - ` + stamp + ` "GET /scripts2/listaccts HTTP/1.1" 401 0 "-" "x" ` + stamp + ` "GET / HTTP/1.1" 200 0 "-" "-" "-" "-" 2083" "-" "-" 2087`, "whm_unauth_scripts_realtime"},
		{"login query quote", `192.0.2.86 - - ` + stamp + ` "POST /login/?login_only=1&x="y HTTP/1.1" 200 0 "-" "Mozilla/5.0" "-" "-" 2087`, "whm_login_realtime"},
		{"login agent quote", `192.0.2.87 - - ` + stamp + ` "POST /login/?login_only=1 HTTP/1.1" 200 0 "-" "Mozilla "5.0"" "-" "host 2087" 2087`, "whm_login_realtime"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := parseAccessLogLineEnhanced(tc.line, &config.Config{})
			found := false
			for _, f := range got {
				found = found || f.Check == tc.check
			}
			if !found {
				t.Fatalf("findings = %+v, want %s", got, tc.check)
			}
		})
	}
	// Client text cannot supply the served port: these lines were served on
	// 2083, whatever their request, referer or user agent claim.
	for _, line := range []string{
		`192.0.2.88 - - ` + stamp + ` "GET /scripts2/listaccts HTTP/1.1" 401 0 "-" "x" "-" "-" 2087" "-" "-" 2083`,
		`192.0.2.89 - - ` + stamp + ` "GET /scripts2/listaccts?p=" 2087 HTTP/1.1" 401 0 "-" "-" "-" "-" 2083`,
	} {
		for _, f := range parseAccessLogLineEnhanced(line, &config.Config{}) {
			if f.Check == "whm_unauth_scripts_realtime" || f.Check == "whm_login_realtime" {
				t.Errorf("%q: client text supplied the WHM port: %+v", line, f)
			}
		}
	}
}
