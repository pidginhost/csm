package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func TestCpanelPurgeSuppressionRequiresUnambiguous401(t *testing.T) {
	old := purgeTracker
	resetPurgeTrackerState()
	t.Cleanup(func() { purgeTracker = old })
	purgeTracker.recordLogin("192.0.2.66", "alice")
	purgeTracker.recordPurge("alice")
	for _, tc := range []struct {
		name, status, agent string
		want                int
	}{
		{"definite 401", "401", "agent", 0},
		{"definite 403", "403", "agent", 1},
		{"ambiguous 401", "401", `agent" 200 0 "`, 1},
		{"ambiguous 403", "403", `agent" 401 0 "`, 1},
		{"ambiguous request", "401", `agent [bad] "GET / HTTP/1.1`, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, target := range []string{
				"/execute/Themes/list", "/ex%65cute/Themes/list", "/xml-api/cpanel",
				"/cpsess0123456789/scripts2/reloadbind_local", "/websocket/MysqlDump",
			} {
				line := `192.0.2.66 - alice [11/09/2026:12:00:00 -0000] "GET ` + target + ` HTTP/1.1" ` +
					tc.status + ` 0 "-" "` + tc.agent + `" "-" "-" 2083`
				got := parseAccessLogLineEnhanced(line, &config.Config{})
				if len(got) != tc.want || len(got) == 1 && (got[0].Check != "api_auth_failure_realtime" || got[0].SourceIP != "192.0.2.66") {
					t.Fatalf("target %s: got %+v, want %d API failures", target, got, tc.want)
				}
			}
		})
	}
}

func TestCpanelFileManagerSkipRequiresUnambiguousStatus(t *testing.T) {
	old := purgeTracker
	resetPurgeTrackerState()
	t.Cleanup(func() { purgeTracker = old })
	for _, tc := range []struct {
		name, agent string
		wantUpload  int
	}{
		{"definite rejection", "agent", 0},
		{"second status", `agent" 200 0 "`, 1},
		{"second request", `agent [bad] "GET / HTTP/1.1`, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line := `192.0.2.66 - alice [11/09/2026:12:00:00 -0000] "POST /execute/Fileman/upload_files HTTP/1.1" 401 0 "-" "` + tc.agent + `" "-" "-" 2083`
			got := parseAccessLogLineEnhanced(line, &config.Config{})
			api, uploads := 0, 0
			for _, f := range got {
				switch f.Check {
				case "api_auth_failure_realtime":
					api++
				case "cpanel_file_upload_realtime":
					uploads++
				default:
					t.Fatalf("unexpected finding: %+v", f)
				}
			}
			if api != 1 || uploads != tc.wantUpload {
				t.Fatalf("got %d API failures and %d uploads, want 1 and %d", api, uploads, tc.wantUpload)
			}
		})
	}
}
