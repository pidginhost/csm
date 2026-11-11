package checks

import (
	"context"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// cpsrvd does not escape quotes in the request, referer or user agent. The
// scans must still see every request the whole-line matching used to see.
func TestCpanelScansSeeRequestsWithRawQuotes(t *testing.T) {
	const stamp = `[11/09/2026:12:00:00 -0000]`
	repeat := func(line string, n int) []string {
		lines := make([]string, n)
		for i := range lines {
			lines[i] = line
		}
		return lines
	}
	for _, tc := range []struct {
		name, check string
		lines       []string
	}{
		{"whm query quote", "whm_account_action",
			[]string{`192.0.2.91 - - ` + stamp + ` "GET /scripts2/createacct?x="y HTTP/1.1" 401 0 "-" "curl/8.4.0" "-" "-" 2087`}},
		{"whm agent quote", "whm_account_action",
			[]string{`192.0.2.92 - - ` + stamp + ` "GET /scripts2/createacct HTTP/1.1" 200 0 "-" "curl "8" x" "-" "-" 2087`}},
		{"whm referer quote", "whm_password_change",
			[]string{`192.0.2.93 - - ` + stamp + ` "POST /json-api/passwd HTTP/1.1" 200 0 "https://host.example.com/"a" "curl/8.4.0" "-" "-" 2087`}},
		{"webmail agent quote", "webmail_bruteforce",
			repeat(`192.0.2.94 - - `+stamp+` "POST /login/?login_only=1 HTTP/1.1" 401 0 "-" "Mozilla "5.0"" "-" "-" 2096`, webmailThreshold)},
		{"api agent quote", "api_auth_failure",
			repeat(`192.0.2.95 - - `+stamp+` "GET /execute/Themes/list HTTP/1.1" 401 0 "-" "curl "8" x" "-" "-" 2083`, apiFailThreshold)},
		{"file manager query quote", "cpanel_file_upload",
			[]string{`192.0.2.96 - alice ` + stamp + ` "POST /execute/Fileman/upload_files?x="y HTTP/1.1" 200 0 "-" "Mozilla/5.0" "-" "-" 2083`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			forceCPanelPlatform(t)
			cpanelScanLog(t, tc.lines)
			cfg := &config.Config{}
			var all []string
			for _, run := range []func() []string{
				func() []string { return checksOf(CheckWHMAccess(context.Background(), cfg, nil)) },
				func() []string { return checksOf(CheckWebmailLogins(context.Background(), cfg, nil)) },
				func() []string { return checksOf(CheckAPIAuthFailures(context.Background(), cfg, nil)) },
				func() []string { return checksOf(CheckCpanelFileManager(context.Background(), cfg, nil)) },
			} {
				all = append(all, run()...)
			}
			if !strings.Contains(" "+strings.Join(all, " ")+" ", " "+tc.check+" ") {
				t.Fatalf("checks = %v, want %s", all, tc.check)
			}
		})
	}
}

func checksOf(findings []alert.Finding) []string {
	names := make([]string, len(findings))
	for i, f := range findings {
		names[i] = f.Check
	}
	return names
}
