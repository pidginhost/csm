package checks

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// Findings about a client address carry it in SourceIP: consumers such as
// the attack database never read addresses out of message text.
func TestAuthFindingsCarryTheirClientAddress(t *testing.T) {
	forceCPanelPlatform(t)

	t.Run("webmail_bruteforce", func(t *testing.T) {
		var log strings.Builder
		for i := 0; i < webmailThreshold; i++ {
			fmt.Fprintf(&log, `203.0.113.40 - - [08/Sep/2026:10:00:%02d +0000] "POST /login/?login_only=1 HTTP/1.1" 401 0 "-" "-" 2096`+"\n", i)
		}
		withMockOS(t, &mockOS{open: openTempLog(t, log.String())})
		assertSourceIP(t, CheckWebmailLogins(context.Background(), &config.Config{}, nil), "webmail_bruteforce", "203.0.113.40")
	})

	t.Run("api_auth_failure", func(t *testing.T) {
		staleSessionLogs(t, staleSessionBurst("203.0.113.41"), []string{staleSessionEarlierLine})
		assertSourceIP(t, CheckAPIAuthFailures(context.Background(), &config.Config{}, nil), "api_auth_failure", "203.0.113.41")
	})

	t.Run("cpanel_login", func(t *testing.T) {
		stamp := time.Now().Format("2006-01-02 15:04:05 -0700")
		log := "[" + stamp + "] info [cpaneld] 203.0.113.42 NEW alice:token address=203.0.113.42,app=cpaneld,method=handle_form_login\n"
		withMockOS(t, &mockOS{open: openTempLog(t, log)})
		assertSourceIP(t, CheckCpanelLogins(context.Background(), &config.Config{}, newTestStore(t)), "cpanel_login", "203.0.113.42")
	})
}

func assertSourceIP(t *testing.T, findings []alert.Finding, check, ip string) {
	t.Helper()
	for _, f := range findings {
		if f.Check == check {
			if f.SourceIP != ip {
				t.Fatalf("%s SourceIP = %q, want %q (%s)", check, f.SourceIP, ip, f.Message)
			}
			return
		}
	}
	t.Fatalf("no %s finding in %+v", check, findings)
}
