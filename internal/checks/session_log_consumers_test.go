package checks

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

func TestSessionScanDoesNotTrustDetailMethods(t *testing.T) {
	stamp := time.Now().Format("2006-01-02 15:04:05 -0700")
	line := "[" + stamp + "] info [cpaneld] 198.51.100.5 NEW alice:tok address=198.51.100.5,method=create_session,app=cpaneld,method=handle_form_login\n"
	withMockOS(t, &mockOS{open: openTempLog(t, line)})
	got := CheckCpanelLogins(context.Background(), &config.Config{}, nil)
	if len(got) != 1 || got[0].Check != "cpanel_login" || got[0].SourceIP != "198.51.100.5" {
		t.Fatalf("direct login findings = %+v", got)
	}
}

func TestSessionScanExcludesAPIFromMultiIP(t *testing.T) {
	stamp := time.Now().Format("2006-01-02 15:04:05 -0700")
	for _, suppress := range []bool{false, true} {
		for _, method := range []string{"create_user_session", "create_session", "handle_form_login"} {
			t.Run(fmt.Sprintf("%s/suppress=%v", method, suppress), func(t *testing.T) {
				var log strings.Builder
				for _, ip := range []string{"192.0.2.5", "198.51.100.5", "203.0.113.5"} {
					fmt.Fprintf(&log, "[%s] info [cpaneld] %s NEW alice:tok method=%s\n", stamp, ip, method)
				}
				withMockOS(t, &mockOS{open: openTempLog(t, log.String())})
				cfg := &config.Config{}
				cfg.Suppressions.SuppressCpanelLogin = suppress
				got := CheckCpanelLogins(context.Background(), cfg, nil)
				counts := make(map[string]int)
				for _, f := range got {
					counts[f.Check]++
				}
				wantLogins, wantMulti := 0, 0
				if method == "handle_form_login" {
					wantMulti = 1
					if !suppress {
						wantLogins = 3
					}
				}
				if len(got) != wantLogins+wantMulti || counts["cpanel_login"] != wantLogins || counts["cpanel_multi_ip_login"] != wantMulti {
					t.Fatalf("findings = %+v, want %d logins and %d multi-IP findings", got, wantLogins, wantMulti)
				}
			})
		}
	}
}

func TestSessionShadowCannotTrustMalformedEvidence(t *testing.T) {
	const prefix = "[2026-04-12 10:00:00 +0000] "
	const infra = prefix + "info [whostmgr] 192.0.2.5 PURGE alice:tok password_change\n"
	for name, untrusted := range map[string]string{
		"untimed":          "info [whostmgr] 203.0.113.5 PURGE alice:tok password_change",
		"bad time":         "[bad time] info [whostmgr] 203.0.113.5 PURGE alice:tok password_change",
		"missing session":  prefix + "info [whostmgr] 203.0.113.5 PURGE alice password_change",
		"wrong level":      prefix + "warn [whostmgr] 192.0.2.5 PURGE alice:tok password_change",
		"origin in detail": prefix + "info [cpaneld] 203.0.113.5 PURGE alice:tok password_change [xml-api] 192.0.2.5",
	} {
		t.Run(name, func(t *testing.T) {
			for _, log := range []string{infra + untrusted + "\n", untrusted + "\n" + infra} {
				mockShadowLogs(t, log, "")
				if isInfraShadowChange(&config.Config{InfraIPs: []string{"192.0.2.5"}}, time.Time{}) {
					t.Fatal("untrusted password-change evidence allowed shadow suppression")
				}
			}
		})
	}
}

func TestSessionTokenDenialKeepsLevelAndPrecision(t *testing.T) {
	for _, line := range []string{
		strings.Replace(staleSessionDeniedLine, " info ", " warn ", 1),
		strings.Replace(staleSessionDeniedLine, "10:00:05", "10:00:05.5", 1),
		strings.Replace(staleSessionDeniedLine, "[cpaneld]", "[whostmgr]", 1),
	} {
		if d, ok := ParseSessionTokenDenial(line); ok {
			t.Fatalf("invalid denial accepted: %+v", d)
		}
	}
}
