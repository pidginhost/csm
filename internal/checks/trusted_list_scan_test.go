package checks

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// A trusted proxy's address stands for every visitor behind it: the
// ModSecurity audit scan never reports it as an attacker, as the realtime
// handler never escalates it, whichever key lists it.
func TestModSecAuditScanNeverReportsATrustedProxy(t *testing.T) {
	content := strings.Repeat(modsecIndexLine("example.com", "203.0.113.50", "GET /x HTTP/1.1", "probe", 403)+"\n", 25)
	for name, trust := range map[string]func(*config.Config){
		"web_server": func(c *config.Config) { c.WebServer.TrustedProxies = []string{"203.0.113.48/29"} },
		"challenge":  func(c *config.Config) { c.Challenge.TrustedProxies = []string{"203.0.113.50"} },
	} {
		t.Run(name, func(t *testing.T) {
			modsecAuditReader.Lock()
			modsecAuditReader.path = ""
			modsecAuditReader.Unlock()
			setupSerialAuditLog(t, content)
			cfg := &config.Config{}
			trust(cfg)
			for _, f := range CheckModSecAuditLog(context.Background(), cfg, nil) {
				if f.Check == "waf_attack_blocked" {
					t.Fatalf("trusted proxy reported: %+v", f)
				}
			}
		})
	}
}

// cpsrvd names its connecting peer, so a trusted proxy in front of it is
// never read as that peer: the legacy finding stays and mints nothing.
func TestCpanelScansNeverVouchForATrustedProxy(t *testing.T) {
	cfg := &config.Config{}
	cfg.WebServer.TrustedProxies = []string{"203.0.113.40", "203.0.113.41"}
	t.Run("webmail_bruteforce", func(t *testing.T) {
		var access []string
		for i := 0; i < webmailThreshold; i++ {
			access = append(access, fmt.Sprintf(`203.0.113.40 - - [%s -0000] "POST /login/?login_only=1 HTTP/1.1" 401 0 "-" "-" 2096`, cpanelUTCStamp(time.Now().Add(-time.Minute))))
		}
		cpanelScanLog(t, access)
		f := oneScanFinding(t, CheckWebmailLogins(context.Background(), cfg, nil), "webmail_bruteforce")
		wantNoPeerKind(t, f, "203.0.113.40")
	})
	t.Run("api_auth_failure", func(t *testing.T) {
		var access []string
		for i := 0; i < apiFailThreshold; i++ {
			access = append(access, staleSessionAccessLine("203.0.113.41", "-", cpanelUTCStamp(time.Now().Add(-time.Minute)), "/execute/Themes/list", "401"))
		}
		cpanelScanLog(t, access)
		f := oneScanFinding(t, CheckAPIAuthFailures(context.Background(), cfg, nil), "api_auth_failure")
		wantNoPeerKind(t, f, "203.0.113.41")
	})
}

func wantNoPeerKind(t *testing.T, f alert.Finding, ip string) {
	t.Helper()
	if f.SourceIP != ip || f.Attribution != admission.AttributionUnknown {
		t.Fatalf("finding %s read as %s, want the legacy finding for %s with no kind", f.SourceIP, f.Attribution, ip)
	}
	if _, _, err := mintScanFinding(t, f); admission.CauseOf(err) != admission.CauseKindNotAllowed {
		t.Fatalf("mint: %v, want the kind cause", err)
	}
}
