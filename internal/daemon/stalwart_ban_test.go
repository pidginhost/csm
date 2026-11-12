package daemon

import (
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
)

func TestStalwartAuthBanOnSMTPBlocks(t *testing.T) {
	cfg := stalwartBruteConfig()
	cfg.AutoResponse.Enabled, cfg.AutoResponse.BlockIPs = true, true
	d, _ := newStalwartAuthDaemon(t, cfg)
	got := feedStalwart(d, stalwartLine(stalwartTestStart, "security.authentication-ban", 25, "203.0.113.30", ""))
	if len(got) != 1 {
		t.Fatalf("findings = %+v, want one", got)
	}
	f := got[0]
	if f.Check != "stalwart_ban" || f.SourceIP != "203.0.113.30" || f.Attribution != admission.AttributionPeer || f.Severity != alert.Critical {
		t.Fatalf("finding = %+v", f)
	}
	if !strings.Contains(f.Message, "repeated failed logins") || !strings.Contains(f.Message, "port 25") {
		t.Fatalf("message = %q", f.Message)
	}
	if !checks.BlockableFinding(cfg, f) {
		t.Fatal("a Stalwart ban on a mail listener must be blockable")
	}
}

func TestStalwartAbuseBanOnIMAPBlocks(t *testing.T) {
	d, _ := newStalwartAuthDaemon(t, stalwartBruteConfig())
	got := feedStalwart(d, stalwartLine(stalwartTestStart, "security.abuse-ban", 993, "203.0.113.31", ""))
	if len(got) != 1 || got[0].Check != "stalwart_ban" || !strings.Contains(got[0].Message, "abuse") {
		t.Fatalf("findings = %+v", got)
	}
}

func TestStalwartScanBanNamesReason(t *testing.T) {
	d, _ := newStalwartAuthDaemon(t, stalwartBruteConfig())
	line := `2026-11-11T10:01:00Z INFO IP banned for port scanning (security.scan-ban) listenerId = "smtp", localPort = 25, remotePort = 41000, remoteIp = 198.51.100.20, reason = "scan"`
	got := feedStalwart(d, line)
	if len(got) != 1 || got[0].SourceIP != "198.51.100.20" || !strings.Contains(got[0].Message, "scanning: scan") {
		t.Fatalf("findings = %+v", got)
	}
}

func TestStalwartBanOnHTTPOrUnknownPortNotFollowed(t *testing.T) {
	d, _ := newStalwartAuthDaemon(t, stalwartBruteConfig())
	for _, port := range []int{8080, 443, 2525} {
		for _, event := range []string{"security.authentication-ban", "security.abuse-ban", "security.scan-ban"} {
			if got := feedStalwart(d, stalwartLine(stalwartTestStart, event, port, "203.0.113.32", "")); len(got) != 0 {
				t.Fatalf("%s on port %d: findings = %+v, want none", event, port, got)
			}
		}
	}
}

func TestStalwartLoiterAndIPBlockedIgnored(t *testing.T) {
	d, _ := newStalwartAuthDaemon(t, stalwartBruteConfig())
	for _, event := range []string{"security.loiter-ban", "security.ip-blocked"} {
		if got := feedStalwart(d, stalwartLine(stalwartTestStart, event, 25, "203.0.113.33", "")); len(got) != 0 {
			t.Fatalf("%s: findings = %+v, want none", event, got)
		}
	}
}

func TestStalwartBanSkipsInfraAndPrivate(t *testing.T) {
	cfg := stalwartBruteConfig()
	cfg.InfraIPs = []string{"192.0.2.10"}
	d, _ := newStalwartAuthDaemon(t, cfg)
	for _, ip := range []string{"10.0.0.5", "192.0.2.10", "127.0.0.1"} {
		if got := feedStalwart(d, stalwartLine(stalwartTestStart, "security.authentication-ban", 587, ip, "")); len(got) != 0 {
			t.Fatalf("%s: findings = %+v, want none", ip, got)
		}
	}
}

// An address a customer logged in from recently, such as an office network
// where one device holds a stale password, is reported but never blocked:
// following Stalwart's ban must not bypass the protection CSM's own trackers
// give established sources.
func TestStalwartBanOfKnownCustomerAlertsOnly(t *testing.T) {
	cfg := stalwartBruteConfig()
	cfg.AutoResponse.Enabled, cfg.AutoResponse.BlockIPs = true, true
	d, _ := newStalwartAuthDaemon(t, cfg)
	d.knownCustomers.Note("203.0.113.34", knownCustomerIMAP, "user@example.com", time.Now(), serviceLog)
	got := feedStalwart(d, stalwartLine(stalwartTestStart, "security.authentication-ban", 993, "203.0.113.34", ""))
	if len(got) != 1 || got[0].Check != "stalwart_ban" || got[0].Severity != alert.High {
		t.Fatalf("findings = %+v, want one High stalwart_ban", got)
	}
	if checks.BlockableFinding(cfg, got[0]) {
		t.Fatal("a known customer's address must not be blocked")
	}
	if !strings.Contains(got[0].Message, "not blocked") {
		t.Fatalf("message = %q, want it to say the address is not blocked", got[0].Message)
	}
}
