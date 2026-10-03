package checks

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// The domlog scan skips proxied panel requests in the central log, so a
// heavy cPanel or webmail session never counts toward web floods or brute
// force; other requests from the same address still count.
func TestDomlogScanSkipsProxiedPanelRequests(t *testing.T) {
	stats := newDomlogStatsAt(time.Date(2026, 10, 2, 12, 0, 30, 0, time.UTC))
	line := func(path, extra string) string {
		return fmt.Sprintf(`192.0.2.85 - - [02/Oct/2026:12:00:00 +0000] "POST %s HTTP/1.1" 200 10 "-" "Mozilla"%s`, path, extra)
	}
	for _, l := range []string{
		line("/___proxy_subdomain_webmail/wp-login.php", ""),
	} {
		rec, ok := parseAccessLogRecord(l)
		if !ok {
			t.Fatalf("unparsable fixture %q", l)
		}
		rec.Central = true
		stats.scan(rec, &config.Config{}, nopBotClassifier{})
	}
	if stats.httpReqs["192.0.2.85"] != 0 || stats.wpLogin["192.0.2.85"] != 0 {
		t.Fatalf("proxied requests counted: %d requests, %d logins", stats.httpReqs["192.0.2.85"], stats.wpLogin["192.0.2.85"])
	}
	rec, ok := parseAccessLogRecord(line("/wp-login.php", ""))
	if !ok {
		t.Fatal("unparsable direct fixture")
	}
	stats.scan(rec, &config.Config{}, nopBotClassifier{})
	if stats.httpReqs["192.0.2.85"] != 1 || stats.wpLogin["192.0.2.85"] != 1 {
		t.Fatalf("direct request counted %d requests, %d logins, want 1 each", stats.httpReqs["192.0.2.85"], stats.wpLogin["192.0.2.85"])
	}
}

// No log field marks a request as panel traffic: a trailing quoted field can
// be a client header, so every one of these lines is a website login.
func TestProxiedPanelVhostUsesOnlyLogExtensions(t *testing.T) {
	base := `192.0.2.85 - - [02/Oct/2026:12:00:00 +0000] "POST /wp-login.php HTTP/1.1" 200 10 "-" "Mozilla"`
	for _, line := range []string{
		base + ` "proxy-subdomains-vhost.localhost"`,
		base + ` "proxy-subdomains-vhost.localhost" "192.0.2.1"`,
		base,
		strings.Replace(base, `"Mozilla"`, `"proxy-subdomains-vhost.localhost"`, 1),
		strings.Replace(base, `"-"`, `"proxy-subdomains-vhost.localhost"`, 1),
		strings.Replace(base, `"Mozilla"`, `"agent \"proxy-subdomains-vhost.localhost\""`, 1),
		base + ` "site.example"`,
	} {
		requireWebsiteLogin(t, line)
	}
	for _, uri := range []string{"/archive/___proxy_subdomain_text/", "/wp-login.php?next=/___proxy_subdomain_text/"} {
		if IsProxiedPanelRequest(uri, true) {
			t.Errorf("ordinary website URI classified as proxy: %q", uri)
		}
	}
}

// requireWebsiteLogin scans line from the central log and from a per-site log
// and requires one counted login from 192.0.2.85 each time.
func requireWebsiteLogin(t *testing.T, line string) {
	t.Helper()
	for _, central := range []bool{true, false} {
		rec, ok := parseAccessLogRecord(line)
		if !ok {
			t.Fatalf("fixture no longer parses: %q", line)
		}
		rec.Central = central
		stats := newDomlogStatsAt(time.Date(2026, 10, 2, 12, 0, 30, 0, time.UTC))
		stats.scan(rec, &config.Config{}, nopBotClassifier{})
		if stats.wpLogin["192.0.2.85"] != 1 {
			t.Errorf("central=%v: website login suppressed by a log field: %q", central, line)
		}
	}
}

func TestProxiedPanelVhostKeepsFieldPositions(t *testing.T) {
	base := `192.0.2.85 - - [02/Oct/2026:12:00:00 +0000] "POST /wp-login.php HTTP/1.1" 200 10 "-" "Mozilla"`
	for name, line := range map[string]string{
		"later extension": base + ` "site.example" "proxy-subdomains-vhost.localhost"`,
		"quoted login":    strings.Replace(strings.Replace(base, ` - - [`, ` - user\"name\" [`, 1), `"Mozilla"`, `"proxy-subdomains-vhost.localhost"`, 1),
		"malformed UA":    strings.Replace(base, `"Mozilla"`, `"Mozilla"junk "proxy-subdomains-vhost.localhost"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			requireWebsiteLogin(t, line)
		})
	}
}

func TestProxiedPanelVhostHandlesRemoteUsers(t *testing.T) {
	for _, user := range []string{`a b`, `""`, `a[1]`, `x] [02/Oct/2026`, `user\"name`} {
		t.Run(user, func(t *testing.T) {
			base := `192.0.2.85 - ` + user + ` [02/Oct/2026:12:00:00 +0000] "POST /wp-login.php HTTP/1.1" 200 10 "-" "Mozilla"`
			for _, line := range []string{
				base + ` "proxy-subdomains-vhost.localhost"`,
				strings.Replace(base, `"Mozilla"`, `"proxy-subdomains-vhost.localhost"`, 1),
			} {
				requireWebsiteLogin(t, line)
			}
		})
	}
}

func TestDomlogProxyClassificationUsesTheFullTarget(t *testing.T) {
	for _, uri := range []string{
		"/___proxy_subdomain_cpanel/" + strings.Repeat("a", 4100) + "/../../wp-login.php",
		"/___proxy_subdomain_cpanel/" + strings.Repeat("a", 4100) + "/%2e%2e/%2e%2e/wp-login.php",
	} {
		line := fmt.Sprintf(`192.0.2.85 - - [02/Oct/2026:12:00:00 +0000] "POST %s HTTP/1.1" 200 10 "-" "Mozilla"`, uri)
		rec, ok := parseAccessLogRecord(line)
		if !ok {
			t.Fatal("fixture no longer parses")
		}
		rec.Central = true
		stats := newDomlogStatsAt(time.Date(2026, 10, 2, 12, 0, 30, 0, time.UTC))
		stats.scan(rec, &config.Config{}, nopBotClassifier{})
		if stats.httpReqs["192.0.2.85"] != 1 {
			t.Fatal("website request was suppressed after target truncation")
		}
	}
}

// A client chooses the logged path. It names a proxied request only in the
// central log and only if it still starts with the prefix once decoded and
// cleaned the way the server routes it.
func TestProxiedPanelPathCountsOnlyInTheCentralLog(t *testing.T) {
	for uri, want := range map[string]bool{
		"/___proxy_subdomain_cpanel/3rdparty/phpMyAdmin/index.php": true,
		"/___proxy_subdomain_webmail/?_task=mail":                  true,
		"/___proxy_subdomain_webmail/?_task=mail&q=%zz":            true,
		"/___proxy_subdomain_webmail/?next=/../../x":               true,
		"/___proxy_subdomain_cpanel/../wp-login.php":               false,
		"/___proxy_subdomain_cpanel/%2e%2e/wp-login.php":           false,
		"/___proxy_subdomain_cpanel/%zz":                           false,
	} {
		if got := IsProxiedPanelRequest(uri, true); got != want {
			t.Errorf("central %q = %v, want %v", uri, got, want)
		}
		if IsProxiedPanelRequest(uri, false) {
			t.Errorf("domlog %q classified as proxy", uri)
		}
	}
	for _, central := range []bool{true, false} {
		if IsProxiedPanelRequest("/wp-login.php", central) {
			t.Errorf("central=%v: a website path classified as proxy", central)
		}
	}
	stats := newDomlogStatsAt(time.Date(2026, 10, 2, 12, 0, 30, 0, time.UTC))
	rec, ok := parseAccessLogRecord(`192.0.2.86 - - [02/Oct/2026:12:00:00 +0000] "POST /___proxy_subdomain_cpanel/wp-login.php HTTP/1.1" 200 10 "-" "Mozilla"`)
	if !ok {
		t.Fatal("unparsable domlog fixture")
	}
	rec.Domain = "shop.example"
	stats.scan(rec, &config.Config{}, nopBotClassifier{})
	if stats.wpLogin["192.0.2.86"] != 1 {
		t.Fatalf("domlog request with a client-chosen proxy path counted %d logins, want 1", stats.wpLogin["192.0.2.86"])
	}
}

// The periodic web detector also cannot corroborate a panel root with itself.
func TestDomlogProxiedPanelSessionStaysOneFamily(t *testing.T) {
	{
		at := time.Unix(1_700_000_000, 0)
		stats := newDomlogStatsAt(at)
		cfg := &config.Config{}
		cfg.Thresholds.HTTPFloodThreshold = 2
		line := `192.0.2.85 - - [14/Nov/2023:22:13:20 +0000] "POST /___proxy_subdomain_cpanel/wp-login.php HTTP/1.1" 401 10 "-" "Mozilla"`
		for i := 0; i < wpLoginThreshold; i++ {
			rec, ok := parseAccessLogRecord(line)
			if !ok {
				t.Fatal("unparsable periodic fixture")
			}
			rec.Central = true
			stats.scan(rec, cfg, nopBotClassifier{})
		}
		findings := append(stats.emit(cfg), alert.Finding{Check: "api_auth_failure_realtime", Severity: alert.Critical})
		reg, err := admission.NewRegistry(AdmissionPolicy)
		if err != nil {
			t.Fatal(err)
		}
		producers := make(map[string]*admission.Producer)
		for _, entry := range ProducerTable() {
			prod, registerErr := reg.Register(entry.Spec)
			if registerErr != nil {
				t.Fatal(registerErr)
			}
			for _, check := range entry.Spec.Checks {
				producers[check] = prod
			}
		}
		target, err := admission.CanonicalAddress("192.0.2.85", admission.Caps{IPv6: true})
		if err != nil {
			t.Fatal(err)
		}
		var roots []admission.Evidence
		for i, finding := range findings {
			prod := producers[finding.Check]
			if prod == nil {
				t.Fatalf("unregistered fixture check %q", finding.Check)
			}
			sev := admission.SeverityHigh
			if finding.Severity == alert.Critical {
				sev = admission.SeverityCritical
			}
			root, mintErr := prod.Mint(admission.EvidenceInput{
				Check: finding.Check, FindingID: "0123456789abcdef", Severity: sev,
				Observation: admission.ObservationRef{Stream: "fixture-" + finding.Check, Cursor: fmt.Sprint(i), Version: 1},
				ObservedAt:  at, Parser: admission.ParserRef{Name: "fixture", Version: 1}, Target: target,
			})
			if mintErr != nil {
				t.Fatal(mintErr)
			}
			roots = append(roots, root)
		}
		assessment, err := admission.Assess(target, roots, at.Add(time.Minute))
		if err != nil || len(roots) != 1 || assessment.Corroborated || assessment.Tier.Class != admission.ClassC2 {
			t.Fatalf("assessment %+v roots %d error %v, want the panel root alone at C2", assessment, len(roots), err)
		}
	}
}
