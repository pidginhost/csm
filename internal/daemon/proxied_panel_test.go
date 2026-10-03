package daemon

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
)

// cPanel proxy subdomains reach the panel through the web server, which logs
// them under /___proxy_subdomain_<service>/ (LiteSpeed) or as the proxy vhost
// (cPanel's trailing vhost field). The panel producers own those requests;
// the web-attack handler skips them.
func TestAccessLogSkipsProxiedPanelRequests(t *testing.T) {
	resetAccessLogTrackerState()
	t.Cleanup(resetAccessLogTrackerState)
	cfg := &config.Config{}
	for name, line := range map[string]string{
		"proxy path":             makeAccessLogLine("203.0.113.81", "POST", "/___proxy_subdomain_cpanel/3rdparty/phpMyAdmin/index.php"),
		"proxy vhost":            makeAccessLogLine("203.0.113.82", "POST", "/phpmyadmin/index.php") + ` "proxy-subdomains-vhost.localhost"`,
		"vhost before extension": makeAccessLogLine("203.0.113.82", "POST", "/phpmyadmin/index.php") + ` "proxy-subdomains-vhost.localhost" "192.0.2.1"`,
	} {
		for i := 0; i < accessLogWPLoginThreshold; i++ {
			if got := parseAccessLogBruteForce(line, cfg); len(got) != 0 {
				t.Fatalf("%s: proxied request gave %+v", name, got)
			}
		}
	}
	for name, line := range map[string]string{
		"direct":        makeAccessLogLine("203.0.113.83", "POST", "/phpmyadmin/index.php"),
		"nested marker": makeAccessLogLine("203.0.113.83", "POST", "/archive/___proxy_subdomain_text/phpmyadmin/index.php"),
		"query marker":  makeAccessLogLine("203.0.113.83", "POST", "/phpmyadmin/index.php?next=/___proxy_subdomain_text/"),
		"UA marker":     strings.Replace(makeAccessLogLine("203.0.113.83", "POST", "/phpmyadmin/index.php"), `"Mozilla"`, `"proxy-subdomains-vhost.localhost"`, 1),
		"quoted UA":     strings.Replace(makeAccessLogLine("203.0.113.83", "POST", "/phpmyadmin/index.php"), `"Mozilla"`, `"agent \"proxy-subdomains-vhost.localhost\""`, 1),
	} {
		resetAccessLogTrackerState()
		var findings []alert.Finding
		for i := 0; i < accessLogWPLoginThreshold; i++ {
			findings = append(findings, parseAccessLogBruteForce(line, cfg)...)
		}
		if len(findings) != 1 || findings[0].Check != "admin_panel_bruteforce" {
			t.Fatalf("%s: findings %+v, want one direct admin-panel finding", name, findings)
		}
	}
}

// A client can put the proxy prefix in front of a path the site serves; the
// handler still counts it, because only the normalized path decides.
func TestAccessLogCountsEscapedProxyPaths(t *testing.T) {
	resetAccessLogTrackerState()
	t.Cleanup(resetAccessLogTrackerState)
	cfg := &config.Config{}
	var fired bool
	for i := 0; i < accessLogWPLoginThreshold; i++ {
		line := makeAccessLogLine("203.0.113.87", "POST", "/___proxy_subdomain_cpanel/../phpmyadmin/index.php")
		fired = fired || len(parseAccessLogBruteForce(line, cfg)) > 0
	}
	if !fired {
		t.Fatal("a phpMyAdmin brute force behind an escaped proxy prefix was skipped")
	}
}

// One proxied panel session seen by the web server log and by the panel log
// stays one family of evidence, so it never corroborates itself into C3.
func TestProxiedPanelSessionStaysOneFamily(t *testing.T) {
	resetAccessLogTrackerState()
	t.Cleanup(resetAccessLogTrackerState)
	cfg := &config.Config{}
	ip := "203.0.113.84"
	var findings []alert.Finding
	for i := 0; i < accessLogWPLoginThreshold; i++ {
		findings = append(findings, parseAccessLogBruteForce(makeAccessLogLine(ip, "POST", "/___proxy_subdomain_cpanel/3rdparty/phpMyAdmin/index.php"), cfg)...)
		findings = append(findings, parseAccessLogLineEnhanced(fmt.Sprintf(`%s - proxy [10/02/2026:12:00:%02d -0000] "POST /cpsess%d/json-api/cpanel HTTP/1.1" 401 0 "-" "Mozilla" "-" 2083`, ip, i, i), cfg)...)
	}
	reg, err := admission.NewRegistry(checks.AdmissionPolicy)
	if err != nil {
		t.Fatal(err)
	}
	producers := map[string]*admission.Producer{}
	for _, entry := range checks.ProducerTable() {
		if entry.Spec.ID != checks.ProducerAccessLog && entry.Spec.ID != checks.ProducerCpanelAccessLog {
			continue
		}
		prod, regErr := reg.Register(entry.Spec)
		if regErr != nil {
			t.Fatal(regErr)
		}
		for _, check := range entry.Spec.Checks {
			producers[check] = prod
		}
	}
	target, err := admission.CanonicalAddress(ip, admission.Caps{IPv6: true})
	if err != nil {
		t.Fatal(err)
	}
	observed := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	var roots []admission.Evidence
	for i, f := range findings {
		prod, ok := producers[f.Check]
		if !ok {
			continue
		}
		sev := admission.SeverityHigh
		if f.Severity == alert.Critical {
			sev = admission.SeverityCritical
		}
		e, mintErr := prod.Mint(admission.EvidenceInput{
			Check: f.Check, FindingID: "0123456789abcdef", Severity: sev,
			Observation: admission.ObservationRef{Stream: "fixture-" + f.Check, Cursor: fmt.Sprint(i), Version: 1},
			ObservedAt:  observed, Parser: admission.ParserRef{Name: "fixture", Version: 1}, Target: target,
		})
		if mintErr != nil {
			t.Fatalf("mint %s: %v", f.Check, mintErr)
		}
		roots = append(roots, e)
	}
	if len(roots) == 0 {
		t.Fatal("no evidence minted; the panel log should give at least one root")
	}
	a, err := admission.Assess(target, roots, observed.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if a.Corroborated || a.Tier.Class != admission.ClassC2 {
		t.Fatalf("assessment %+v, want one family at C2", a)
	}
}
