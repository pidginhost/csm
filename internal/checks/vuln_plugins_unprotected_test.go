package checks

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/store"
)

// vulnFinding is the shape evaluatePluginVulns produces, reduced to the
// fields the correlation reads.
func vulnFinding(domain, account string, sev alert.Severity) alert.Finding {
	return alert.Finding{
		Severity: sev,
		Check:    "vulnerable_plugins",
		Message:  "Known-vulnerable plugin ultimate-member 2.4.1 (CVE-2023-3460) on " + domain,
		Details:  "privesc (CVE-2023-3460). Installed ultimate-member 2.4.1 is active; fixed in 2.6.7.",
		Domain:   domain,
		TenantID: account,
	}
}

// The incident shape: ModSecurity switched off account-wide, so the CVE's
// shipped virtual patch never executes for any domain the account owns.
func TestAnnotateUnprotected_AccountWideModsecOff(t *testing.T) {
	cov := vpCoverage{
		engineMode: "on",
		disabled: []modsecDisabledScope{{
			User:   "acme",
			Source: "/etc/apache2/conf.d/userdata/std/2_4/acme/modsec.conf",
		}},
	}

	got := annotateUnprotected([]alert.Finding{vulnFinding("shop.example", "acme", alert.Critical)}, cov)

	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}
	if !strings.Contains(got[0].Message, "unprotected") {
		t.Errorf("message must say the finding is unprotected; got %q", got[0].Message)
	}
	if !strings.Contains(got[0].Message, "account acme") {
		t.Errorf("message must name the disabled account scope; got %q", got[0].Message)
	}
	if !strings.Contains(got[0].Details, "/etc/apache2/conf.d/userdata/std/2_4/acme/modsec.conf") {
		t.Errorf("details must name the source that disabled filtering; got:\n%s", got[0].Details)
	}
}

// The alias lesson: the disabled scope names the vhost servername while the
// WordPress inventory knows the site by its addon domain. Both names serve the
// same docroot, so the site is unprotected even though the strings differ.
func TestAnnotateUnprotected_DisabledScopeIsAnAlias(t *testing.T) {
	cov := vpCoverage{
		engineMode: "on",
		disabled: []modsecDisabledScope{{
			User:   "acme",
			Domain: "shop.example.acme-host.example",
			Source: "/var/cpanel/userdata/acme/shop.example.acme-host.example",
		}},
		aliases: vhostAliasSets("" +
			"shop.example: acme==acme==addon==acme.example==/home/acme/public_html/shop==1.2.3.4==1.2.3.4\n" +
			"shop.example.acme-host.example: acme==acme==sub==acme.example==/home/acme/public_html/shop==1.2.3.4==1.2.3.4\n"),
	}

	got := annotateUnprotected([]alert.Finding{vulnFinding("shop.example", "acme", alert.Critical)}, cov)

	if !strings.Contains(got[0].Message, "unprotected") {
		t.Fatalf("alias of a disabled vhost must be reported unprotected; got %q", got[0].Message)
	}
	if !strings.Contains(got[0].Message, "shop.example.acme-host.example") {
		t.Errorf("message must name the vhost that carries the disabled flag; got %q", got[0].Message)
	}
	if !strings.Contains(got[0].Details, "alias") {
		t.Errorf("details must explain the alias relationship; got:\n%s", got[0].Details)
	}
}

// A vulnerability CSM grades High becomes Critical once nothing filters it:
// the missing compensating control is what makes it immediately exploitable.
func TestAnnotateUnprotected_EscalatesHighToCritical(t *testing.T) {
	cov := vpCoverage{
		engineMode: "on",
		disabled:   []modsecDisabledScope{{User: "acme", Source: "/src/modsec.conf"}},
	}

	got := annotateUnprotected([]alert.Finding{vulnFinding("shop.example", "acme", alert.High)}, cov)

	if got[0].Severity != alert.Critical {
		t.Errorf("severity = %v, want Critical once the virtual patch is inert", got[0].Severity)
	}
}

// With filtering in place the finding is left exactly as the detector built it.
func TestAnnotateUnprotected_SilentWhenFilteringApplies(t *testing.T) {
	in := vulnFinding("shop.example", "acme", alert.High)
	cov := vpCoverage{engineMode: "on"}

	got := annotateUnprotected([]alert.Finding{in}, cov)

	if got[0].Message != in.Message || got[0].Details != in.Details {
		t.Errorf("protected finding must not be rewritten; got %q / %q", got[0].Message, got[0].Details)
	}
	if got[0].Severity != alert.High {
		t.Errorf("severity = %v, want the detector's own High", got[0].Severity)
	}
}

// A host-wide engine that is off, or only logging, voids every virtual patch
// for every account regardless of the per-vhost flags.
func TestAnnotateUnprotected_HostWideEngineMode(t *testing.T) {
	for _, tc := range []struct{ mode, want string }{
		{"off", "off host-wide"},
		{"detectiononly", "DetectionOnly"},
	} {
		got := annotateUnprotected(
			[]alert.Finding{vulnFinding("shop.example", "acme", alert.Critical)},
			vpCoverage{engineMode: tc.mode},
		)
		if !strings.Contains(got[0].Message, tc.want) {
			t.Errorf("engine %q: message = %q, want it to mention %q", tc.mode, got[0].Message, tc.want)
		}
	}
}

// Another tenant's disabled scope says nothing about this site.
func TestAnnotateUnprotected_IgnoresUnrelatedScopes(t *testing.T) {
	cov := vpCoverage{
		engineMode: "on",
		disabled: []modsecDisabledScope{
			{User: "other", Source: "/src/other/modsec.conf"},
			{User: "other", Domain: "unrelated.example", Source: "/var/cpanel/userdata/other/unrelated.example"},
		},
	}

	got := annotateUnprotected([]alert.Finding{vulnFinding("shop.example", "acme", alert.Critical)}, cov)

	if strings.Contains(got[0].Message, "unprotected") {
		t.Errorf("another account's disabled scope must not annotate this finding; got %q", got[0].Message)
	}
}

// Two accounts can legitimately name the same docroot path; they are not
// aliases of one another and one's disabled flag must not cover the other.
func TestVhostAliasSets_ScopedToOneAccount(t *testing.T) {
	sets := vhostAliasSets("" +
		"a.example: alice==alice==main==a.example==/home/shared/public_html==1.2.3.4==1.2.3.4\n" +
		"b.example: bob==bob==main==b.example==/home/shared/public_html==1.2.3.4==1.2.3.4\n")

	peers := sets[aliasKey("alice", "a.example")]
	for _, p := range peers {
		if p == "b.example" {
			t.Fatalf("alias set for alice/a.example leaked another account's domain: %v", peers)
		}
	}
}

// The detector must apply the correlation itself; a caller reading
// vulnerable_plugins findings gets the escalated form.
func TestCheckVulnerablePluginsAnnotatesUnprotectedSites(t *testing.T) {
	db := setupPluginStore(t)
	wpConfig := "/home/alice/public_html/wp-config.php"
	withMockOS(t, &mockOS{glob: func(pattern string) ([]string, error) {
		if pattern == "/home/*/public_html/wp-config.php" {
			return []string{wpConfig}, nil
		}
		return nil, nil
	}})
	withMockCmd(t, &mockCmd{runContextStdout: func(_ context.Context, _ string, args ...string) ([]byte, error) {
		command := strings.Join(args, " ")
		if strings.Contains(command, "plugin list") {
			return []byte(`[{"name":"ultimate-member","status":"active","version":"2.4.1","update_version":"2.9.1"}]`), nil
		}
		if strings.Contains(command, "option get siteurl") {
			return []byte("https://alice.example\n"), nil
		}
		return nil, nil
	}})
	if err := db.SetPluginInfo("ultimate-member", store.PluginInfo{LastChecked: time.Now().Unix()}); err != nil {
		t.Fatal(err)
	}

	restore := vpCoverageForHost
	t.Cleanup(func() { vpCoverageForHost = restore })
	vpCoverageForHost = func() vpCoverage {
		return vpCoverage{
			engineMode: "on",
			disabled:   []modsecDisabledScope{{User: "alice", Source: "/src/alice/modsec.conf"}},
		}
	}

	cfg := &config.Config{}
	cfg.Thresholds.PluginCheckIntervalMin = 1440

	findings := CheckVulnerablePlugins(context.Background(), cfg, nil)

	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %+v", findings)
	}
	if !strings.Contains(findings[0].Message, "unprotected") {
		t.Fatalf("detector did not apply the coverage correlation: %q", findings[0].Message)
	}
}
