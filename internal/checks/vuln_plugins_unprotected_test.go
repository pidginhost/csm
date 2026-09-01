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
			"shop.example: acme==acme==addon==acme-host.example==/home/acme/public_html/shop==1.2.3.4==1.2.3.4\n" +
			"shop.example.acme-host.example: acme==acme==sub==acme-host.example==/home/acme/public_html/shop==1.2.3.4==1.2.3.4\n"),
	}

	got := annotateUnprotected([]alert.Finding{vulnFinding("shop.example", "acme", alert.Critical)}, cov)

	if !strings.Contains(got[0].Message, "unprotected") {
		t.Fatalf("alias of a disabled vhost must be reported unprotected; got %q", got[0].Message)
	}
	if !strings.Contains(got[0].Message, "shop.example.acme-host.example") {
		t.Errorf("message must name the vhost that carries the disabled flag; got %q", got[0].Message)
	}
	if !strings.Contains(got[0].Details, "associated subdomain") {
		t.Errorf("details must explain the associated-subdomain relationship; got:\n%s", got[0].Details)
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

// Domain names are only unique inside an account. A stale userdata record for
// another tenant can carry the same hostname and must not expose this tenant.
func TestAnnotateUnprotected_IgnoresSameDomainInAnotherAccount(t *testing.T) {
	cov := vpCoverage{
		engineMode: "on",
		disabled: []modsecDisabledScope{{
			User:   "other",
			Domain: "shop.example",
			Source: "/var/cpanel/userdata/other/shop.example",
		}},
	}

	got := annotateUnprotected([]alert.Finding{vulnFinding("shop.example", "acme", alert.Critical)}, cov)

	if strings.Contains(got[0].Message, "unprotected") {
		t.Errorf("another account's same-named domain must not annotate this finding; got %q", got[0].Message)
	}
}

// A broad account scope is the setting an operator must fix first. Without
// one, the finding's exact vhost is more actionable than an associated subdomain,
// regardless of the disabled-scope sort order.
func TestInertReason_PrefersActionableScope(t *testing.T) {
	aliases := vhostAliasSets("" +
		"shop.example: acme==acme==addon==acme.example==/home/acme/shop==1.2.3.4==1.2.3.4\n" +
		"shop.example.acme.example: acme==acme==sub==acme.example==/home/acme/shop==1.2.3.4==1.2.3.4\n")
	exact := modsecDisabledScope{User: "acme", Domain: "shop.example", Source: "/exact"}
	alias := modsecDisabledScope{User: "acme", Domain: "shop.example.acme.example", Source: "/alias"}
	account := modsecDisabledScope{User: "acme", Source: "/account"}

	reason, source := (vpCoverage{disabled: []modsecDisabledScope{alias, exact}, aliases: aliases}).inertReason("acme", "shop.example")
	if source != "/exact" || !strings.Contains(reason, "shop.example") {
		t.Fatalf("exact scope = %q / %q, want /exact", reason, source)
	}
	reason, source = (vpCoverage{disabled: []modsecDisabledScope{alias, exact, account}, aliases: aliases}).inertReason("acme", "shop.example")
	if source != "/account" || !strings.Contains(reason, "all domains") {
		t.Fatalf("account scope = %q / %q, want /account", reason, source)
	}
}

func TestAnnotateUnprotected_IsIdempotent(t *testing.T) {
	cov := vpCoverage{disabled: []modsecDisabledScope{{User: "acme", Source: "/account"}}}
	findings := []alert.Finding{vulnFinding("shop.example", "acme", alert.Critical)}

	once := annotateUnprotected(findings, cov)[0]
	twice := annotateUnprotected(findings, cov)[0]

	if twice.Message != once.Message || twice.Details != once.Details {
		t.Fatalf("second annotation changed finding:\nonce:  %q / %q\ntwice: %q / %q", once.Message, once.Details, twice.Message, twice.Details)
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

// Same-account docroot reuse is common and does not make independent vhosts
// aliases. In particular, parked piles and an addon left on public_html must
// not inherit another domain's disabled flag.
func TestVhostAliasSets_RejectsAmbiguousSharedDocroots(t *testing.T) {
	sets := vhostAliasSets("" +
		"main.example: acme==acme==main==main.example==/home/acme/public_html==1.2.3.4==1.2.3.4\n" +
		"parked.example: acme==acme==parked==main.example==/home/acme/public_html==1.2.3.4==1.2.3.4\n" +
		"addon.example: acme==acme==addon==main.example==/home/acme/public_html==1.2.3.4==1.2.3.4\n")
	if peers := sets[aliasKey("acme", "addon.example")]; len(peers) != 0 {
		t.Fatalf("ambiguous shared docroot produced aliases: %v", peers)
	}

	cov := vpCoverage{
		disabled: []modsecDisabledScope{{User: "acme", Domain: "main.example", Source: "/main"}},
		aliases:  sets,
	}
	got := annotateUnprotected([]alert.Finding{vulnFinding("addon.example", "acme", alert.Critical)}, cov)
	if strings.Contains(got[0].Message, "unprotected") {
		t.Fatalf("disabled main domain leaked across ambiguous docroot: %q", got[0].Message)
	}

	sets = vhostAliasSets("" +
		"shop.example: acme==acme==addon==main.example==/home/acme/shared==1.2.3.4==1.2.3.4\n" +
		"shop.main.example: acme==acme==sub==main.example==/home/acme/shared==1.2.3.4==1.2.3.4\n")
	if peers := sets[aliasKey("acme", "shop.example")]; len(peers) != 0 {
		t.Fatalf("unrelated addon/subdomain pair produced aliases: %v", peers)
	}
}

func TestVhostAliasSets_RejectsIncompleteDomainMap(t *testing.T) {
	sets := vhostAliasSets("" +
		"shop.example: acme==acme==addon==acme.example==/home/acme/shop==1.2.3.4==1.2.3.4\n" +
		"shop.example.acme.example: acme==acme==sub==acme.example==/home/acme/shop==1.2.3.4==1.2.3.4\n" +
		"truncated-row-without-fields\n")

	if len(sets) != 0 {
		t.Fatalf("incomplete domain map produced aliases: %+v", sets)
	}
}

func TestModsecDisabledScopesForFindings_ReadsOnlyCandidateSites(t *testing.T) {
	fs := newGlobFS(map[string]string{
		"/var/cpanel/userdata/acme/shop.acme.example": "secruleengineoff: 1\n",
		"/var/cpanel/userdata/other/other.example":    "secruleengineoff: 1\n",
	})
	fs.glob = func(pattern string) ([]string, error) {
		t.Fatalf("targeted correlation must not glob the host: %s", pattern)
		return nil, nil
	}
	withMockOS(t, fs)

	scopes := modsecDisabledScopesForFindings(cpanelInfo(), []alert.Finding{
		vulnFinding("shop.example", "acme", alert.Critical),
	}, map[string][]string{
		aliasKey("acme", "shop.example"): {"shop.example", "shop.acme.example"},
	})

	if len(scopes) != 1 || scopes[0].User != "acme" || scopes[0].Domain != "shop.acme.example" {
		t.Fatalf("targeted scopes = %+v, want only acme/shop.acme.example", scopes)
	}
	for _, path := range fs.readPaths {
		if strings.Contains(path, "/other/") {
			t.Fatalf("correlation read unrelated vhost %s", path)
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
	vpCoverageForHost = func([]alert.Finding) vpCoverage {
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

func TestCheckVulnerablePluginsDoesNotClaimMissingPatchForUncoveredCVE(t *testing.T) {
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
			return []byte(`[{"name":"duplicator","status":"active","version":"1.3.20","update_version":"1.5.0"}]`), nil
		}
		if strings.Contains(command, "option get siteurl") {
			return []byte("https://alice.example\n"), nil
		}
		return nil, nil
	}})
	if err := db.SetPluginInfo("duplicator", store.PluginInfo{LastChecked: time.Now().Unix()}); err != nil {
		t.Fatal(err)
	}

	restore := vpCoverageForHost
	t.Cleanup(func() { vpCoverageForHost = restore })
	vpCoverageForHost = func([]alert.Finding) vpCoverage {
		t.Fatal("coverage must not be read for a CVE with no shipped virtual patch")
		return vpCoverage{}
	}

	cfg := &config.Config{}
	cfg.Thresholds.PluginCheckIntervalMin = 1440
	findings := CheckVulnerablePlugins(context.Background(), cfg, nil)

	if len(findings) != 1 {
		t.Fatalf("want 1 duplicator finding, got %+v", findings)
	}
	if strings.Contains(findings[0].Message, "unprotected") || strings.Contains(findings[0].Details, "virtual patches never run") {
		t.Fatalf("uncovered CVE claimed a missing virtual patch: %+v", findings[0])
	}
}
