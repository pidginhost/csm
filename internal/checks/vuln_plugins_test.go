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

func TestLoadPluginVulnFeed_SkipsMalformed(t *testing.T) {
	data := []byte(`plugins:
  - slug: good
    cve: CVE-2020-0001
    fixed_in: "1.2.3"
    severity: critical
  - slug: ""
    cve: CVE-2020-0002
    fixed_in: "1.0.0"
  - slug: nofix
    cve: CVE-2020-0003
  - slug: nocve
    fixed_in: "2.0.0"
  - slug: badfix
    cve: CVE-2020-0004
    fixed_in: "not-a-version"
  - slug: badmin
    cve: CVE-2020-0005
    fixed_in: "3.0.0"
    min_affected: "not-a-version"
`)
	feed, err := loadPluginVulnFeed(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(feed) != 1 || feed[0].Slug != "good" {
		t.Fatalf("malformed entries must be dropped, got %+v", feed)
	}
}

func TestLoadPluginVulnFeed_Embedded(t *testing.T) {
	feed, err := loadPluginVulnFeed(pluginVulnFeedData)
	if err != nil {
		t.Fatalf("embedded feed must parse: %v", err)
	}
	if len(feed) == 0 {
		t.Fatal("embedded feed is empty")
	}
	foundUltimateMember := false
	foundFileManager := false
	for _, v := range feed {
		if v.Slug == "ultimate-member" && v.FixedIn == "2.6.7" && v.KEV {
			foundUltimateMember = true
		}
		if v.Slug == "wp-file-manager" && v.MinAffected == "6.0" && v.FixedIn == "6.9" && v.KEV {
			foundFileManager = true
		}
	}
	if !foundUltimateMember {
		t.Fatal("embedded feed missing the ultimate-member CVE-2023-3460 KEV entry")
	}
	if !foundFileManager {
		t.Fatal("embedded feed missing the bounded wp-file-manager CVE-2020-25213 KEV entry")
	}
}

func TestMatchPluginVuln(t *testing.T) {
	um := pluginVuln{Slug: "ultimate-member", FixedIn: "2.6.7"}
	dup := pluginVuln{Slug: "duplicator", FixedIn: "1.3.28"}
	stats := pluginVuln{Slug: "wp-statistics", FixedIn: "13.0.8"}
	ranged := pluginVuln{Slug: "x", FixedIn: "3.0.0", MinAffected: "2.0.0"}
	fileManager := pluginVuln{Slug: "wp-file-manager", FixedIn: "6.9", MinAffected: "6.0"}
	cases := []struct {
		name      string
		installed string
		v         pluginVuln
		want      bool
	}{
		{"below fixed fires", "2.4.1", um, true},
		{"at fixed silent", "2.6.7", um, false},
		{"above fixed silent", "2.9.1", um, false},
		{"extra component above fixed silent", "2.6.7.1", um, false},
		{"fixed version suffix stays silent", "2.6.7-p1", um, false},
		{"short version below fixed fires", "2.6", um, true},
		{"surrounding whitespace ignored", " 2.9.1 ", um, false},
		{"internal whitespace never fires", "2. 4.1", um, false},
		{"overflowing component does not underflow", "99999999999999999999.0", um, false},
		{"non-numeric version never fires", "not-a-version", um, false},
		{"malformed numeric prefix never fires", "2garbage", um, false},
		{"negative version never fires", "-1.0", um, false},
		{"duplicator old fires", "0.5.32", dup, true},
		{"duplicator mid fires", "1.2.34", dup, true},
		{"duplicator patched silent", "1.5.0", dup, false},
		{"wp statistics affected fires", "12.5.5", stats, true},
		{"wp statistics fixed silent", "13.0.8", stats, false},
		{"empty version never fires", "", um, false},
		{"below min_affected silent", "1.5.0", ranged, false},
		{"within range fires", "2.5.0", ranged, true},
		{"at min_affected fires", "2.0.0", ranged, true},
		{"file manager before affected range silent", "5.9", fileManager, false},
		{"file manager at affected range fires", "6.0", fileManager, true},
		{"file manager last affected release fires", "6.8", fileManager, true},
		{"file manager fixed release silent", "6.9", fileManager, false},
	}
	for _, c := range cases {
		if got := matchPluginVuln(c.installed, c.v); got != c.want {
			t.Errorf("%s: matchPluginVuln(%q, fixed=%s min=%s)=%v want %v",
				c.name, c.installed, c.v.FixedIn, c.v.MinAffected, got, c.want)
		}
	}
}

func TestVulnPluginSeverity(t *testing.T) {
	if got := vulnPluginSeverity(pluginVuln{KEV: true, Severity: "high"}); got != alert.Critical {
		t.Errorf("KEV must be Critical regardless of severity field, got %v", got)
	}
	if got := vulnPluginSeverity(pluginVuln{Severity: "high"}); got != alert.High {
		t.Errorf("high -> High, got %v", got)
	}
	if got := vulnPluginSeverity(pluginVuln{Severity: "critical"}); got != alert.Critical {
		t.Errorf("critical -> Critical, got %v", got)
	}
	// Never Warning: an unknown/blank severity is actionable by definition.
	if got := vulnPluginSeverity(pluginVuln{Severity: ""}); got == alert.Warning {
		t.Errorf("blank severity must not be Warning, got %v", got)
	}
}

func TestBuildVulnPluginFindingActivationNote(t *testing.T) {
	vuln := pluginVuln{CVE: "CVE-2020-0001", Title: "test", FixedIn: "2.0.0"}
	for _, tc := range []struct {
		status string
		want   string
	}{
		{status: "active", want: "is active"},
		{status: "active-network", want: "is active"},
		{status: "must-use", want: "is active"},
		{status: "inactive", want: "is inactive"},
	} {
		finding := buildVulnPluginFinding("/home/a/wp", store.SitePlugins{}, store.SitePluginEntry{
			Slug: "plugin", InstalledVersion: "1.0.0", Status: tc.status,
		}, vuln)
		if !strings.Contains(finding.Details, tc.want) {
			t.Errorf("status %q details = %q, want %q", tc.status, finding.Details, tc.want)
		}
	}
}

func TestEvaluatePluginVulns(t *testing.T) {
	feed := []pluginVuln{
		{Slug: "ultimate-member", CVE: "CVE-2023-3460", Title: "privesc", FixedIn: "2.6.7", KEV: true, Severity: "critical"},
		{Slug: "duplicator", CVE: "CVE-2020-11738", Title: "file download", FixedIn: "1.3.28", Severity: "critical"},
	}
	sites := map[string]store.SitePlugins{
		"/home/a/wp": {Account: "a", Domain: "a.example", Plugins: []store.SitePluginEntry{
			{Slug: "ultimate-member", InstalledVersion: "2.4.1", Status: "active"}, // vuln
			{Slug: "akismet", InstalledVersion: "5.0", Status: "active"},           // clean
		}},
		"/home/b/wp": {Account: "b", Domain: "b.example", Plugins: []store.SitePluginEntry{
			{Slug: "ultimate-member", InstalledVersion: "2.9.1", Status: "active"}, // patched -> silent
			{Slug: "duplicator", InstalledVersion: "1.2.34", Status: "inactive"},   // vuln, inactive
		}},
	}

	findings := evaluatePluginVulns(sites, feed, nil)
	if len(findings) != 2 {
		t.Fatalf("want 2 findings (um on a, duplicator on b), got %d: %+v", len(findings), findings)
	}
	for _, f := range findings {
		if f.Check != "vulnerable_plugins" {
			t.Errorf("check = %q", f.Check)
		}
		if f.Domain == "" || f.TenantID == "" {
			t.Errorf("finding missing domain/tenant: %+v", f)
		}
		if f.Severity != alert.Critical {
			t.Errorf("matched critical CVE severity = %v, want Critical", f.Severity)
		}
	}
	if !strings.Contains(findings[1].Details, "inactive") && !strings.Contains(findings[0].Details, "inactive") {
		t.Fatal("inactive vulnerable plugin must still produce an inactive-annotated finding")
	}

	// Allowlist suppresses the ultimate-member@2.4.1 acceptance.
	allow := map[string]bool{"ultimate-member@2.4.1": true}
	suppressed := evaluatePluginVulns(sites, feed, allow)
	if len(suppressed) != 1 {
		t.Fatalf("allowlist should suppress one finding, got %d", len(suppressed))
	}
}

func TestVulnPluginAllowlistIsCaseInsensitiveAndVersionSpecific(t *testing.T) {
	feed := []pluginVuln{{
		Slug: "ultimate-member", CVE: "CVE-2023-3460", Title: "privesc", FixedIn: "2.6.7", KEV: true,
	}}
	sites := map[string]store.SitePlugins{
		"/home/a/wp": {
			Domain: "a.example",
			Plugins: []store.SitePluginEntry{
				{Slug: "Ultimate-Member", InstalledVersion: "2.4.1-RC1", Status: "active"},
				{Slug: "ultimate-member", InstalledVersion: "2.5.0", Status: "active"},
			},
		},
	}
	cfg := &config.Config{}
	cfg.Detection.VulnerablePluginAllow = []string{"ULTIMATE-MEMBER@2.4.1-rc1"}

	findings := evaluatePluginVulns(sites, feed, vulnPluginAllowSet(cfg))
	if len(findings) != 1 {
		t.Fatalf("allowlist must suppress exactly one slug@version, got %d: %+v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Message, "2.5.0") {
		t.Fatalf("allowlist suppressed another version of the slug: %+v", findings[0])
	}
}

func TestCheckVulnerablePluginsHandlesEmptyFreshCache(t *testing.T) {
	db := setupPluginStore(t)
	if err := db.SetPluginRefreshTime(time.Now()); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Thresholds.PluginCheckIntervalMin = 1440

	if got := CheckVulnerablePlugins(context.Background(), cfg, nil); got != nil {
		t.Fatalf("empty cache returned findings: %+v", got)
	}
}

func TestCheckVulnerablePluginsRefreshesItsSharedInventory(t *testing.T) {
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
			return []byte(`[{"name":"ultimate-member","status":"inactive","version":"2.4.1","update_version":"2.9.1"}]`), nil
		}
		if strings.Contains(command, "option get siteurl") {
			return []byte("https://alice.example\n"), nil
		}
		return nil, nil
	}})
	if err := db.SetPluginInfo("ultimate-member", store.PluginInfo{LastChecked: time.Now().Unix()}); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Thresholds.PluginCheckIntervalMin = 1440

	findings := CheckVulnerablePlugins(context.Background(), cfg, nil)
	if len(findings) != 1 {
		t.Fatalf("vulnerable detector did not refresh independently: %+v", findings)
	}
	if !strings.Contains(findings[0].Details, "inactive") {
		t.Fatalf("inactive refreshed plugin was not annotated: %+v", findings[0])
	}
}
