package checks

import (
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/store"
)

// evaluatePluginCache used to emit one finding per outdated plugin per
// site. With 200 accounts averaging ~5 outdated plugins each, a single
// deep tier produced ~1000 findings, blowing past the alert channel cap
// and burying real signal under "alert channel full, dropping deep
// finding: outdated_plugins".
//
// Aggregation: one finding per site, severity = max of constituents,
// Message describes the count, Details lists the per-plugin breakdown
// so operators still see exactly which plugins are behind.
//
// All tests here use a real bbolt store via t.TempDir() because
// evaluatePluginCache reads via db.AllSitePlugins; mocking the store
// would test the mock, not the function.

func newAggregationStore(t *testing.T) *store.DB {
	t.Helper()
	dir := t.TempDir()
	sdb, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sdb.Close() })
	return sdb
}

func TestEvaluatePluginCache_OneFindingPerSiteRegardlessOfPluginCount(t *testing.T) {
	db := newAggregationStore(t)

	site := store.SitePlugins{
		Account: "alice",
		Domain:  "alice.example",
		Plugins: []store.SitePluginEntry{
			{Slug: "p1", Name: "Plugin One", Status: "active", InstalledVersion: "1.0.0", UpdateVersion: "1.0.1"},
			{Slug: "p2", Name: "Plugin Two", Status: "active", InstalledVersion: "1.0.0", UpdateVersion: "1.0.2"},
			{Slug: "p3", Name: "Plugin Three", Status: "active", InstalledVersion: "1.0.0", UpdateVersion: "1.0.3"},
			{Slug: "p4", Name: "Plugin Four", Status: "active", InstalledVersion: "1.0.0", UpdateVersion: "1.0.4"},
			{Slug: "p5", Name: "Plugin Five", Status: "active", InstalledVersion: "1.0.0", UpdateVersion: "1.0.5"},
		},
	}
	if err := db.SetSitePlugins("/home/alice/public_html", site); err != nil {
		t.Fatal(err)
	}

	findings := evaluatePluginCache(db)

	count := 0
	for _, f := range findings {
		if f.Check == "outdated_plugins" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("got %d outdated_plugins findings for 5 plugins on one site; want exactly 1", count)
	}
}

func TestEvaluatePluginCache_AggregateSeverityIsMaximumOfConstituents(t *testing.T) {
	db := newAggregationStore(t)

	// Constituents:
	//   one warning (1.0.0 -> 1.0.1, single-minor gap)
	//   one critical (1.0.0 -> 2.0.0, major-version gap)
	site := store.SitePlugins{
		Account: "alice",
		Domain:  "alice.example",
		Plugins: []store.SitePluginEntry{
			{Slug: "warn-only", Name: "Warning Only", Status: "active", InstalledVersion: "1.0.0", UpdateVersion: "1.0.1"},
			{Slug: "critical-major", Name: "Critical Major", Status: "active", InstalledVersion: "1.0.0", UpdateVersion: "2.0.0"},
		},
	}
	if err := db.SetSitePlugins("/home/alice/public_html", site); err != nil {
		t.Fatal(err)
	}

	findings := evaluatePluginCache(db)

	var f alert.Finding
	for _, ff := range findings {
		if ff.Check == "outdated_plugins" {
			f = ff
			break
		}
	}
	if f.Severity != alert.Critical {
		t.Errorf("aggregate severity = %v, want Critical (must escalate to highest constituent)", f.Severity)
	}
}

func TestEvaluatePluginCache_PerPluginDetailsPreservedInDetails(t *testing.T) {
	db := newAggregationStore(t)

	site := store.SitePlugins{
		Account: "alice",
		Domain:  "alice.example",
		Plugins: []store.SitePluginEntry{
			{Slug: "yoast", Name: "Yoast SEO", Status: "active", InstalledVersion: "20.0.0", UpdateVersion: "21.5.0"},
			{Slug: "elementor", Name: "Elementor", Status: "active", InstalledVersion: "3.20.0", UpdateVersion: "3.25.1"},
		},
	}
	if err := db.SetSitePlugins("/home/alice/public_html", site); err != nil {
		t.Fatal(err)
	}

	findings := evaluatePluginCache(db)
	var f alert.Finding
	for _, ff := range findings {
		if ff.Check == "outdated_plugins" {
			f = ff
			break
		}
	}

	// Operators triaging the alert need to know exactly which plugins
	// are behind, not just the count. The Details field must contain
	// each plugin slug, installed version, and available version.
	for _, want := range []string{"yoast", "20.0.0", "21.5.0", "elementor", "3.20.0", "3.25.1"} {
		if !strings.Contains(f.Details, want) {
			t.Errorf("Details missing %q; got: %s", want, f.Details)
		}
	}
}

func TestEvaluatePluginCache_OneSiteOneFindingDifferentSitesIndependent(t *testing.T) {
	db := newAggregationStore(t)

	if err := db.SetSitePlugins("/home/alice/public_html", store.SitePlugins{
		Account: "alice", Domain: "alice.example",
		Plugins: []store.SitePluginEntry{
			{Slug: "p1", Name: "P1", Status: "active", InstalledVersion: "1.0.0", UpdateVersion: "1.0.1"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.SetSitePlugins("/home/bob/public_html", store.SitePlugins{
		Account: "bob", Domain: "bob.example",
		Plugins: []store.SitePluginEntry{
			{Slug: "q1", Name: "Q1", Status: "active", InstalledVersion: "1.0.0", UpdateVersion: "1.0.1"},
			{Slug: "q2", Name: "Q2", Status: "active", InstalledVersion: "1.0.0", UpdateVersion: "1.0.1"},
		},
	}); err != nil {
		t.Fatal(err)
	}

	findings := evaluatePluginCache(db)
	count := 0
	for _, f := range findings {
		if f.Check == "outdated_plugins" {
			count++
		}
	}
	if count != 2 {
		t.Errorf("got %d findings for 2 sites; want exactly 2 (one per site)", count)
	}
}

func TestEvaluatePluginCache_InactivePluginsExcludedFromCount(t *testing.T) {
	db := newAggregationStore(t)

	site := store.SitePlugins{
		Account: "alice",
		Domain:  "alice.example",
		Plugins: []store.SitePluginEntry{
			{Slug: "active1", Name: "Active 1", Status: "active", InstalledVersion: "1.0.0", UpdateVersion: "1.0.1"},
			{Slug: "inactive1", Name: "Inactive 1", Status: "inactive", InstalledVersion: "0.5.0", UpdateVersion: "1.0.0"},
		},
	}
	if err := db.SetSitePlugins("/home/alice/public_html", site); err != nil {
		t.Fatal(err)
	}

	findings := evaluatePluginCache(db)
	var f alert.Finding
	for _, ff := range findings {
		if ff.Check == "outdated_plugins" {
			f = ff
			break
		}
	}

	if !strings.Contains(f.Message, "1 outdated") {
		t.Errorf("Message must reflect only the active outdated count; got: %s", f.Message)
	}
	if strings.Contains(f.Details, "inactive1") {
		t.Errorf("inactive plugins must be excluded from per-plugin details; got: %s", f.Details)
	}
}

func TestEvaluatePluginCache_EmitsNoFindingWhenAllUpToDate(t *testing.T) {
	db := newAggregationStore(t)

	site := store.SitePlugins{
		Account: "alice",
		Domain:  "alice.example",
		Plugins: []store.SitePluginEntry{
			{Slug: "current", Name: "Current", Status: "active", InstalledVersion: "1.0.0", UpdateVersion: "1.0.0"},
		},
	}
	if err := db.SetSitePlugins("/home/alice/public_html", site); err != nil {
		t.Fatal(err)
	}

	findings := evaluatePluginCache(db)
	for _, f := range findings {
		if f.Check == "outdated_plugins" {
			t.Errorf("must not emit outdated_plugins finding when no plugin is behind; got: %+v", f)
		}
	}
}

// Latent bug surfaced during review: alert.Severity's zero value is
// Warning. When EVERY outdated plugin on a site is Warning-severity the
// previous worstSevLabel comparison (severityRank > severityRank) never
// updated, leaving the label empty and the message malformed
// ("worst severity " with trailing nothing). This test pins the label
// to a non-empty value for the all-Warning case.

func TestEvaluatePluginCache_AllWarningSeverityProducesNonEmptyLabel(t *testing.T) {
	db := newAggregationStore(t)

	site := store.SitePlugins{
		Account: "alice",
		Domain:  "alice.example",
		Plugins: []store.SitePluginEntry{
			{Slug: "p1", Name: "P1", Status: "active", InstalledVersion: "1.0.0", UpdateVersion: "1.0.1"},
			{Slug: "p2", Name: "P2", Status: "active", InstalledVersion: "1.0.0", UpdateVersion: "1.0.1"},
		},
	}
	if err := db.SetSitePlugins("/home/alice/public_html", site); err != nil {
		t.Fatal(err)
	}

	findings := evaluatePluginCache(db)
	var f alert.Finding
	for _, ff := range findings {
		if ff.Check == "outdated_plugins" {
			f = ff
			break
		}
	}

	if !strings.Contains(f.Message, "warning") {
		t.Errorf("aggregate message must include the severity label even when all constituents are Warning; got: %q", f.Message)
	}
	if strings.HasSuffix(f.Message, "worst severity ") {
		t.Errorf("aggregate message has empty severity label (trailing space); got: %q", f.Message)
	}
}
