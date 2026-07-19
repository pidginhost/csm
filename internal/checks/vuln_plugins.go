package checks

import (
	"context"
	_ "embed"
	"fmt"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/store"
)

// Known-vulnerable WordPress plugin detector.
//
// CheckOutdatedPlugins grades severity by how far a plugin is behind the latest
// release, which buries an actively-exploited version that is only a few
// releases stale. This detector instead matches the installed version against a
// curated feed of known-vulnerable ranges and elevates confirmed hits (CISA-KEV
// / unauthenticated RCE, privesc, SQLi, secret disclosure) to High or Critical
// regardless of version gap. It shares the cached inventory refresh with
// outdated_plugins and only alerts (v1 never disables a plugin, so a real
// customer site is never taken down).

//go:embed embed/plugin_vulns.yaml
var pluginVulnFeedData []byte

// pluginVuln is one known-vulnerable version range for a plugin slug.
type pluginVuln struct {
	Slug        string `yaml:"slug"`
	CVE         string `yaml:"cve"`
	Title       string `yaml:"title"`
	FixedIn     string `yaml:"fixed_in"`
	MinAffected string `yaml:"min_affected"` // optional lower bound
	KEV         bool   `yaml:"kev"`
	Severity    string `yaml:"severity"`
	Reference   string `yaml:"reference"`
}

type pluginVulnFeed struct {
	Plugins []pluginVuln `yaml:"plugins"`
}

// loadPluginVulnFeed parses the curated feed and fails closed on individual
// malformed entries: an entry with missing or invalid range fields is dropped
// (rather than matching everything) so a bad line cannot create false positives.
func loadPluginVulnFeed(data []byte) ([]pluginVuln, error) {
	var feed pluginVulnFeed
	if err := yaml.Unmarshal(data, &feed); err != nil {
		return nil, err
	}
	out := make([]pluginVuln, 0, len(feed.Plugins))
	for _, v := range feed.Plugins {
		if strings.TrimSpace(v.Slug) == "" || strings.TrimSpace(v.CVE) == "" || strings.TrimSpace(v.FixedIn) == "" {
			continue
		}
		if _, ok := parsePluginVersion(v.FixedIn); !ok {
			continue
		}
		if strings.TrimSpace(v.MinAffected) != "" {
			cmp, ok := comparePluginVersions(v.MinAffected, v.FixedIn)
			if !ok || cmp >= 0 {
				continue
			}
		}
		out = append(out, v)
	}
	return out, nil
}

// parsePluginVersion returns normalized decimal components without converting
// them to machine integers. WordPress versions are not strict semver, so a
// suffix on a numeric component is tolerated and ignored. A component that
// does not start with a digit makes the version unusable; an unknown version
// must never underflow into a false vulnerability match.
func parsePluginVersion(v string) ([]string, bool) {
	v = strings.TrimSpace(v)
	if len(v) > 1 && (v[0] == 'v' || v[0] == 'V') && v[1] >= '0' && v[1] <= '9' {
		v = v[1:]
	}
	if v == "" {
		return nil, false
	}
	parts := strings.Split(v, ".")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		i := 0
		for i < len(part) && part[i] >= '0' && part[i] <= '9' {
			i++
		}
		if i == 0 {
			return nil, false
		}
		digits := strings.TrimLeft(part[:i], "0")
		if digits == "" {
			digits = "0"
		}
		out = append(out, digits)
		if i != len(part) {
			if part[i] != '-' && part[i] != '+' {
				return nil, false
			}
			break
		}
	}
	return out, true
}

func comparePluginVersions(a, b string) (int, bool) {
	av, aok := parsePluginVersion(a)
	bv, bok := parsePluginVersion(b)
	if !aok || !bok {
		return 0, false
	}
	n := len(av)
	if len(bv) > n {
		n = len(bv)
	}
	for i := 0; i < n; i++ {
		x, y := "0", "0"
		if i < len(av) {
			x = av[i]
		}
		if i < len(bv) {
			y = bv[i]
		}
		if len(x) < len(y) {
			return -1, true
		}
		if len(x) > len(y) {
			return 1, true
		}
		if x < y {
			return -1, true
		}
		if x > y {
			return 1, true
		}
	}
	return 0, true
}

// versionLess reports whether version a is strictly older than b. Invalid
// versions are incomparable and therefore never considered older.
func versionLess(a, b string) bool {
	cmp, ok := comparePluginVersions(a, b)
	return ok && cmp < 0
}

// matchPluginVuln reports whether an installed version falls inside a
// vulnerable range: strictly below fixed_in and, when a lower bound is given,
// at or above min_affected. An install at or above fixed_in is patched and
// never matches.
func matchPluginVuln(installed string, v pluginVuln) bool {
	if strings.TrimSpace(installed) == "" {
		return false
	}
	if !versionLess(installed, v.FixedIn) {
		return false
	}
	if strings.TrimSpace(v.MinAffected) != "" && versionLess(installed, v.MinAffected) {
		return false
	}
	return true
}

// vulnPluginSeverity maps a matched vulnerability to a finding severity. A
// version-matched known CVE is actionable by definition, so it is never a
// Warning: KEV/actively-exploited or an explicit "critical" is Critical, an
// explicit "high" is High, and anything else defaults to Critical.
func vulnPluginSeverity(v pluginVuln) alert.Severity {
	if v.KEV {
		return alert.Critical
	}
	if strings.EqualFold(strings.TrimSpace(v.Severity), "high") {
		return alert.High
	}
	return alert.Critical
}

func vulnAllowKey(slug, version string) string {
	return strings.ToLower(strings.TrimSpace(slug) + "@" + strings.TrimSpace(version))
}

// evaluatePluginVulns matches the cached per-site plugin inventory against the
// feed and returns one finding per confirmed vulnerable install, skipping any
// slug@version the operator has explicitly accepted via the allowlist.
func evaluatePluginVulns(sites map[string]store.SitePlugins, feed []pluginVuln, allow map[string]bool) []alert.Finding {
	bySlug := make(map[string][]pluginVuln, len(feed))
	for _, v := range feed {
		key := strings.ToLower(strings.TrimSpace(v.Slug))
		bySlug[key] = append(bySlug[key], v)
	}

	var findings []alert.Finding
	for wpPath, site := range sites {
		for _, p := range site.Plugins {
			for _, v := range bySlug[strings.ToLower(strings.TrimSpace(p.Slug))] {
				if !matchPluginVuln(p.InstalledVersion, v) {
					continue
				}
				if allow[vulnAllowKey(p.Slug, p.InstalledVersion)] {
					continue
				}
				findings = append(findings, buildVulnPluginFinding(wpPath, site, p, v))
			}
		}
	}
	return findings
}

func buildVulnPluginFinding(wpPath string, site store.SitePlugins, p store.SitePluginEntry, v pluginVuln) alert.Finding {
	activeNote := "inactive"
	switch strings.ToLower(strings.TrimSpace(p.Status)) {
	case "active", "active-network", "must-use":
		activeNote = "active"
	}
	kevNote := ""
	if v.KEV {
		kevNote = " [CISA-KEV: actively exploited]"
	}
	details := fmt.Sprintf("%s (%s)%s. Installed %s %s is %s; fixed in %s. Remediate: update to %s or newer, or remove the plugin.",
		v.Title, v.CVE, kevNote, p.Slug, p.InstalledVersion, activeNote, v.FixedIn, v.FixedIn)
	if v.Reference != "" {
		details += "\nReference: " + v.Reference
	}
	details += "\nPath: " + wpPath
	return alert.Finding{
		Severity:  vulnPluginSeverity(v),
		Check:     "vulnerable_plugins",
		Message:   fmt.Sprintf("Known-vulnerable plugin %s %s (%s) on %s", p.Slug, p.InstalledVersion, v.CVE, site.Domain),
		Details:   details,
		Domain:    site.Domain,
		TenantID:  site.Account,
		Timestamp: time.Now(),
	}
}

// CheckVulnerablePlugins matches the shared WordPress plugin inventory against
// the curated known-vulnerable feed. It participates in the same serialized
// refresh as CheckOutdatedPlugins and only reports -- it never disables a
// plugin.
func CheckVulnerablePlugins(ctx context.Context, cfg *config.Config, _ *state.Store) []alert.Finding {
	if cfg != nil && !cfg.VulnerablePluginScanningEnabled() {
		return nil
	}
	db := store.Global()
	if db == nil {
		return nil
	}
	if !ensurePluginCacheFresh(ctx, cfg, db) {
		return nil
	}
	feed, err := loadPluginVulnFeed(pluginVulnFeedData)
	if err != nil || len(feed) == 0 {
		return nil
	}
	return evaluatePluginVulns(db.AllSitePlugins(), feed, vulnPluginAllowSet(cfg))
}

func vulnPluginAllowSet(cfg *config.Config) map[string]bool {
	if cfg == nil || len(cfg.Detection.VulnerablePluginAllow) == 0 {
		return nil
	}
	set := make(map[string]bool, len(cfg.Detection.VulnerablePluginAllow))
	for _, e := range cfg.Detection.VulnerablePluginAllow {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		set[strings.ToLower(e)] = true
	}
	return set
}
