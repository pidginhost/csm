package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/store"
)

var wpOrgHTTPClient = &http.Client{Timeout: 10 * time.Second}

type wpOrgResponse struct {
	Slug    string `json:"slug"`
	Version string `json:"version"`
	Tested  string `json:"tested"`
	Error   string `json:"error"`
}

// parseWPOrgPluginResponse parses a JSON body from the WordPress.org plugin
// information API into a store.PluginInfo. It returns an error if the response
// contains an error field (e.g. "Plugin not found.") or if the JSON is invalid.
func parseWPOrgPluginResponse(body []byte) (store.PluginInfo, error) {
	var resp wpOrgResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return store.PluginInfo{}, fmt.Errorf("wporg: invalid JSON: %w", err)
	}
	if resp.Error != "" {
		return store.PluginInfo{}, fmt.Errorf("wporg: %s", resp.Error)
	}
	return store.PluginInfo{
		LatestVersion: resp.Version,
		TestedUpTo:    resp.Tested,
		LastChecked:   time.Now().Unix(),
	}, nil
}

// fetchWPOrgPluginInfo queries the WordPress.org plugin information API for the
// given slug and returns the parsed PluginInfo.
func fetchWPOrgPluginInfo(ctx context.Context, slug string) (store.PluginInfo, error) {
	url := "https://api.wordpress.org/plugins/info/1.2/?action=plugin_information" +
		"&request[slug]=" + neturl.QueryEscape(slug) +
		"&request[fields][version]=1&request[fields][tested]=1"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return store.PluginInfo{}, fmt.Errorf("wporg: building request: %w", err)
	}
	resp, err := wpOrgHTTPClient.Do(req)
	if err != nil {
		return store.PluginInfo{}, fmt.Errorf("wporg: HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return store.PluginInfo{}, fmt.Errorf("wporg: reading response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return store.PluginInfo{}, fmt.Errorf("wporg: unexpected status %d", resp.StatusCode)
	}

	return parseWPOrgPluginResponse(body)
}

// parseVersion splits a dotted version string like "6.4.2" into []int{6, 4, 2}.
// Non-numeric segments are treated as 0.
func parseVersion(v string) []int {
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ".")
	out := make([]int, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			n = 0
		}
		out[i] = n
	}
	return out
}

// compareVersions returns whether there is a major version gap and
// how many minor versions behind the installed version is.
func compareVersions(installed, available string) (majorGap bool, minorBehind int) {
	iv := parseVersion(installed)
	av := parseVersion(available)

	if len(iv) < 2 || len(av) < 2 {
		return false, 0
	}

	if av[0] > iv[0] {
		return true, 0
	}

	if av[0] == iv[0] && av[1] > iv[1] {
		return false, av[1] - iv[1]
	}

	return false, 0
}

// pluginAlertSeverity returns "critical", "high", "warning", or "" for a version gap.
func pluginAlertSeverity(installed, available string) string {
	majorGap, minorBehind := compareVersions(installed, available)

	if majorGap {
		return "critical"
	}
	if minorBehind >= 3 {
		return "high"
	}

	// Check if there is any difference at all.
	iv := parseVersion(installed)
	av := parseVersion(available)
	if len(iv) < 2 || len(av) < 2 {
		return ""
	}

	// Compare all parsed components to detect if available is actually newer.
	// If installed >= available at every component, the site is up to date
	// (or ahead, e.g. custom/premium builds). Only warn when behind.
	maxLen := len(iv)
	if len(av) > maxLen {
		maxLen = len(av)
	}
	for i := 0; i < maxLen; i++ {
		var a, b int
		if i < len(iv) {
			a = iv[i]
		}
		if i < len(av) {
			b = av[i]
		}
		if b > a {
			return "warning" // available is newer at this component
		}
		if a > b {
			return "" // installed is ahead - not outdated
		}
	}
	return "" // identical
}

const pluginCheckWorkers = 5

// CheckOutdatedPlugins scans all WordPress installations for plugins with
// available updates and emits findings based on severity of the version gap.
// Results are cached in bbolt with a configurable refresh interval (default 24h).
func CheckOutdatedPlugins(ctx context.Context, cfg *config.Config, _ *state.Store) []alert.Finding {
	db := store.Global()
	if db == nil {
		return nil
	}

	// Refresh cache if stale.
	lastRefresh := db.GetPluginRefreshTime()
	interval := time.Duration(cfg.Thresholds.PluginCheckIntervalMin) * time.Minute
	if time.Since(lastRefresh) > interval {
		refreshPluginCache(ctx, db)
	}

	return evaluatePluginCache(db)
}

// findAllWPInstalls discovers all wp-config.php files under /home, deduplicating
// and skipping cache/backup/staging/trash paths.
func findAllWPInstalls() []string {
	patterns := []string{
		"/home/*/public_html/wp-config.php",
		"/home/*/public_html/*/wp-config.php",
		"/home/*/*/wp-config.php",
	}

	seen := make(map[string]bool)
	var results []string

	skipSubstrings := []string{"/cache/", "/backup", "/staging", "/.trash/"}

	for _, pattern := range patterns {
		matches, _ := osFS.Glob(pattern)
		for _, m := range matches {
			skip := false
			lower := strings.ToLower(m)
			for _, sub := range skipSubstrings {
				if strings.Contains(lower, sub) {
					skip = true
					break
				}
			}
			if skip {
				continue
			}
			if !seen[m] {
				seen[m] = true
				results = append(results, m)
			}
		}
	}

	return results
}

// wpCLIPluginEntry mirrors the JSON output of `wp plugin list --format=json`.
type wpCLIPluginEntry struct {
	Name          string `json:"name"`
	Status        string `json:"status"`
	Version       string `json:"version"`
	UpdateVersion string `json:"update_version"`
}

// refreshPluginCache discovers all WP installs, runs wp-cli to inventory
// plugins for each site, enriches free plugins via the WordPress.org API,
// and stores everything in bbolt.
func refreshPluginCache(ctx context.Context, db *store.DB) {
	wpConfigs := findAllWPInstalls()
	if len(wpConfigs) == 0 {
		return
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	successCount := 0
	slugsSeen := make(map[string]bool)
	discoveredPaths := make(map[string]bool)

	jobs := make(chan string, len(wpConfigs))
	for i := 0; i < pluginCheckWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for wpConfig := range jobs {
				if ctx.Err() != nil {
					return
				}
				wpPath := filepath.Dir(wpConfig)
				user := extractUser(wpPath)
				domain := extractWPDomain(ctx, wpPath, user)
				if ctx.Err() != nil {
					return
				}

				mu.Lock()
				discoveredPaths[wpPath] = true
				mu.Unlock()

				// Run wp plugin list as the site owner.
				// Use --path flag instead of shell cd to avoid shell injection
				// via crafted directory names on shared hosting.
				out, err := exec.CommandContext(ctx, "su", "-", user, "-s", "/bin/bash", "-c",
					"wp plugin list --fields=name,status,version,update_version --format=json --path="+shellQuote(wpPath),
				).Output()
				if err != nil {
					if ctx.Err() != nil {
						return
					}
					fmt.Fprintf(os.Stderr, "plugincheck: wp-cli failed for %s: %v\n", wpPath, err)
					continue
				}

				var entries []wpCLIPluginEntry
				if err := json.Unmarshal(out, &entries); err != nil {
					fmt.Fprintf(os.Stderr, "plugincheck: JSON parse failed for %s: %v\n", wpPath, err)
					continue
				}

				sitePlugins := store.SitePlugins{
					Account: user,
					Domain:  domain,
				}
				for _, e := range entries {
					sitePlugins.Plugins = append(sitePlugins.Plugins, store.SitePluginEntry{
						Slug:             e.Name,
						Name:             e.Name,
						Status:           e.Status,
						InstalledVersion: e.Version,
						UpdateVersion:    e.UpdateVersion,
					})
					mu.Lock()
					slugsSeen[e.Name] = true
					mu.Unlock()
				}

				if err := db.SetSitePlugins(wpPath, sitePlugins); err != nil {
					fmt.Fprintf(os.Stderr, "plugincheck: store failed for %s: %v\n", wpPath, err)
					continue
				}

				mu.Lock()
				successCount++
				mu.Unlock()
			}
		}()
	}

	for _, wpConfig := range wpConfigs {
		if ctx.Err() != nil {
			break
		}
		jobs <- wpConfig
	}
	close(jobs)
	wg.Wait()
	if ctx.Err() != nil {
		return
	}

	// Enrich free plugins via WordPress.org API (one lookup per unique slug).
	mu.Lock()
	slugList := make([]string, 0, len(slugsSeen))
	for slug := range slugsSeen {
		slugList = append(slugList, slug)
	}
	mu.Unlock()

	for _, slug := range slugList {
		if ctx.Err() != nil {
			return
		}
		// Skip if we have a recent cached entry (< 24h).
		if cached, ok := db.GetPluginInfo(slug); ok {
			if time.Since(time.Unix(cached.LastChecked, 0)) < 24*time.Hour {
				continue
			}
		}
		info, err := fetchWPOrgPluginInfo(ctx, slug)
		if err != nil {
			// Not found on .org = premium/custom plugin, skip silently.
			continue
		}
		_ = db.SetPluginInfo(slug, info)
	}

	// Prune cache entries for WP installs no longer on disk.
	allCached := db.AllSitePlugins()
	for path := range allCached {
		if !discoveredPaths[path] {
			_ = db.DeleteSitePlugins(path)
		}
	}

	// Only mark refresh as complete if the majority of sites refreshed
	// successfully. A partial failure (e.g. one wp-cli timeout on a 100-site
	// server) should not freeze ALL stale data for 24 hours. But if most
	// sites failed (e.g. transient PHP issue), don't mark as fresh - allow
	// retry next cycle.
	mu.Lock()
	sc := successCount
	mu.Unlock()
	failCount := len(wpConfigs) - sc
	if sc == 0 {
		fmt.Fprintf(os.Stderr, "[%s] Plugin cache refresh FAILED: 0/%d sites succeeded, not updating timestamp\n",
			time.Now().Format("2006-01-02 15:04:05"), len(wpConfigs))
		return
	}
	if failCount > sc {
		fmt.Fprintf(os.Stderr, "[%s] Plugin cache refresh PARTIAL: %d/%d sites failed (majority), not updating timestamp\n",
			time.Now().Format("2006-01-02 15:04:05"), failCount, len(wpConfigs))
		return
	}
	_ = db.SetPluginRefreshTime(time.Now())
}

// evaluatePluginCache reads the cached plugin inventory and emits findings
// for outdated or untracked active plugins.
func evaluatePluginCache(db *store.DB) []alert.Finding {
	var findings []alert.Finding
	allSites := db.AllSitePlugins()

	for wpPath, site := range allSites {
		for _, p := range site.Plugins {
			if p.Status != "active" && p.Status != "active-network" {
				continue
			}

			// Determine the best available version: prefer wp-cli's update_version,
			// fall back to WordPress.org API cache.
			available := p.UpdateVersion
			if available == "" {
				if info, ok := db.GetPluginInfo(p.Slug); ok {
					available = info.LatestVersion
				}
			}

			if available == "" {
				// No update source - skip silently (custom/private plugins).
				continue
			}

			sev := pluginAlertSeverity(p.InstalledVersion, available)
			if sev == "" {
				continue
			}

			var severity alert.Severity
			switch sev {
			case "critical":
				severity = alert.Critical
			case "high":
				severity = alert.High
			default:
				severity = alert.Warning
			}

			findings = append(findings, alert.Finding{
				Severity: severity,
				Check:    "outdated_plugins",
				Message:  fmt.Sprintf("Outdated plugin %q on %s (%s): %s -> %s", p.Name, site.Domain, site.Account, p.InstalledVersion, available),
				Details:  fmt.Sprintf("Path: %s\nInstalled: %s\nAvailable: %s\nSeverity: %s", wpPath, p.InstalledVersion, available, sev),
			})
		}
	}

	return findings
}

// extractWPDomain runs `wp option get siteurl` to discover the site's domain.
// Falls back to directory name heuristics if wp-cli fails.
func extractWPDomain(ctx context.Context, wpPath, user string) string {
	out, err := exec.CommandContext(ctx, "su", "-", user, "-s", "/bin/bash", "-c",
		"wp option get siteurl --path="+shellQuote(wpPath),
	).Output()
	if err == nil {
		url := strings.TrimSpace(string(out))
		if url != "" {
			// Strip protocol prefix for display.
			url = strings.TrimPrefix(url, "https://")
			url = strings.TrimPrefix(url, "http://")
			return url
		}
	}

	// Fallback: use directory name after public_html (addon domain)
	// or account name (main domain).
	parts := strings.Split(wpPath, "/")
	for i, p := range parts {
		if p == "public_html" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return user
}

// shellQuote wraps a string in single quotes for safe shell argument passing.
// Any embedded single quotes are escaped as '\” (end quote, literal quote, start quote).
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
