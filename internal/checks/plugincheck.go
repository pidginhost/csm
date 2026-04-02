package checks

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/pidginhost/cpanel-security-monitor/internal/store"
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
func fetchWPOrgPluginInfo(slug string) (store.PluginInfo, error) {
	url := "https://api.wordpress.org/plugins/info/1.2/?action=plugin_information" +
		"&request[slug]=" + slug +
		"&request[fields][version]=1&request[fields][tested]=1"

	resp, err := wpOrgHTTPClient.Get(url) //nolint:noctx // simple GET, no context needed
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

	// Compare all parsed components to detect any difference (including patch).
	maxLen := len(iv)
	if len(av) > maxLen {
		maxLen = len(av)
	}
	differs := false
	for i := 0; i < maxLen; i++ {
		var a, b int
		if i < len(iv) {
			a = iv[i]
		}
		if i < len(av) {
			b = av[i]
		}
		if a != b {
			differs = true
			break
		}
	}

	if differs {
		return "warning"
	}
	return ""
}
