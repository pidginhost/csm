package checks

import (
	"strconv"
	"strings"
)

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
