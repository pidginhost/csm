package checks

import (
	"path/filepath"
	"strings"

	"github.com/pidginhost/csm/internal/config"
)

// MigrateWPCronCrontabs upgrades CSM-managed wp-cron crontab lines installed
// by older releases (synchronized */N schedule, no overlap lock) to the
// current staggered format. The perf_wp_cron finding never re-fires once
// DISABLE_WP_CRON is set, so already-fixed accounts can only be reached by
// walking the spool directly. Gated on the same fix_wp_cron opt-in as the
// install path; returns the number of crontabs rewritten.
func MigrateWPCronCrontabs(cfg *config.Config) int {
	if cfg == nil || !cfg.AutoResponse.Enabled || !cfg.AutoResponse.FixWPCron {
		return 0
	}
	opts := WPCronFixOptions{
		IntervalMinutes: cfg.Performance.WPCronFix.IntervalMinutes,
		PHPBin:          cfg.Performance.WPCronFix.PHPBin,
	}

	upgraded := 0
	seen := map[string]bool{}
	for _, dir := range wpCronSpoolDirs {
		entries, err := osFS.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			owner := e.Name()
			if seen[owner] || !validCPUser.MatchString(owner) {
				continue
			}
			seen[owner] = true
			data, err := osFS.ReadFile(filepath.Join(dir, owner))
			if err != nil {
				continue
			}
			for _, docroot := range wpCronManagedDocroots(string(data)) {
				installed, err := installUserWPCron(owner, docroot, opts)
				if err == nil && installed {
					upgraded++
				}
			}
		}
	}
	return upgraded
}

// wpCronManagedDocroots extracts docroots from CSM marker lines. The marker
// is attacker-writable in principle (the spool file belongs to the account),
// so only clean absolute paths may flow into a crontab rewrite.
func wpCronManagedDocroots(crontab string) []string {
	var roots []string
	for _, line := range strings.Split(crontab, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, wpCronJobMarker) {
			continue
		}
		docroot := strings.TrimSpace(strings.TrimPrefix(trimmed, wpCronJobMarker))
		if docroot == "" || !filepath.IsAbs(docroot) || filepath.Clean(docroot) != docroot {
			continue
		}
		roots = append(roots, docroot)
	}
	return roots
}
