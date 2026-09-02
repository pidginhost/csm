//go:build linux

package daemon

import "github.com/pidginhost/csm/internal/platform"

// cronSpoolDir returns the per-user crontab directory the watcher marks and
// matches event paths against: cronie's /var/spool/cron, or Debian cron's
// /var/spool/cron/crontabs. platform.Detect caches its answer, so this is
// cheap enough for the per-event path checks.
func cronSpoolDir() string {
	if cronSpoolWatchDir != "" {
		return cronSpoolWatchDir
	}
	return platform.Detect().CronSpoolDir()
}
