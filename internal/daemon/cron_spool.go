package daemon

import "github.com/pidginhost/csm/internal/platform"

// cronSpoolWatchDir overrides the directory the realtime crontab watcher
// marks. Empty means "ask the platform". Tests redirect it under
// t.TempDir() without touching the real spool.
var cronSpoolWatchDir = ""

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
