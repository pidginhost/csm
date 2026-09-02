package checks

import "github.com/pidginhost/csm/internal/platform"

// cronSpoolDir returns the directory holding per-user crontabs for this
// platform (cronie: /var/spool/cron; Debian cron: /var/spool/cron/crontabs).
// Var so tests can pin a layout without touching the host.
var cronSpoolDir = func() string { return platform.Detect().CronSpoolDir() }
