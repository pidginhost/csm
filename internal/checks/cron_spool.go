package checks

import "github.com/pidginhost/csm/internal/platform"

// cronSpoolDir returns the directory holding per-user crontabs for this
// platform (cronie: /var/spool/cron; Debian cron: /var/spool/cron/crontabs).
// Var so tests can pin a layout without touching the host.
var cronSpoolDir = func() string { return platform.Detect().CronSpoolDir() }

// webServerUsers returns the accounts the web server runs as on this
// platform; a seam so tests can stand in for platform detection.
var webServerUsers = func() []string { return platform.Detect().WebServerUsers() }
