package checks

import (
	"os"
	"testing"
)

// The crontab fixtures in this package are written for the cronie layout
// (/var/spool/cron/<user>). Pin the platform seam so the suite does not
// change shape on a Debian-based test host; tests that exercise the Debian
// layout pin it explicitly with withCronSpoolDir.
func TestMain(m *testing.M) {
	cronSpoolDir = func() string { return "/var/spool/cron" }
	os.Exit(m.Run())
}
