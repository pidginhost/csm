package checks

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// The crontab fixtures in this package are written for the cronie layout
// (/var/spool/cron/<user>). Pin the platform seam so the suite does not
// change shape on a Debian-based test host; tests that exercise the Debian
// layout pin it explicitly with withCronSpoolDir.
func TestMain(m *testing.M) {
	cronSpoolDir = func() string { return "/var/spool/cron" }
	SetZipLister(inProcessZipLister{})
	// The test host's web server is not the one a test describes.
	SetHTTPRewrite(HTTPRewrite{State: RewriteNone})
	// Every applied fix writes an undo record; keep them out of the real store.
	undoRoot, err := os.MkdirTemp("", "csm-hardening-undo-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	hardeningUndoDir, hardeningUndoOwner = filepath.Join(undoRoot, "undo"), os.Getuid()
	code := m.Run()
	_ = os.RemoveAll(undoRoot)
	os.Exit(code)
}
