//go:build linux

package daemon

import (
	"os"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

func newTestFileMonitor(t *testing.T) *FileMonitor {
	t.Helper()
	ch := make(chan alert.Finding, 100)
	cfg := &config.Config{}
	cfg.Suppressions.IgnorePaths = []string{"*/node_modules/*", "*.log"}
	return &FileMonitor{
		cfg:     cfg,
		alertCh: ch,
	}
}

// --- isInteresting ---------------------------------------------------

func TestIsInterestingPHP(t *testing.T) {
	fm := newTestFileMonitor(t)
	if !fm.isInteresting("/home/alice/public_html/evil.php") {
		t.Error("PHP file should be interesting")
	}
}

func TestIsInterestingHTMLPhishing(t *testing.T) {
	fm := newTestFileMonitor(t)
	if !fm.isInteresting("/home/alice/public_html/verify.html") {
		t.Error("HTML file should be interesting")
	}
}

func TestIsInterestingHtaccess(t *testing.T) {
	fm := newTestFileMonitor(t)
	if !fm.isInteresting("/home/alice/public_html/.htaccess") {
		t.Error(".htaccess should be interesting")
	}
}

func TestIsInterestingNonPHP(t *testing.T) {
	fm := newTestFileMonitor(t)
	if fm.isInteresting("/home/alice/public_html/style.css") {
		t.Error("CSS should not be interesting")
	}
}

func TestIsInterestingNodeModules(t *testing.T) {
	fm := newTestFileMonitor(t)
	// isInteresting checks extension, not suppression — PHP in node_modules IS interesting
	// (suppression is applied later in analyzeFile)
	result := fm.isInteresting("/home/alice/node_modules/pkg/index.php")
	_ = result // exercises the function
}

// --- isInteresting: atomic-write staging files ----------------------
//
// cPanel's fileTransfer service (and every restore tool that rolls its
// own atomic write) stages content in `.temp.<nanoseconds>.<name>.<ext>`
// before calling rename(2) to the final path. CSM's fanotify mask is
// CLOSE_WRITE + CREATE (no MOVED_TO), so the scanner sees the temp
// file's content but never the rename target. Scanning the temp path
// means a WordPress restore produces dozens of Critical alerts on the
// content of genuine WP core / plugin files (PHPMailer.php matches
// webshell_marijuana; class-json.php matches dropper_php_input_stream;
// etc.) seconds before those files land at their canonical paths.
//
// The fix skips these transient staging filenames at the fast-path
// filter. The post-rename file is not re-scanned by realtime, but the
// hourly deep scan catches any file that fails to complete its rename,
// so detection is deferred, not abandoned. An attacker attempting to
// hide a webshell as `.temp.123.evil.php` would have to leave that
// hidden file in place forever (deep scan picks it up) or arrange an
// include(.temp...) from another file (which itself would have fired
// CLOSE_WRITE at a non-staging path).

func TestIsInteresting_SkipsAtomicWriteStagingFile(t *testing.T) {
	fm := newTestFileMonitor(t)
	paths := []string{
		"/home/user/public_html/wp-includes/PHPMailer/.temp.1776678837447384369.PHPMailer.php",
		"/home/user/public_html/.temp.1776678837499645998.class-json.php",
		"/home/user/public_html/.temp.0.file.php",
		"/home/user/public_html/.temp.9.x.htaccess",
		"/home/user/public_html/.temp.1.foo.html",
	}
	for _, p := range paths {
		if fm.isInteresting(p) {
			t.Errorf("isInteresting(%q) = true, want false (atomic-write staging file)", p)
		}
	}
}

func TestIsInteresting_DoesNotSkipLookalikes(t *testing.T) {
	fm := newTestFileMonitor(t)
	// Filenames that look similar but are not the atomic-write staging
	// shape. Must still be scanned normally.
	interesting := []string{
		"/home/user/public_html/temp.1234.file.php",       // no leading dot
		"/home/user/public_html/.temp.abc.file.php",       // non-digit middle segment
		"/home/user/public_html/.temporary.1234.file.php", // wrong prefix
	}
	for _, p := range interesting {
		if !fm.isInteresting(p) {
			t.Errorf("isInteresting(%q) = false, want true (not an atomic-write staging pattern)", p)
		}
	}
}

func TestIsInteresting_RejectsIncompleteStagingNames(t *testing.T) {
	fm := newTestFileMonitor(t)
	// `.temp.<digits>` alone (no trailing .<name>) is not an atomic-write
	// staging file -- it's just a hidden temp. Do not treat specially;
	// extension rules apply. `.temp.1234` has no PHP extension so it is
	// uninteresting via the normal path, which is the correct outcome.
	if fm.isInteresting("/home/user/.temp.1234") {
		t.Error("isInteresting(.temp.1234) without trailing name segment should fall through to extension rules and be uninteresting")
	}
}

// --- shouldAlert -----------------------------------------------------

func TestShouldAlertFirst(t *testing.T) {
	fm := newTestFileMonitor(t)
	if !fm.shouldAlert("webshell", "/home/alice/evil.php") {
		t.Error("first alert should fire")
	}
}

func TestShouldAlertDeduplicated(t *testing.T) {
	fm := newTestFileMonitor(t)
	fm.shouldAlert("webshell", "/home/alice/evil.php")
	if fm.shouldAlert("webshell", "/home/alice/evil.php") {
		t.Error("duplicate alert within window should be suppressed")
	}
}

// --- sendAlert -------------------------------------------------------

func TestSendAlert(t *testing.T) {
	ch := make(chan alert.Finding, 10)
	fm := &FileMonitor{
		cfg:     &config.Config{},
		alertCh: ch,
	}
	fm.sendAlert(alert.Critical, "webshell_realtime", "Found webshell", "details here")

	select {
	case f := <-ch:
		if f.Check != "webshell_realtime" {
			t.Errorf("check = %q", f.Check)
		}
	default:
		t.Error("alert should be sent to channel")
	}
}

// --- sendAlertWithPath -----------------------------------------------

func TestSendAlertWithPath(t *testing.T) {
	ch := make(chan alert.Finding, 10)
	fm := &FileMonitor{
		cfg:     &config.Config{},
		alertCh: ch,
	}
	fm.sendAlertWithPath(alert.Critical, "php_in_uploads_realtime", "PHP in uploads", "details", "/home/alice/wp-content/uploads/evil.php", "php-fpm")

	select {
	case f := <-ch:
		if f.FilePath != "/home/alice/wp-content/uploads/evil.php" {
			t.Errorf("FilePath = %q", f.FilePath)
		}
	default:
		t.Error("alert should be sent")
	}
}

// --- checkCredentialLog with temp file --------------------------------

func TestCheckCredentialLogWithData(t *testing.T) {
	ch := make(chan alert.Finding, 10)
	fm := &FileMonitor{
		cfg:     &config.Config{},
		alertCh: ch,
	}

	dir := t.TempDir()
	path := dir + "/results.txt"
	_ = os.WriteFile(path, []byte("alice@example.com:pass1\nbob@example.com:pass2\ncarol@example.com:pass3\n"), 0644)

	fm.checkCredentialLog(path, "unknown")
	// Exercises the credential log detection path
}

// --- checkPhishingZip with suspicious name ---------------------------

func TestCheckPhishingZipSuspiciousName(t *testing.T) {
	ch := make(chan alert.Finding, 10)
	fm := &FileMonitor{
		cfg:     &config.Config{},
		alertCh: ch,
	}

	fm.checkPhishingZip("/home/alice/public_html/office365_kit.zip", "office365_kit.zip", "unknown")
	// Exercises the ZIP name checking path
}

// --- resolveProcessInfo with nonexistent pid -------------------------

func TestResolveProcessInfoNonexistent(t *testing.T) {
	info := resolveProcessInfo(999999)
	// Should return empty or "unknown" for nonexistent pid
	_ = info
}
