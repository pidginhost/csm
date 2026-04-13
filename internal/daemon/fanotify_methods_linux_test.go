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

func TestIsInterestingSuppressed(t *testing.T) {
	fm := newTestFileMonitor(t)
	if fm.isInteresting("/home/alice/node_modules/pkg/index.php") {
		t.Error("node_modules should be suppressed")
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
