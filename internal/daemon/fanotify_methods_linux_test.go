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
	// Suppressions are applied later in analyzeFile.
	if !fm.isInteresting("/home/alice/node_modules/pkg/index.php") {
		t.Error("PHP must be admitted before suppression filtering")
	}
}

// Staging names are tenant-controlled and must reach content analysis.
func TestIsInteresting_ScansAtomicWriteStagingFile(t *testing.T) {
	fm := newTestFileMonitor(t)
	paths := []string{
		"/home/user/public_html/wp-includes/PHPMailer/.temp.1776678837447384369.PHPMailer.php",
		"/home/user/public_html/.temp.1776678837499645998.class-json.php",
		"/home/user/public_html/.temp.0.file.php",
		"/home/user/public_html/.temp.9.x.htaccess",
		"/home/user/public_html/.temp.1.foo.html",
		"/home/user/public_html/.temp.1..user.ini",
		"/home/user/public_html/.temp.1.results.txt",
	}
	for _, p := range paths {
		if !fm.isInteresting(p) {
			t.Errorf("isInteresting(%q) = false, want true (atomic-write staging file)", p)
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
	real := dir + "/results.txt"
	_ = os.WriteFile(real, []byte(
		"alice@example.com:pass1\nbob@example.com:pass2\ncarol@example.com:pass3\n"+
			"dave@example.com:pass4\neve@example.com:pass5\n"), 0644)
	f, err := os.Open(real) // #nosec G304 -- test-controlled temp path
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	// Content is read from the fd; the path string only needs /public_html/
	// for the location gate, so it does not have to exist on disk.
	fm.checkCredentialLog(int(f.Fd()), "/home/u/public_html/results.txt", "unknown")
	select {
	case got := <-ch:
		if got.Check != "credential_log_realtime" {
			t.Errorf("Check = %q, want credential_log_realtime", got.Check)
		}
	default:
		t.Error("expected credential_log_realtime alert from fd-read content")
	}
}

// --- checkPhishingZip with suspicious name ---------------------------

func TestCheckPhishingZipSuspiciousName(t *testing.T) {
	ch := make(chan alert.Finding, 10)
	fm := &FileMonitor{
		cfg:     &config.Config{},
		alertCh: ch,
	}

	fm.checkPhishingZip("/home/alice/public_html/office365_kit.zip", "office365_kit.zip", "unknown")
	if len(ch) != 0 {
		t.Fatal("brand plus kit alone must not flag a legitimate distribution")
	}
	fm.checkPhishingZip("/home/alice/public_html/office365-login.zip", "office365-login.zip", "unknown")
	select {
	case finding := <-ch:
		if finding.Check != "phishing_kit_realtime" || finding.Severity != alert.High {
			t.Fatalf("unexpected phishing kit finding: %+v", finding)
		}
	default:
		t.Fatal("brand plus credential action must alert")
	}
}

// --- resolveProcessInfo with nonexistent pid -------------------------

func TestResolveProcessInfoNonexistent(t *testing.T) {
	if info := resolveProcessInfo(1 << 30); info != "" {
		t.Fatalf("process beyond Linux PID range returned info: %q", info)
	}
}
