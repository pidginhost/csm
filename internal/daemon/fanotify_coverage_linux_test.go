//go:build linux

package daemon

import (
	"archive/zip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"golang.org/x/sys/unix"
)

// --- isInteresting: extended coverage for every branch ------------------

func TestIsInterestingAllBranches(t *testing.T) {
	fm := newTestFileMonitor(t)

	cases := []struct {
		path string
		want bool
		desc string
	}{
		// PHP variants
		{"/home/a/x.php", true, "php"},
		{"/home/a/x.phtml", true, "phtml"},
		{"/home/a/x.pht", true, "pht"},
		{"/home/a/x.php5", true, "php5"},
		// Webshell extensions
		{"/home/a/x.haxor", true, "haxor"},
		{"/home/a/x.cgix", true, "cgix"},
		// CGI in /home/
		{"/home/a/x.pl", true, "perl"},
		{"/home/a/x.cgi", true, "cgi"},
		{"/home/a/x.py", true, "python"},
		{"/home/a/x.sh", true, "bash"},
		{"/home/a/x.rb", true, "ruby"},
		// CGI outside /home/ and /tmp/
		{"/var/log/x.pl", false, "pl outside /home and /tmp"},
		// .user.ini
		{"/home/a/.user.ini", true, "user.ini"},
		// HTML in /home
		{"/home/a/index.html", true, "html in /home"},
		{"/home/a/page.htm", true, "htm in /home"},
		{"/opt/www/index.html", false, "html outside /home"},
		// Credential log filenames
		{"/home/a/public_html/results.txt", true, "credential log"},
		{"/home/a/public_html/passwords.txt", true, "credential log passwords"},
		// ZIP in /home
		{"/home/a/public_html/phish.zip", true, "zip in /home"},
		{"/opt/phish.zip", false, "zip outside /home"},
		// .config directory
		{"/home/a/.config/foo", true, ".config subtree"},
		// /tmp, /dev/shm, /var/tmp
		{"/tmp/dropper", true, "/tmp path"},
		{"/dev/shm/xyz", true, "/dev/shm"},
		{"/var/tmp/abc", true, "/var/tmp"},
		// PHP in sensitive dir
		{"/home/a/.ssh/evil.php", true, "php in .ssh"},
		{"/home/a/.cpanel/evil.php", true, "php in .cpanel"},
		{"/home/a/mail/evil.php", true, "php in mail"},
		{"/home/a/.gnupg/evil.php", true, "php in .gnupg"},
		{"/home/a/.cagefs/evil.php", true, "php in .cagefs"},
		// Uninteresting
		{"/opt/data.csv", false, "csv outside /home"},
		{"/home/a/style.css", false, "css file"},
		{"/home/a/image.jpg", false, "jpg file"},
	}

	for _, tc := range cases {
		got := fm.isInteresting(tc.path)
		if got != tc.want {
			t.Errorf("%s: isInteresting(%q) = %v, want %v", tc.desc, tc.path, got, tc.want)
		}
	}
}

// --- shouldAlert edge cases --------------------------------------------

func TestShouldAlertEmptyPath(t *testing.T) {
	fm := newTestFileMonitor(t)
	if !fm.shouldAlert("check", "") {
		t.Error("empty path should always alert")
	}
	if !fm.shouldAlert("check", "") {
		t.Error("empty path should always alert (second call)")
	}
}

func TestShouldAlertDifferentKeys(t *testing.T) {
	fm := newTestFileMonitor(t)
	if !fm.shouldAlert("check1", "/x.php") {
		t.Error("first should alert")
	}
	if !fm.shouldAlert("check2", "/x.php") {
		t.Error("different check should alert")
	}
	if !fm.shouldAlert("check1", "/y.php") {
		t.Error("different path should alert")
	}
}

func TestShouldAlertExpiredTTL(t *testing.T) {
	fm := newTestFileMonitor(t)
	key := "check:/path.php"
	fm.alertDedup.Store(key, time.Now().Add(-2*alertDedupTTL))
	if !fm.shouldAlert("check", "/path.php") {
		t.Error("expired entry should allow alert (refresh TTL)")
	}
}

// --- sendAlert with full channel drops alert ---------------------------

func TestSendAlertChannelFullIncrementsDropped(t *testing.T) {
	ch := make(chan alert.Finding, 1)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}

	fm.sendAlert(alert.High, "check1", "msg1", "d1")
	fm.sendAlert(alert.High, "check2", "msg2", "d2")

	if got := atomic.LoadInt64(&fm.droppedAlerts); got != 1 {
		t.Errorf("droppedAlerts = %d, want 1", got)
	}
}

func TestSendAlertWithPathDedupSuppresses(t *testing.T) {
	ch := make(chan alert.Finding, 10)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}

	fm.sendAlertWithPath(alert.Critical, "c", "msg", "d", "/x.php", "pi")
	fm.sendAlertWithPath(alert.Critical, "c", "msg2", "d2", "/x.php", "pi")

	count := 0
drain:
	for {
		select {
		case <-ch:
			count++
		default:
			break drain
		}
	}
	if count != 1 {
		t.Errorf("alerts received = %d, want 1 (second deduped)", count)
	}
}

func TestSendAlertWithPathChannelFullIncrementsDropped(t *testing.T) {
	ch := make(chan alert.Finding, 1)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}

	fm.sendAlertWithPath(alert.High, "c", "m1", "d1", "/a.php", "p")
	fm.sendAlertWithPath(alert.High, "c", "m2", "d2", "/b.php", "p")

	if got := atomic.LoadInt64(&fm.droppedAlerts); got != 1 {
		t.Errorf("droppedAlerts = %d, want 1", got)
	}
}

// --- resolveProcessInfo with real PID (self) ---------------------------

func TestResolveProcessInfoSelf(t *testing.T) {
	info := resolveProcessInfo(int32(os.Getpid()))
	if info == "" {
		t.Fatal("expected non-empty info for self pid")
	}
	if !containsSubstring(info, "pid=") || !containsSubstring(info, "cmd=") {
		t.Errorf("missing pid/cmd fields: %q", info)
	}
	if !containsSubstring(info, "uid=") {
		t.Errorf("missing uid field: %q", info)
	}
}

func TestResolveProcessInfoZero(t *testing.T) {
	if got := resolveProcessInfo(0); got != "" {
		t.Errorf("pid=0 should return empty, got %q", got)
	}
	if got := resolveProcessInfo(-1); got != "" {
		t.Errorf("pid=-1 should return empty, got %q", got)
	}
}

// --- readFromFd / readTailFromFd with real fds -------------------------

func TestReadFromFdBasic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f.txt")
	if err := os.WriteFile(path, []byte("hello world"), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	got := readFromFd(int(f.Fd()), 1024)
	if string(got) != "hello world" {
		t.Errorf("readFromFd = %q, want %q", got, "hello world")
	}
}

func TestReadFromFdEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(path, []byte{}, 0644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if got := readFromFd(int(f.Fd()), 1024); got != nil {
		t.Errorf("empty file should return nil, got %v", got)
	}
}

func TestReadFromFdInvalid(t *testing.T) {
	if got := readFromFd(-1, 1024); got != nil {
		t.Errorf("invalid fd should return nil, got %v", got)
	}
}

func TestReadTailFromFdSmallFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "small.txt")
	if err := os.WriteFile(path, []byte("tiny"), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if got := readTailFromFd(int(f.Fd()), 1024); got != nil {
		t.Errorf("tail of small file should return nil, got %v", got)
	}
}

func TestReadTailFromFdLargeFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "large.txt")
	payload := make([]byte, 200)
	for i := range payload {
		payload[i] = 'A'
	}
	payload = append(payload, []byte("BBBBBBBBBBBBBBBBBBBB")...)
	if err := os.WriteFile(path, payload, 0644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	tail := readTailFromFd(int(f.Fd()), 20)
	if string(tail) != "BBBBBBBBBBBBBBBBBBBB" {
		t.Errorf("tail = %q, want 20 Bs", tail)
	}
}

func TestReadTailFromFdInvalid(t *testing.T) {
	if got := readTailFromFd(-1, 1024); got != nil {
		t.Errorf("invalid fd should return nil, got %v", got)
	}
}

// --- containsFunc additional edges -------------------------------------

func TestContainsFuncAtStart(t *testing.T) {
	if !containsFunc("base64_decode(x)", "base64_decode(") {
		t.Error("match at position 0 should succeed")
	}
}

func TestContainsFuncAfterUnderscore(t *testing.T) {
	if containsFunc("_base64_decode(x)", "base64_decode(") {
		t.Error("match preceded by underscore is embedded, should not match")
	}
}

func TestContainsFuncAfterDigit(t *testing.T) {
	if containsFunc("1base64_decode(x)", "base64_decode(") {
		t.Error("match preceded by digit is embedded")
	}
}

func TestContainsFuncAdvancesPastFalsePositive(t *testing.T) {
	input := "aexec(; exec(x)"
	if !containsFunc(input, "exec(") {
		t.Error("should find standalone match after skipping embedded one")
	}
}

// --- checkPhishingZip: branches ---------------------------------------

func TestCheckPhishingZipOutsidePublicHTML(t *testing.T) {
	ch := make(chan alert.Finding, 10)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkPhishingZip("/home/a/backup/office365.zip", "office365.zip", "pi")
	select {
	case f := <-ch:
		t.Errorf("no alert expected, got %v", f)
	default:
	}
}

func TestCheckPhishingZipInnocentName(t *testing.T) {
	ch := make(chan alert.Finding, 10)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkPhishingZip("/home/a/public_html/holiday-photos.zip", "holiday-photos.zip", "pi")
	select {
	case f := <-ch:
		t.Errorf("no alert expected, got %v", f)
	default:
	}
}

func TestCheckPhishingZipRealFileSuspicious(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "office365_kit.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, _ := zw.Create("index.php")
	_, _ = w.Write([]byte("<?php echo 'hi'; ?>"))
	_ = zw.Close()
	_ = f.Close()

	ch := make(chan alert.Finding, 10)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkPhishingZip("/home/a/public_html/office365_kit.zip", "office365_kit.zip", "pi")
	select {
	case f := <-ch:
		if f.Check != "phishing_kit_realtime" {
			t.Errorf("check = %q, want phishing_kit_realtime", f.Check)
		}
	default:
		t.Error("expected phishing_kit_realtime alert")
	}
}

// --- checkCredentialLog: early-return branches -------------------------

func TestCheckCredentialLogOutsidePublicHTML(t *testing.T) {
	ch := make(chan alert.Finding, 10)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkCredentialLog("/home/a/results.txt", "pi")
	select {
	case f := <-ch:
		t.Errorf("no alert expected, got %v", f)
	default:
	}
}

func TestCheckCredentialLogEtcSkipped(t *testing.T) {
	ch := make(chan alert.Finding, 10)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkCredentialLog("/etc/passwd", "pi")
	select {
	case f := <-ch:
		t.Errorf("no alert expected for /etc/, got %v", f)
	default:
	}
}

func TestCheckCredentialLogConfigSuffixSkipped(t *testing.T) {
	ch := make(chan alert.Finding, 10)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	for _, p := range []string{
		"/home/a/public_html/app.conf",
		"/home/a/public_html/app.cfg",
		"/home/a/public_html/app.ini",
		"/home/a/public_html/app.yaml",
		"/home/a/public_html/app.yml",
	} {
		fm.checkCredentialLog(p, "pi")
	}
	select {
	case f := <-ch:
		t.Errorf("no alert expected for config suffix, got %v", f)
	default:
	}
}

func TestCheckCredentialLogEmailListHigh(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "public_html")
	if err := os.MkdirAll(nested, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(nested, "emails.txt")

	var content []byte
	for i := 0; i < 12; i++ {
		content = append(content, []byte("someone@example.com (unformatted line)\n")...)
	}
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatal(err)
	}

	ch := make(chan alert.Finding, 10)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkCredentialLog(path, "pi")

	select {
	case f := <-ch:
		if f.Check != "credential_log_realtime" {
			t.Errorf("check = %q", f.Check)
		}
		if f.Severity != alert.High {
			t.Errorf("severity = %v, want High", f.Severity)
		}
	default:
		t.Error("expected credential_log_realtime High alert")
	}
}

func TestCheckCredentialLogCriticalFromDelimiters(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "public_html")
	if err := os.MkdirAll(nested, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(nested, "data.txt")

	content := []byte(
		"a@example.com|pass1\n" +
			"b@example.com,pass2\n" +
			"c@example.com\tpass3\n" +
			"d@example.com:pass4\n" +
			"e@example.com:pass5\n" +
			"f@example.com:pass6\n")
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatal(err)
	}

	ch := make(chan alert.Finding, 10)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkCredentialLog(path, "pi")

	select {
	case f := <-ch:
		if f.Severity != alert.Critical {
			t.Errorf("severity = %v, want Critical", f.Severity)
		}
	default:
		t.Error("expected Critical alert for 6 email:password lines")
	}
}

func TestCheckCredentialLogMissingFile(t *testing.T) {
	ch := make(chan alert.Finding, 10)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkCredentialLog("/home/a/public_html/nope.txt", "pi")
	select {
	case f := <-ch:
		t.Errorf("no alert expected, got %v", f)
	default:
	}
}

// --- checkHtaccess (fd-based) ------------------------------------------

func TestCheckHtaccessDangerous(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".htaccess")
	if err := os.WriteFile(path, []byte("php_value auto_prepend_file /tmp/x.php\n"), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	ch := make(chan alert.Finding, 10)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkHtaccess(int(f.Fd()), path, "pi")

	select {
	case a := <-ch:
		if a.Check != "htaccess_injection_realtime" {
			t.Errorf("check = %q", a.Check)
		}
	default:
		t.Error("expected htaccess_injection_realtime alert")
	}
}

func TestCheckHtaccessSafePlugin(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".htaccess")
	if err := os.WriteFile(path, []byte("php_value auto_prepend_file /wordfence-waf.php\n"), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	ch := make(chan alert.Finding, 10)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkHtaccess(int(f.Fd()), path, "pi")

	select {
	case a := <-ch:
		if a.Check == "htaccess_injection_realtime" {
			t.Errorf("should not flag wordfence WAF line: %v", a)
		}
	default:
	}
}

func TestCheckHtaccessCommentLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".htaccess")
	if err := os.WriteFile(path, []byte("# auto_prepend_file /tmp/x.php\n"), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	ch := make(chan alert.Finding, 10)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkHtaccess(int(f.Fd()), path, "pi")

	select {
	case a := <-ch:
		if a.Check == "htaccess_injection_realtime" {
			t.Errorf("should not flag comments: %v", a)
		}
	default:
	}
}

// --- checkUserINI (fd-based) -------------------------------------------

func TestCheckUserINIAllowURLInclude(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".user.ini")
	if err := os.WriteFile(path, []byte("allow_url_include = On\n"), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	ch := make(chan alert.Finding, 10)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkUserINI(int(f.Fd()), path, "pi")

	select {
	case a := <-ch:
		if a.Check != "php_config_realtime" {
			t.Errorf("check = %q", a.Check)
		}
	default:
		t.Error("expected php_config_realtime alert")
	}
}

func TestCheckUserINIDisableFunctionsCleared(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".user.ini")
	if err := os.WriteFile(path, []byte("disable_functions = \n"), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	ch := make(chan alert.Finding, 10)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkUserINI(int(f.Fd()), path, "pi")

	select {
	case a := <-ch:
		if a.Check != "php_config_realtime" {
			t.Errorf("check = %q", a.Check)
		}
	default:
		t.Error("expected php_config_realtime alert for cleared disable_functions")
	}
}

func TestCheckUserINISafe(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".user.ini")
	if err := os.WriteFile(path, []byte("memory_limit = 128M\n"), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	ch := make(chan alert.Finding, 10)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkUserINI(int(f.Fd()), path, "pi")

	select {
	case a := <-ch:
		if a.Check == "php_config_realtime" {
			t.Errorf("should not flag safe INI: %v", a)
		}
	default:
	}
}

// --- checkPHPContent (fd-based) ----------------------------------------

func TestCheckPHPContentPasteSite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.php")
	if err := os.WriteFile(path, []byte("<?php $x = 'https://pastebin.com/raw/abc'; ?>"), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	ch := make(chan alert.Finding, 10)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkPHPContent(int(f.Fd()), path, "pi")

	select {
	case a := <-ch:
		if a.Check != "php_dropper_realtime" {
			t.Errorf("check = %q", a.Check)
		}
	default:
		t.Error("expected php_dropper_realtime alert")
	}
}

func TestCheckPHPContentEvalBase64(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.php")
	if err := os.WriteFile(path, []byte("<?php eval(base64_decode('ZWNobyAxOw==')); ?>"), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	ch := make(chan alert.Finding, 10)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkPHPContent(int(f.Fd()), path, "pi")

	select {
	case a := <-ch:
		if a.Check != "obfuscated_php_realtime" {
			t.Errorf("check = %q", a.Check)
		}
	default:
		t.Error("expected obfuscated_php_realtime alert")
	}
}

func TestCheckPHPContentEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.php")
	if err := os.WriteFile(path, []byte{}, 0644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	ch := make(chan alert.Finding, 10)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkPHPContent(int(f.Fd()), path, "pi")
	select {
	case a := <-ch:
		t.Errorf("no alert expected for empty file, got %v", a)
	default:
	}
}

func TestCheckPHPContentBenign(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.php")
	if err := os.WriteFile(path, []byte("<?php echo 'hello world'; ?>"), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	ch := make(chan alert.Finding, 10)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkPHPContent(int(f.Fd()), path, "pi")
	// A signature rule may still match; this test only exercises the path.
	select {
	case <-ch:
	default:
	}
}

// --- checkHTMLPhishing (fd-based) --------------------------------------

func TestCheckHTMLPhishingNotInPublicHTML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.html")
	if err := os.WriteFile(path, []byte("<html></html>"), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	ch := make(chan alert.Finding, 10)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkHTMLPhishing(int(f.Fd()), "/home/a/x.html", "pi")
	select {
	case a := <-ch:
		t.Errorf("no alert expected, got %v", a)
	default:
	}
}

func TestCheckHTMLPhishingSafeDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.html")
	if err := os.WriteFile(path, []byte("<html></html>"), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	ch := make(chan alert.Finding, 10)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkHTMLPhishing(int(f.Fd()), "/home/a/public_html/vendor/pkg/doc.html", "pi")
	select {
	case a := <-ch:
		t.Errorf("no alert expected for safe dir, got %v", a)
	default:
	}
}

func TestCheckHTMLPhishingTooSmall(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.html")
	if err := os.WriteFile(path, []byte("<html></html>"), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	ch := make(chan alert.Finding, 10)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkHTMLPhishing(int(f.Fd()), "/home/a/public_html/x.html", "pi")
	select {
	case a := <-ch:
		t.Errorf("no alert expected for tiny file, got %v", a)
	default:
	}
}

func TestCheckHTMLPhishingBrandImpersonation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "verify.html")
	body := `<!DOCTYPE html><html><head><title>Microsoft 365 Login</title></head><body>
<h1>Sign in to Office 365</h1>
<p>secured by microsoft - 256-bit encrypted</p>
<form action="javascript:void(0)">
<input type="email" name="email" placeholder="you@example.com">
<input type="password" name="password">
<button onclick="window.location.href='https://attacker.workers.dev/submit'">Sign in</button>
</form>
<p>` + string(make([]byte, 400)) + `</p>
</body></html>`
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	ch := make(chan alert.Finding, 10)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkHTMLPhishing(int(f.Fd()), "/home/a/public_html/verify.html", "pi")

	select {
	case a := <-ch:
		if a.Check != "phishing_realtime" {
			t.Errorf("check = %q, want phishing_realtime", a.Check)
		}
	default:
		t.Error("expected phishing_realtime alert")
	}
}

// --- checkCGIBackdoor (fd-based) ---------------------------------------

func TestCheckCGIBackdoorManyIndicators(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.cgi")
	body := `#!/usr/bin/perl
system("id");
my $cmd = param('c');
$data = base64_decode($cmd);
use CGI;
$len = $ENV{CONTENT_LENGTH};
`
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	ch := make(chan alert.Finding, 10)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkCGIBackdoor(int(f.Fd()), path, "pi")

	select {
	case a := <-ch:
		if a.Check != "cgi_backdoor_realtime" {
			t.Errorf("check = %q, want cgi_backdoor_realtime", a.Check)
		}
	default:
		t.Error("expected cgi_backdoor_realtime alert")
	}
}

func TestCheckCGIBackdoorInImagesDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.cgi")
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho hello\n"), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	ch := make(chan alert.Finding, 10)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkCGIBackdoor(int(f.Fd()), "/home/a/public_html/images/evil.cgi", "pi")

	select {
	case a := <-ch:
		if a.Check != "cgi_suspicious_location_realtime" {
			t.Errorf("check = %q, want cgi_suspicious_location_realtime", a.Check)
		}
	default:
		t.Error("expected cgi_suspicious_location_realtime alert")
	}
}

func TestCheckCGIBackdoorEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.cgi")
	if err := os.WriteFile(path, []byte{}, 0644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	ch := make(chan alert.Finding, 10)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkCGIBackdoor(int(f.Fd()), "/home/a/public_html/x.cgi", "pi")
	select {
	case a := <-ch:
		t.Errorf("no alert expected, got %v", a)
	default:
	}
}

// --- Stop/drainAndClose safety -----------------------------------------

func TestStopIsIdempotent(t *testing.T) {
	var pipeFds [2]int
	if err := unix.Pipe2(pipeFds[:], unix.O_NONBLOCK|unix.O_CLOEXEC); err != nil {
		t.Skipf("pipe2 not available: %v", err)
	}
	devNull, err := os.OpenFile("/dev/null", os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}

	fm := &FileMonitor{
		fd:      int(devNull.Fd()),
		cfg:     &config.Config{},
		alertCh: make(chan alert.Finding, 10),
		pipeFds: pipeFds,
		stopCh:  make(chan struct{}),
	}
	_ = devNull

	fm.Stop()
	fm.Stop() // must be safe to call twice

	fm.analyzerCh = make(chan fileEvent)
	fm.drainAndClose()
	fm.drainAndClose() // second call must be safe
}

// --- Helper ------------------------------------------------------------

func containsSubstring(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
