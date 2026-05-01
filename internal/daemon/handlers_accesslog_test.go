package daemon

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

func resetAccessLogTrackerState() {
	accessLogTrackers = sync.Map{}
}

func resetPurgeTrackerState() {
	purgeTracker = &purgeState{
		purges:   make(map[string]time.Time),
		sessions: make(map[string]string),
	}
}

func TestExtractRequestURI(t *testing.T) {
	line := `198.51.100.10 - - [11/Apr/2026:12:00:00 +0000] "POST /cpsess1234567/json-api/fileman/upload_files HTTP/1.1" 200 123 "-" "Mozilla/5.0"`
	got := extractRequestURI(line)
	want := "POST /cpsess1234567/json-api/fileman/upload_files HTTP/1.1"
	if got != want {
		t.Fatalf("extractRequestURI() = %q, want %q", got, want)
	}
}

func TestParseAccessLogLineEnhanced_FileManagerWrite(t *testing.T) {
	cfg := &config.Config{}
	line := `198.51.100.10 - - [11/Apr/2026:12:00:00 +0000] "POST /cpsess1234567/json-api/fileman/upload_files HTTP/1.1" 200 123 "-" "Mozilla/5.0" "example.com:2083"`

	findings := parseAccessLogLineEnhanced(line, cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}
	if findings[0].Check != "cpanel_file_upload_realtime" {
		t.Fatalf("check = %q, want cpanel_file_upload_realtime", findings[0].Check)
	}
	if !strings.Contains(findings[0].Message, "198.51.100.10") {
		t.Fatalf("message should contain source IP, got %q", findings[0].Message)
	}
}

func TestParseAccessLogLineEnhanced_IgnoresReadOnlyFileManagerAction(t *testing.T) {
	cfg := &config.Config{}
	line := `198.51.100.10 - - [11/Apr/2026:12:00:00 +0000] "GET /cpsess1234567/json-api/fileman/get_homedir HTTP/1.1" 200 123 "-" "Mozilla/5.0" "example.com:2083"`

	findings := parseAccessLogLineEnhanced(line, cfg)
	if len(findings) != 0 {
		t.Fatalf("expected no findings for read-only action, got %v", findings)
	}
}

func TestParseAccessLogLineEnhanced_DoesNotMatchRefererOnlyUpload(t *testing.T) {
	cfg := &config.Config{}
	line := `198.51.100.10 - - [11/Apr/2026:12:00:00 +0000] "GET /cpsess1234567/json-api/fileman/get_homedir HTTP/1.1" 200 123 "https://example.com:2083/cpsess1234567/fileman/upload_files" "Mozilla/5.0"`

	findings := parseAccessLogLineEnhanced(line, cfg)
	if len(findings) != 0 {
		t.Fatalf("expected no findings when upload appears only in referer, got %v", findings)
	}
}

func TestParseAccessLogLineEnhanced_APIFailure(t *testing.T) {
	resetPurgeTrackerState()

	cfg := &config.Config{}
	line := `198.51.100.11 - - [11/Apr/2026:12:00:00 +0000] "GET /cpsess1234567/execute/Email/list_pops HTTP/1.1" 401 0 "-" "Mozilla/5.0" "example.com:2083"`

	findings := parseAccessLogLineEnhanced(line, cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}
	if findings[0].Check != "api_auth_failure_realtime" {
		t.Fatalf("check = %q, want api_auth_failure_realtime", findings[0].Check)
	}
}

func TestParseAccessLogLineEnhanced_SuppressesPostPurge401(t *testing.T) {
	resetPurgeTrackerState()

	cfg := &config.Config{}
	ip := "198.51.100.11"
	purgeTracker.recordLogin(ip, "alice")
	purgeTracker.recordPurge("alice")

	line := `198.51.100.11 - - [11/Apr/2026:12:00:00 +0000] "GET /cpsess1234567/execute/Email/list_pops HTTP/1.1" 401 0 "-" "Mozilla/5.0" "example.com:2083"`
	findings := parseAccessLogLineEnhanced(line, cfg)
	if len(findings) != 0 {
		t.Fatalf("expected stale-session 401 to be suppressed, got %v", findings)
	}
}

func TestParseAccessLogLineEnhanced_WebmailLogin(t *testing.T) {
	cfg := &config.Config{}
	line := `198.51.100.12 - - [11/Apr/2026:12:00:00 +0000] "POST /login/?login_only=1 HTTP/1.1" 200 123 "-" "Mozilla/5.0" "mail.example.com:2096"`

	findings := parseAccessLogLineEnhanced(line, cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}
	if findings[0].Check != "webmail_login_realtime" {
		t.Fatalf("check = %q, want webmail_login_realtime", findings[0].Check)
	}
}

// CVE-2026-41940 (cPanel/WHM auth-bypass) step 1: a preauth POST to
// /login/?login_only=1 on the WHM ports (2087 SSL, 2086 plain) creates the
// session file the attacker later mutates via CRLF injection. Surface every
// non-infra POST so brute-force/recon shows up in alerts.
func TestParseAccessLogLineEnhanced_WHMLogin_Port2087(t *testing.T) {
	cfg := &config.Config{}
	line := `198.51.100.20 - - [11/Apr/2026:12:00:00 +0000] "POST /login/?login_only=1 HTTP/1.1" 200 123 "-" "Mozilla/5.0" "host.example.com:2087"`

	findings := parseAccessLogLineEnhanced(line, cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}
	if findings[0].Check != "whm_login_realtime" {
		t.Fatalf("check = %q, want whm_login_realtime", findings[0].Check)
	}
	if findings[0].Severity != alert.Warning {
		t.Fatalf("severity = %v, want Warning", findings[0].Severity)
	}
	if !strings.Contains(findings[0].Message, "198.51.100.20") {
		t.Fatalf("message should contain source IP, got %q", findings[0].Message)
	}
}

func TestParseAccessLogLineEnhanced_WHMLogin_Port2086(t *testing.T) {
	cfg := &config.Config{}
	line := `198.51.100.21 - - [11/Apr/2026:12:00:00 +0000] "POST /login/?login_only=1 HTTP/1.1" 200 123 "-" "Mozilla/5.0" "host.example.com:2086"`

	findings := parseAccessLogLineEnhanced(line, cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}
	if findings[0].Check != "whm_login_realtime" {
		t.Fatalf("check = %q, want whm_login_realtime", findings[0].Check)
	}
}

func TestParseAccessLogLineEnhanced_WHMLogin_GETIgnored(t *testing.T) {
	cfg := &config.Config{}
	line := `198.51.100.22 - - [11/Apr/2026:12:00:00 +0000] "GET /login/?login_only=1 HTTP/1.1" 200 123 "-" "Mozilla/5.0" "host.example.com:2087"`

	findings := parseAccessLogLineEnhanced(line, cfg)
	if len(findings) != 0 {
		t.Fatalf("expected no finding for GET (PoC uses POST), got %v", findings)
	}
}

func TestParseAccessLogLineEnhanced_WHMLogin_Suppression(t *testing.T) {
	cfg := &config.Config{}
	cfg.Suppressions.SuppressCpanelLogin = true
	line := `198.51.100.23 - - [11/Apr/2026:12:00:00 +0000] "POST /login/?login_only=1 HTTP/1.1" 200 123 "-" "Mozilla/5.0" "host.example.com:2087"`

	findings := parseAccessLogLineEnhanced(line, cfg)
	if len(findings) != 0 {
		t.Fatalf("expected suppression to silence WHM login alert, got %v", findings)
	}
}

// CVE-2026-41940 step 4 (cache promotion): the watchTowr PoC fires a tokenless
// GET against a token-required path so do_token_denied() rewrites the session
// JSON cache from the CRLF-injected raw file. Legitimate WHM clients always
// prefix /scripts*/* with /cpsessXXXXXX/ - the bare path is a hard signature.
func TestParseAccessLogLineEnhanced_WHMUnauthScripts_listaccts2(t *testing.T) {
	cfg := &config.Config{}
	line := `203.0.113.77 - - [11/Apr/2026:12:00:00 +0000] "GET /scripts2/listaccts HTTP/1.1" 200 0 "-" "curl/8.4.0" "host.example.com:2087"`

	findings := parseAccessLogLineEnhanced(line, cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}
	if findings[0].Check != "whm_unauth_scripts_realtime" {
		t.Fatalf("check = %q, want whm_unauth_scripts_realtime", findings[0].Check)
	}
	if findings[0].Severity != alert.Critical {
		t.Fatalf("severity = %v, want Critical", findings[0].Severity)
	}
	if !strings.Contains(findings[0].Message, "203.0.113.77") {
		t.Fatalf("message should contain source IP, got %q", findings[0].Message)
	}
}

func TestParseAccessLogLineEnhanced_WHMUnauthScripts_listaccts1(t *testing.T) {
	cfg := &config.Config{}
	line := `203.0.113.79 - - [11/Apr/2026:12:00:00 +0000] "GET /scripts/listaccts HTTP/1.1" 200 0 "-" "curl/8.4.0" "host.example.com:2087"`

	findings := parseAccessLogLineEnhanced(line, cfg)
	if len(findings) != 1 || findings[0].Check != "whm_unauth_scripts_realtime" {
		t.Fatalf("expected whm_unauth_scripts_realtime, got %v", findings)
	}
}

// Detector must catch step-4-equivalent tokenless requests to ANY WHM script
// path, not just listaccts - do_token_denied() fires path-agnostically and a
// non-naive attacker will pivot endpoints.
func TestParseAccessLogLineEnhanced_WHMUnauthScripts_OtherEndpoint(t *testing.T) {
	cfg := &config.Config{}
	line := `203.0.113.80 - - [11/Apr/2026:12:00:00 +0000] "GET /scripts2/createacct HTTP/1.1" 200 0 "-" "curl/8.4.0" "host.example.com:2087"`

	findings := parseAccessLogLineEnhanced(line, cfg)
	if len(findings) != 1 || findings[0].Check != "whm_unauth_scripts_realtime" {
		t.Fatalf("expected whm_unauth_scripts_realtime on /scripts2/createacct, got %v", findings)
	}
}

func TestParseAccessLogLineEnhanced_WHMUnauthScripts_QueryStringStripped(t *testing.T) {
	cfg := &config.Config{}
	line := `203.0.113.81 - - [11/Apr/2026:12:00:00 +0000] "GET /scripts2/listaccts?api.version=1 HTTP/1.1" 200 0 "-" "curl/8.4.0" "host.example.com:2087"`

	findings := parseAccessLogLineEnhanced(line, cfg)
	if len(findings) != 1 || findings[0].Check != "whm_unauth_scripts_realtime" {
		t.Fatalf("query string must not defeat path match, got %v", findings)
	}
}

func TestParseAccessLogLineEnhanced_WHMUnauthScripts_Port2086(t *testing.T) {
	cfg := &config.Config{}
	line := `203.0.113.82 - - [11/Apr/2026:12:00:00 +0000] "GET /scripts2/listaccts HTTP/1.1" 200 0 "-" "curl/8.4.0" "host.example.com:2086"`

	findings := parseAccessLogLineEnhanced(line, cfg)
	if len(findings) != 1 || findings[0].Check != "whm_unauth_scripts_realtime" {
		t.Fatalf("expected whm_unauth_scripts_realtime on plain WHM port, got %v", findings)
	}
}

func TestParseAccessLogLineEnhanced_WHMScripts_WithCpsessIgnored(t *testing.T) {
	cfg := &config.Config{}
	line := `198.51.100.30 - - [11/Apr/2026:12:00:00 +0000] "GET /cpsess1234567/scripts2/listaccts HTTP/1.1" 200 4096 "-" "Mozilla/5.0" "host.example.com:2087"`

	findings := parseAccessLogLineEnhanced(line, cfg)
	if len(findings) != 0 {
		t.Fatalf("legit cpsess-prefixed scripts request must not alert, got %v", findings)
	}
}

func TestParseAccessLogLineEnhanced_WHMUnauthScripts_NotWHMPort(t *testing.T) {
	cfg := &config.Config{}
	line := `203.0.113.78 - - [11/Apr/2026:12:00:00 +0000] "GET /scripts2/listaccts HTTP/1.1" 404 0 "-" "curl/8.4.0" "host.example.com:2083"`

	findings := parseAccessLogLineEnhanced(line, cfg)
	for _, f := range findings {
		if f.Check == "whm_unauth_scripts_realtime" {
			t.Fatalf("scripts check must not fire on cPanel port 2083, got %v", findings)
		}
	}
}

// Anchor port detection on the served-vhost field at end of line, not any
// occurrence of :2087 anywhere on the line. A referer URL pointing at
// :2087/foo while the request is served on port 80 must NOT trigger the
// Critical-tier finding.
func TestParseAccessLogLineEnhanced_WHMUnauthScripts_RefererPortNotMatched(t *testing.T) {
	cfg := &config.Config{}
	line := `203.0.113.83 - - [11/Apr/2026:12:00:00 +0000] "GET /scripts2/listaccts HTTP/1.1" 200 0 "https://attacker.example.com:2087/pivot" "curl/8.4.0" "host.example.com:80"`

	findings := parseAccessLogLineEnhanced(line, cfg)
	for _, f := range findings {
		if f.Check == "whm_unauth_scripts_realtime" {
			t.Fatalf("must not fire when :2087 only appears in referer, got %v", findings)
		}
	}
}

// SuppressCpanelLogin must NOT silence whm_unauth_scripts_realtime - it is
// an attack IOC, not a login alert.
func TestParseAccessLogLineEnhanced_WHMUnauthScripts_SuppressionImmune(t *testing.T) {
	cfg := &config.Config{}
	cfg.Suppressions.SuppressCpanelLogin = true
	line := `203.0.113.84 - - [11/Apr/2026:12:00:00 +0000] "GET /scripts2/listaccts HTTP/1.1" 200 0 "-" "curl/8.4.0" "host.example.com:2087"`

	findings := parseAccessLogLineEnhanced(line, cfg)
	if len(findings) != 1 || findings[0].Check != "whm_unauth_scripts_realtime" {
		t.Fatalf("login suppression must not silence attack IOC, got %v", findings)
	}
}

// Infra IP must short-circuit before either WHM detector fires. Belt-and-
// suspenders: catches a future regression of the top-level isInfraIPDaemon
// gate where someone reorders the function and lets WHM checks bypass it.
func TestParseAccessLogLineEnhanced_WHM_InfraIPSkipped(t *testing.T) {
	cfg := &config.Config{InfraIPs: []string{"10.0.0.5"}}

	loginLine := `10.0.0.5 - - [11/Apr/2026:12:00:00 +0000] "POST /login/?login_only=1 HTTP/1.1" 200 123 "-" "Mozilla/5.0" "host.example.com:2087"`
	if findings := parseAccessLogLineEnhanced(loginLine, cfg); len(findings) != 0 {
		t.Fatalf("infra IP must skip whm_login_realtime, got %v", findings)
	}

	scriptsLine := `10.0.0.5 - - [11/Apr/2026:12:00:00 +0000] "GET /scripts2/listaccts HTTP/1.1" 200 0 "-" "curl/8.4.0" "host.example.com:2087"`
	if findings := parseAccessLogLineEnhanced(scriptsLine, cfg); len(findings) != 0 {
		t.Fatalf("infra IP must skip whm_unauth_scripts_realtime, got %v", findings)
	}
}

func TestParseAccessLogBruteForce_WPLoginThresholdAndDedup(t *testing.T) {
	resetAccessLogTrackerState()

	cfg := &config.Config{}
	line := `203.0.113.50 - - [11/Apr/2026:12:00:00 +0000] "POST /wp-login.php HTTP/1.1" 200 123 "-" "Mozilla/5.0"`

	for i := 0; i < accessLogWPLoginThreshold-1; i++ {
		findings := parseAccessLogBruteForce(line, cfg)
		if len(findings) != 0 {
			t.Fatalf("expected no findings before threshold, got %v on iteration %d", findings, i+1)
		}
	}

	findings := parseAccessLogBruteForce(line, cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding at threshold, got %d: %v", len(findings), findings)
	}
	if findings[0].Check != "wp_login_bruteforce" {
		t.Fatalf("check = %q, want wp_login_bruteforce", findings[0].Check)
	}

	deduped := parseAccessLogBruteForce(line, cfg)
	if len(deduped) != 0 {
		t.Fatalf("expected no duplicate finding after alert, got %v", deduped)
	}
}

func TestParseAccessLogBruteForce_IgnoresInfraAndLoopback(t *testing.T) {
	resetAccessLogTrackerState()

	cfg := &config.Config{InfraIPs: []string{"203.0.113.60/32"}}
	infraLine := `203.0.113.60 - - [11/Apr/2026:12:00:00 +0000] "POST /wp-login.php HTTP/1.1" 200 123 "-" "Mozilla/5.0"`
	loopbackLine := `127.0.0.1 - - [11/Apr/2026:12:00:00 +0000] "POST /wp-login.php HTTP/1.1" 200 123 "-" "Mozilla/5.0"`

	if findings := parseAccessLogBruteForce(infraLine, cfg); len(findings) != 0 {
		t.Fatalf("infra IP should be ignored, got %v", findings)
	}
	if findings := parseAccessLogBruteForce(loopbackLine, cfg); len(findings) != 0 {
		t.Fatalf("loopback IP should be ignored, got %v", findings)
	}
}

func makeAccessLogLine(ip, method, path string) string {
	return fmt.Sprintf(`%s - - [14/Apr/2026:12:00:00 +0300] "%s %s HTTP/1.1" 200 123 "-" "Mozilla"`, ip, method, path)
}

func TestAccessLog_AdminPanelBruteForce_PhpMyAdmin(t *testing.T) {
	resetAccessLogTrackerState()
	cfg := &config.Config{}
	var fired bool
	for i := 0; i < accessLogWPLoginThreshold; i++ {
		line := makeAccessLogLine("203.0.113.5", "POST", "/phpmyadmin/index.php")
		for _, f := range parseAccessLogBruteForce(line, cfg) {
			if f.Check == "admin_panel_bruteforce" {
				fired = true
			}
		}
	}
	if !fired {
		t.Fatalf("expected admin_panel_bruteforce after %d POSTs to /phpmyadmin/index.php", accessLogWPLoginThreshold)
	}
}

func TestAccessLog_AdminPanelBruteForce_Joomla(t *testing.T) {
	resetAccessLogTrackerState()
	cfg := &config.Config{}
	var fired bool
	for i := 0; i < accessLogWPLoginThreshold; i++ {
		line := makeAccessLogLine("203.0.113.6", "POST", "/administrator/index.php")
		for _, f := range parseAccessLogBruteForce(line, cfg) {
			if f.Check == "admin_panel_bruteforce" {
				fired = true
			}
		}
	}
	if !fired {
		t.Fatalf("expected admin_panel_bruteforce for Joomla")
	}
}

func TestAccessLog_AdminPanelBruteForce_Suppression(t *testing.T) {
	resetAccessLogTrackerState()
	cfg := &config.Config{}
	for i := 0; i < accessLogWPLoginThreshold; i++ {
		parseAccessLogBruteForce(makeAccessLogLine("203.0.113.9", "POST", "/phpmyadmin/index.php"), cfg)
	}
	var duplicateFired bool
	for i := 0; i < 10; i++ {
		for _, f := range parseAccessLogBruteForce(makeAccessLogLine("203.0.113.9", "POST", "/phpmyadmin/index.php"), cfg) {
			if f.Check == "admin_panel_bruteforce" {
				duplicateFired = true
			}
		}
	}
	if duplicateFired {
		t.Fatalf("admin_panel_bruteforce must suppress duplicates within cooldown")
	}
}

// Drupal (/user/login) and Tomcat (/manager/html) are intentionally NOT
// covered by this detector. Drupal's path is too generic on shared hosting;
// Tomcat's attack shape is Basic auth GET/401, not POST form submission.
// Both are flagged as follow-up work in the spec. TestAccessLog_AdminPanel
// BruteForce_DoesNotMatchBarePaths pins the tight scope against future drift.
func TestAccessLog_AdminPanelBruteForce_DoesNotMatchBarePaths(t *testing.T) {
	cfg := &config.Config{}
	barePaths := []string{
		"/user/login",
		"/manager/html",
		"/admin/login.php",
		"/mysql/",
		"/phpmyadmin/",        // missing index.php
		"/phpmyadmin/foo.php", // wrong subpath
		"/administrator/",     // missing index.php
	}
	for _, path := range barePaths {
		resetAccessLogTrackerState()
		var fired bool
		for i := 0; i < accessLogWPLoginThreshold+5; i++ {
			line := makeAccessLogLine("203.0.113.50", "POST", path)
			for _, f := range parseAccessLogBruteForce(line, cfg) {
				if f.Check == "admin_panel_bruteforce" {
					fired = true
				}
			}
		}
		if fired {
			t.Errorf("path %q must NOT fire admin_panel_bruteforce (too generic / wrong attack shape)", path)
		}
	}
}

// TestAccessLog_HotPathSkipsAfterAlert pins the perf optimization that
// avoids the per-IP timestamp slice growing without bound during a sustained
// burst once the IP has already alerted. After the threshold-fire, additional
// POSTs from the same IP must NOT add to wpLoginTimes (the eviction loop
// will trim it; the alerted flag prevents re-fires regardless).
func TestAccessLog_HotPathSkipsAfterAlert(t *testing.T) {
	resetAccessLogTrackerState()
	cfg := &config.Config{}

	ip := "203.0.113.99"
	// Fire the alert.
	for i := 0; i < accessLogWPLoginThreshold; i++ {
		parseAccessLogBruteForce(makeAccessLogLine(ip, "POST", "/wp-login.php"), cfg)
	}

	val, ok := accessLogTrackers.Load(ip)
	if !ok {
		t.Fatalf("expected tracker for %s after threshold burst", ip)
	}
	tr := val.(*accessLogTracker)
	tr.mu.Lock()
	postAlertLen := len(tr.wpLoginTimes)
	alerted := tr.wpLoginAlerted
	tr.mu.Unlock()

	if !alerted {
		t.Fatalf("wpLoginAlerted should be true after threshold burst")
	}
	if postAlertLen < accessLogWPLoginThreshold {
		t.Fatalf("wpLoginTimes len = %d, want at least %d after fire", postAlertLen, accessLogWPLoginThreshold)
	}

	// Sustained burst — 1000 more POSTs from the same IP. With the perf
	// optimization, wpLoginTimes must NOT grow.
	for i := 0; i < 1000; i++ {
		parseAccessLogBruteForce(makeAccessLogLine(ip, "POST", "/wp-login.php"), cfg)
	}

	tr.mu.Lock()
	finalLen := len(tr.wpLoginTimes)
	tr.mu.Unlock()

	if finalLen != postAlertLen {
		t.Errorf("wpLoginTimes grew during alerted burst: postAlert=%d, after 1000 more POSTs=%d (want unchanged — alerted flag should short-circuit append)", postAlertLen, finalLen)
	}
}
