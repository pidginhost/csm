package daemon

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

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
