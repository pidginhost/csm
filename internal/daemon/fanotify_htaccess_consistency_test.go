//go:build linux

package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

func TestCheckHtaccessHarmlessPrependSettingsStayClean(t *testing.T) {
	for _, body := range []string{
		"php_value auto_prepend_file none\n",
		"php_value auto_append_file /etc/csm-prelude.php\n",
		"SetEnv NOTE auto_prepend_file\n",
	} {
		t.Run(body, func(t *testing.T) { expectNoHtaccessAlert(t, body) })
	}
}

func TestCheckHtaccessTamperTokenCannotHideInSafeComment(t *testing.T) {
	expectHtaccessAlert(t, "SetEnv PAYLOAD base64_decode(c29tZQ==) # litespeed\n", "htaccess_injection_realtime")
}

func TestCheckHtaccessLegacyWAFBlockIsHigh(t *testing.T) {
	fd, path := writeHtaccess(t, "<IfModule mod_security.c>\nSecFilterEngine Off\nSecFilterScanPOST Off\n</IfModule>\n")
	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkHtaccess(fd, path, "fixture")
	if len(ch) != 1 {
		// Realtime emits one finding per check and file, even when both
		// engine and POST scanning are disabled in the same write.
		t.Fatalf("realtime findings = %d, want 1", len(ch))
	}
	f := <-ch
	if f.Check != "htaccess_security_disabled" || f.Severity != alert.High || f.FilePath != path {
		t.Fatalf("legacy WAF finding = %+v, want High with the event path", f)
	}
}

// The variable name is no evidence: Apache expands an E= name before setting
// it, so a request header can supply PHP_VALUE. Any line carrying a prelude
// target is judged by that target.
func TestCheckHtaccessPreludeThroughEnvironmentAlerts(t *testing.T) {
	for _, body := range []string{
		"SetEnv PHP_VALUE \"auto_prepend_file=/tmp/x.php\"\n",
		"RewriteRule .* - [E=PHP_VALUE:auto_prepend_file=/tmp/x.php]\n",
		"RewriteCond %{HTTP:X-N} (.+)\nRewriteRule .* - [E=%1:auto_prepend_file=/tmp/x.php]\n",
		"SetEnv NOTE 'auto_prepend_file /tmp/example.php'\n",
	} {
		t.Run(body, func(t *testing.T) { expectHtaccessAlert(t, body, "htaccess_injection_realtime") })
	}
}

// Realtime findings reach automatic quarantine but not automatic cleaning, so
// the generic handler-abuse finding keeps the realtime name there: a write must
// never move the whole .htaccess out of the site.
func TestCheckHtaccessHandlerAbuseUsesRealtimeName(t *testing.T) {
	fd, path := writeHtaccess(t, "AddHandler cgi-script .haxor\n")
	ch := make(chan alert.Finding, 8)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkHtaccess(fd, path, "fixture")
	close(ch)
	var realtime int
	for f := range ch {
		if f.Check == "htaccess_handler_abuse" {
			t.Errorf("realtime emitted %s: %+v", f.Check, f)
		}
		if f.Check == "htaccess_injection_realtime" && f.Severity == alert.Critical {
			realtime++
		}
	}
	if realtime != 1 {
		t.Errorf("critical htaccess_injection_realtime findings = %d, want 1", realtime)
	}
}
