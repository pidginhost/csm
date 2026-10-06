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
		"SetEnv NOTE 'auto_prepend_file /tmp/example.php'\n",
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
