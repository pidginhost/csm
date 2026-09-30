//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// checkHtaccess historically used a loose-substring safe list
// ("wordfence-waf.php", "litespeed", "advanced-headers.php", "rsssl")
// that any attacker could satisfy with a trailing comment token. These
// tests pin the expected behaviour after the fix: exclusions are anchored
// to the directive target (the filename the directive points at), and the
// RewriteCond defensive context is recognised structurally.

func writeHtaccess(t *testing.T, body string) (fd int, path string) {
	t.Helper()
	dir := t.TempDir()
	path = filepath.Join(dir, ".htaccess")
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	return openRawFd(t, path), path
}

func expectHtaccessAlert(t *testing.T, body, wantCheck string) {
	t.Helper()
	fd, path := writeHtaccess(t, body)
	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkHtaccess(fd, path, "pi")
	select {
	case a := <-ch:
		if a.Check != wantCheck {
			t.Errorf("got %s, want %s (body=%q)", a.Check, wantCheck, body)
		}
	case <-time.After(150 * time.Millisecond):
		t.Errorf("expected %s alert for body=%q", wantCheck, body)
	}
}

func expectNoHtaccessAlert(t *testing.T, body string) {
	t.Helper()
	fd, path := writeHtaccess(t, body)
	expectNoHtaccessAlertFromFD(t, fd, path, body)
}

func expectNoHtaccessAlertFromFD(t *testing.T, fd int, path, body string) {
	t.Helper()
	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkHtaccess(fd, path, "pi")
	select {
	case a := <-ch:
		t.Errorf("unexpected %s for body=%q: %+v", a.Check, body, a)
	case <-time.After(80 * time.Millisecond):
		// No alert - correct.
	}
}

func TestCheckHtaccess_LooseTokenNoLongerSuppressesMaliciousAutoPrepend(t *testing.T) {
	// Attacker pastes "litespeed" and "rsssl" into a comment on the
	// directive line. The prior loose-substring safe list accepted
	// these as safety hints. They carry no structural meaning and must
	// no longer suppress the alert.
	expectHtaccessAlert(t, "php_value auto_prepend_file /tmp/evil.php # litespeed\n", "htaccess_injection_realtime")
	expectHtaccessAlert(t, "php_value auto_prepend_file /tmp/evil.php # rsssl\n", "htaccess_injection_realtime")
}

func TestCheckHtaccess_LegitWordfenceDirective(t *testing.T) {
	// Production shape: Wordfence writes the directive target
	// under the account's public_html as wordfence-waf.php. Anchored
	// regex must keep this silent.
	expectNoHtaccessAlert(t, "php_value auto_prepend_file '/home/user/public_html/wordfence-waf.php'\n")
	expectNoHtaccessAlert(t, "\tphp_value auto_prepend_file '/home/user/public_html/wordfence-waf.php'\n")
}

func TestCheckHtaccess_LegitReallySimpleSSLDirective(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".htaccess")
	body := "php_value auto_prepend_file " + filepath.Join(dir, "wp-content", "advanced-headers.php") + "\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	expectNoHtaccessAlertFromFD(t, openRawFd(t, path), path, body)
}

func TestCheckHtaccess_UnboundReallySimpleSSLDirective(t *testing.T) {
	// Retained preludes still need an alert, including targets outside the
	// usual account roots. The generic realtime scan excuses the filename,
	// so this assertion must see the hardened detector's finding.
	expectHtaccessAlert(t, "php_value auto_prepend_file /srv/example/wp-content/advanced-headers.php\n", "htaccess_auto_prepend")
}

func TestCheckHtaccess_LegitReallySimpleSSLRewriteCondBase64Defense(t *testing.T) {
	// Really Simple SSL and other hardening plugins write RewriteCond
	// blocks that filter out attacker payloads referencing base64_*.
	// The literal token base64_decode inside a RewriteCond/RewriteRule is
	// a regex pattern blocking attack queries, not a PHP function call.
	expectNoHtaccessAlert(t, "RewriteCond %{QUERY_STRING} base64_decode [NC,OR]\n")
	expectNoHtaccessAlert(t, "RewriteRule \\b(eval\\(|base64_decode) - [F,L]\n")
}

func TestCheckHtaccess_BarePHPEvalOutsideRewriteStillFires(t *testing.T) {
	// Outside a Rewrite directive, eval( / base64_decode in .htaccess
	// is a tamper signal regardless of other content on the line.
	expectHtaccessAlert(t, "SetEnv PAYLOAD base64_decode(c29tZQ==)\n", "htaccess_injection_realtime")
}
