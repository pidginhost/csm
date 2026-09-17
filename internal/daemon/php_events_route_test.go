package daemon

import (
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

const shieldFrontController = "/home/exampleuser/example.test/index.php"

func webshellParamLine(script, uri string) string {
	return "[2026-09-17 10:00:00] WEBSHELL_PARAM ip=192.0.2.10 script=" + script +
		" uri=" + uri + " ua=Mozilla/5.0 details=Request contains command parameter: cmd"
}

// A probe for a script that does not exist is answered by the CMS front
// controller through its rewrite rules. The command parameter never reached
// the script the request named, so there is no webshell to observe.
func TestParsePHPShieldLineIgnoresProbeRewrittenToFrontController(t *testing.T) {
	for _, uri := range []string{
		"/lib/terminal-xhr.php",
		"/icecoder/lib/terminal-xhr.php",
		"/ALFA_DATA/alfacgiapi/perl.alfa",
		"/wp-content/uploads/0xss.php?c=false%7Cmd5sum",
		"/setup.cgi?next_file=netgear.cfg&todo=syscmd&cmd=rm+-rf",
		"/admin/config?cmd=cat%20/root/.aws/credentials",
		"/tcp.php",
		"/tcp.php?cmd=id",
		"/missing-dir/?cmd=id",
		"/missing-dir/index.php?cmd=id",
		"http://example.test/tcp.php?cmd=id",
	} {
		t.Run(uri, func(t *testing.T) {
			if f := parsePHPShieldLine(webshellParamLine(shieldFrontController, uri)); f != nil {
				t.Fatalf("probe rewritten to the front controller raised %s: %s", f.Check, f.Details)
			}
		})
	}
}

// The parameter reached the script the request named, so the observation is
// real and must keep firing.
func TestParsePHPShieldLineReportsParamOnRequestedScript(t *testing.T) {
	const shell = "/home/exampleuser/example.test/wp-content/plugins/example/about.php"
	for _, tc := range []struct{ name, script, uri string }{
		{"document root index", shieldFrontController, "/?cmd=id"},
		{"document root bare", shieldFrontController, "/"},
		{"named front controller", shieldFrontController, "/index.php?cmd=id"},
		{"front controller path info", shieldFrontController, "/index.php/lib/terminal-xhr.php?cmd=id"},
		{"direct script", shell, "/wp-content/plugins/example/about.php?cmd=id"},
		{"path info", shell, "/wp-content/plugins/example/about.php/x/y.php?cmd=id"},
		{"percent encoded", shell, "/wp-content/plugins/example/ab%6Fut.php?cmd=id"},
		{"dot segments", shell, "/wp-content/x/../plugins//example/./about.php?cmd=id"},
		{"subdirectory index", "/home/exampleuser/example.test/blog/index.php", "/blog/?cmd=id"},
		{"subdirectory index without slash", "/home/exampleuser/example.test/blog/index.php", "/blog?cmd=id"},
		{"user directory", "/home/exampleuser/public_html/shell.php", "/~exampleuser/shell.php?cmd=id"},
		{"absolute form", shell, "http://example.test/wp-content/plugins/example/about.php?cmd=id"},
		{"no request uri", shieldFrontController, "-"},
		{"invalid escape", shieldFrontController, "/tcp%zz.php?cmd=id"},
		{"relative request", shieldFrontController, "*"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := parsePHPShieldLine(webshellParamLine(tc.script, tc.uri))
			if f == nil {
				t.Fatalf("parameter on the requested script %s via %s raised nothing", tc.script, tc.uri)
			}
			if f.Check != "php_shield_webshell" || f.Severity != alert.Warning || f.FilePath != tc.script {
				t.Fatalf("finding = %+v", f)
			}
		})
	}
}

// Shield events from before the request URI was sent carry no uri field.
// Without it there is no evidence of a rewrite, so the event still fires.
func TestParsePHPShieldLineReportsParamWithoutURIField(t *testing.T) {
	line := "[2026-09-17 10:00:00] WEBSHELL_PARAM ip=192.0.2.10 script=" + shieldFrontController + " details=cmd"
	if f := parsePHPShieldLine(line); f == nil {
		t.Fatal("event without a request URI raised nothing")
	}
}

// The Shield truncates the URI it sends. When the cut falls inside the path the
// named script is unknown, so a padded path must not buy silence.
func TestParsePHPShieldLineReportsParamWhenURIPathTruncated(t *testing.T) {
	uri := "/wp-content/plugins/" + strings.Repeat("a", phpShieldURIMaxBytes)
	uri = uri[:phpShieldURIMaxBytes]
	if f := parsePHPShieldLine(webshellParamLine(shieldFrontController, uri)); f == nil {
		t.Fatal("truncated request path raised nothing")
	}
}

// A block is decided from the executing script's own source, not from what the
// request named. A rewrite into a planted shell is still a stopped webshell.
func TestParsePHPShieldLineBlockedWebshellIgnoresRequestPath(t *testing.T) {
	line := "[2026-09-17 10:00:00] BLOCK_WEBSHELL ip=192.0.2.10 " +
		"script=/home/exampleuser/example.test/wp-content/plugins/example/about.php " +
		"uri=/some/rewritten/route?cmd=id ua=curl details=Command parameter with exec sink: cmd"
	f := parsePHPShieldLine(line)
	if f == nil || f.Severity != alert.Critical || f.Check != "php_shield_webshell" {
		t.Fatalf("blocked webshell reached through a rewrite = %+v", f)
	}
}
