package daemon

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
)

const shieldFrontController = "/home/exampleuser/example.test/index.php"

func webshellParamLine(script, uri string) string {
	digest := "-"
	if body, err := os.ReadFile(script); err == nil {
		digest = fmt.Sprintf("%x", sha256.Sum256(body))
	}
	return "[2026-09-17 10:00:00] WEBSHELL_PARAM sha256=" + digest + " ip=192.0.2.10 script=" + script +
		" uri=" + uri + " ua=Mozilla/5.0 details=Request contains command parameter: cmd"
}

// A mismatched probe can be quieted when the executing controller has
// verified CMS content. Its raw observation must still be archived.
func TestParsePHPShieldLineIgnoresProbeRewrittenToFrontController(t *testing.T) {
	script := verifiedShieldFrontController(t)
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
			if f := parsePHPShieldLine(webshellParamLine(script, uri)); f != nil {
				t.Fatalf("probe rewritten to the front controller raised %s: %s", f.Check, f.Details)
			}
		})
	}
}

// Suppression needs content evidence. A rewrite can invoke a planted shell,
// including one named index.php, without ever naming that file in the URI.
func TestPHPShieldRewriteRetainsUnverifiedScript(t *testing.T) {
	for _, name := range []string{"index.php", "shell.php", "addon/index.php"} {
		t.Run(name, func(t *testing.T) {
			script := filepath.Join(t.TempDir(), "public_html", name)
			if err := os.MkdirAll(filepath.Dir(script), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(script, []byte("<?php system($_REQUEST['cmd']);"), 0o600); err != nil {
				t.Fatal(err)
			}
			if f := parsePHPShieldLine(webshellParamLine(script, "/missing.php?cmd=id")); f == nil || f.Severity != alert.Warning {
				t.Fatalf("rewritten command observation lost: %+v", f)
			}
		})
	}
}

func verifiedShieldFrontController(t *testing.T) string {
	t.Helper()
	// Model the cache populated after CMS core verification. The unique comment
	// keeps this entry independent of other tests sharing the process cache.
	body := []byte("<?php /* " + t.Name() + " */ require __DIR__ . '/wp-blog-header.php';")
	script := filepath.Join(t.TempDir(), "index.php")
	if err := os.WriteFile(script, body, 0o600); err != nil {
		t.Fatal(err)
	}
	checks.GlobalCMSCache().Add(fmt.Sprintf("%x", sha256.Sum256(body)), int64(len(body)))
	return script
}

func TestPHPShieldRewriteRechecksContent(t *testing.T) {
	script := verifiedShieldFrontController(t)
	line := webshellParamLine(script, "/missing.php?cmd=id")
	if f := parsePHPShieldLine(line); f != nil {
		t.Fatalf("verified controller raised a probe finding: %+v", f)
	}
	info, err := os.Stat(script)
	if err != nil {
		t.Fatal(err)
	}
	body := "<?php system($_REQUEST['cmd']);"
	body += strings.Repeat(" ", int(info.Size())-len(body))
	if err := os.WriteFile(script, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(script, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	if f := parsePHPShieldLine(webshellParamLine(script, "/missing.php?cmd=id")); f == nil || f.Severity != alert.Warning {
		t.Fatalf("same-size modified controller lost its observation: %+v", f)
	}
}

func TestPHPShieldRewriteUsesEventContent(t *testing.T) {
	script := verifiedShieldFrontController(t)
	clean, err := os.ReadFile(script)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(script, []byte("<?php system($_REQUEST['cmd']);"), 0o600); err != nil {
		t.Fatal(err)
	}
	line := webshellParamLine(script, "/missing.php?cmd=id")
	if err := os.WriteFile(script, clean, 0o600); err != nil {
		t.Fatal(err)
	}
	if f := parsePHPShieldLine(line); f == nil {
		t.Fatal("restoring the controller concealed the queued shell observation")
	}
}

func TestPHPShieldLegacyEventCannotBorrowContentProof(t *testing.T) {
	script := verifiedShieldFrontController(t)
	body, err := os.ReadFile(script)
	if err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(body))
	for _, suffix := range []string{
		"uri=/missing.php?cmd=id ua=curl details=cmd",
		"uri=/missing.php?cmd=id&sha256=" + digest + " ua=curl details=cmd",
		"uri=/missing.php?cmd=id ua=curl sha256=" + digest + " details=cmd",
	} {
		line := "[2026-09-17 10:00:00] WEBSHELL_PARAM ip=192.0.2.10 script=" + script + " " + suffix
		if f := parsePHPShieldLine(line); f == nil {
			t.Fatal("legacy or attacker-supplied fields concealed an observation")
		}
	}
}

func TestPHPShieldRewriteRetainsMissingScript(t *testing.T) {
	script := filepath.Join(t.TempDir(), "index.php")
	if f := parsePHPShieldLine(webshellParamLine(script, "/missing.php?cmd=id")); f == nil {
		t.Fatal("unreadable script lost its observation")
	}
}

func TestPHPShieldVerifiedDirectRequestStillAlerts(t *testing.T) {
	script := verifiedShieldFrontController(t)
	for _, uri := range []string{
		"/", "/index.php?cmd=id", "/index.php/extra?cmd=id", "/%69ndex.php?cmd=id",
		"/x/../index.php?cmd=id", "/~exampleuser/index.php?cmd=id",
		"http://[2001:db8::1]/index.php?cmd=id",
	} {
		if f := parsePHPShieldLine(webshellParamLine(script, uri)); f == nil || f.Severity != alert.Warning || f.FilePath != script || f.SourceIP != "192.0.2.10" {
			t.Fatalf("direct request %q lost its observation: %+v", uri, f)
		}
	}
}

func TestPHPShieldVerifiedContentDoesNotQuietOtherEvents(t *testing.T) {
	script := verifiedShieldFrontController(t)
	for _, event := range []struct {
		name  string
		check string
		level alert.Severity
	}{
		{"BLOCK_WEBSHELL", "php_shield_webshell", alert.Critical},
		{"BLOCK_PATH", "php_shield_block", alert.Critical},
		{"EVAL_FATAL", "php_shield_eval", alert.High},
	} {
		line := strings.Replace(webshellParamLine(script, "/missing.php?cmd=id"), "WEBSHELL_PARAM", event.name, 1)
		f, quiet := parsePHPShieldEventLine(line)
		if quiet || f == nil || f.Severity != event.level || f.Check != event.check {
			t.Fatalf("%s event changed: quiet=%v finding=%+v", event.name, quiet, f)
		}
	}
}

func TestPHPShieldRewrittenProbeIsArchived(t *testing.T) {
	script := verifiedShieldFrontController(t)
	line := webshellParamLine(script, "/missing.php?cmd=id")
	archive := filepath.Join(t.TempDir(), "events.log")
	alerts := make(chan alert.Finding, 1)
	processed, err := processPHPShieldEventPacket([]byte(line+"\n"), archive, nil, alerts)
	if err != nil || !processed {
		t.Fatalf("observation not processed: processed=%v err=%v", processed, err)
	}
	got, err := os.ReadFile(archive)
	if err != nil || string(got) != line+"\n" {
		t.Fatalf("observation missing from archive: %q, %v", got, err)
	}
	if len(alerts) != 0 {
		t.Fatal("verified probe emitted an alert")
	}
	processed, err = processPHPShieldEventPacket([]byte(line), filepath.Join(t.TempDir(), "missing", "events.log"), nil, alerts)
	if err == nil || !processed || len(alerts) != 0 {
		t.Fatalf("quiet archive failure was lost: processed=%v err=%v alerts=%d", processed, err, len(alerts))
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
		{"addon document root", "/home/exampleuser/public_html/addon/index.php", "/index.php?cmd=id"},
		{"addon root directory", "/home/exampleuser/public_html/addon/index.php", "/?cmd=id"},
		{"addon script", "/home/exampleuser/public_html/addon/shell.php", "/shell.php?cmd=id"},
		{"encoded separators", shell, "/wp-content%2Fplugins%2Fexample%2Fabout.php?cmd=id"},
		{"encoded dot segments", shell, "/wp-content/x/%2e%2e/plugins/example/about.php?cmd=id"},
		{"encoded userdir", "/home/exampleuser/public_html/shell.php", "/%7eexampleuser/shell.php/extra?cmd=id"},
		{"literal percent filename", "/home/exampleuser/public_html/a%20b.php", "/a%2520b.php?cmd=id"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !phpShieldRequestReachedScript(tc.script, tc.uri) {
				t.Fatal("request matcher missed the executing script")
			}
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

func TestPHPShieldRequestAmbiguityRetainsObservation(t *testing.T) {
	script := verifiedShieldFrontController(t)
	for _, uri := range []string{
		"http:///missing.php?cmd=id",
		"ftp://example.test/missing.php?cmd=id",
		"http://[invalid]/missing.php?cmd=id",
		"/missing%00.php?cmd=id",
		"/missing%0a.php?cmd=id",
		"/missing\\index.php?cmd=id",
		"/missing.php#fragment?cmd=id",
		"/missing.php " + strings.Repeat(" ", phpShieldURIMaxBytes-len("/missing.php ")),
	} {
		t.Run(uri, func(t *testing.T) {
			if f := parsePHPShieldLine(webshellParamLine(script, uri)); f == nil {
				t.Fatal("ambiguous request lost its observation")
			}
		})
	}
}

func TestPHPShieldPathComparisonBoundaries(t *testing.T) {
	for _, tc := range []struct{ script, uri string }{
		{shieldFrontController, "/INDEX.php?cmd=id"},
		{shieldFrontController, "/Index.php?cmd=id"},
		{shieldFrontController, "/missing/index.php?cmd=id"},
		{shieldFrontController, "/index.php.other?cmd=id"},
		{shieldFrontController, "/otherindex.php?cmd=id"},
		{shieldFrontController, "/%2569ndex.php?cmd=id"},
		{"/home/exampleuser/public_html/addon/index.php", "/missing/index.php?cmd=id"},
		{"/home/exampleuser/public_html/addon/index.php", "/~exampleuser/missing.php?cmd=id"},
		{"/home/exampleuser/public_html/myblog/index.php", "/blog/?cmd=id"},
	} {
		if phpShieldRequestReachedScript(tc.script, tc.uri) {
			t.Errorf("%q incorrectly names %q", tc.uri, tc.script)
		}
	}
}

func TestPHPShieldTruncatedURIWithCompletePath(t *testing.T) {
	script := verifiedShieldFrontController(t)
	uri := "/missing.php?cmd=" + strings.Repeat("x", phpShieldURIMaxBytes)
	if f := parsePHPShieldLine(webshellParamLine(script, uri[:phpShieldURIMaxBytes])); f != nil {
		t.Fatalf("complete mismatched path raised a finding: %+v", f)
	}
	uri = "/missing/" + strings.Repeat("x", phpShieldURIMaxBytes)
	if f := parsePHPShieldLine(webshellParamLine(script, uri[:phpShieldURIMaxBytes])); f == nil {
		t.Fatal("truncated path lost its observation")
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
