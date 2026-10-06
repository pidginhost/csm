package checks

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

func TestHtaccessEnvironmentPreludeUsesTargetBoundaries(t *testing.T) {
	for _, body := range []string{
		"SetEnv PHP_VALUE \"auto_prepend_file=none\"\n",
		"SetEnv PHP_VALUE 'auto_append_file=/etc/csm-prelude.php'\n",
		"SetEnv PHP_VALUE \"auto_prepend_file=\\\"/etc/csm/prelude file.php\\\"\"\n",
		"RewriteRule .* - [E=PHP_VALUE:auto_prepend_file=none]\n",
		"RewriteRule .* - [E=PHP_VALUE:auto_append_file=/etc/csm-prelude.php,L]\n",
		"RewriteRule .* - [E=%1:auto_prepend_file=/home/example/public_html/wordfence-waf.php]\n",
		"RewriteRule .* - \"[E=PHP_VALUE:auto_prepend_file='/etc/csm/prelude file.php',L]\"\n",
		"RewriteRule .* - \"[E=PHP_VALUE:auto_prepend_file=none]\"\n",
	} {
		t.Run(body, func(t *testing.T) {
			path := writeHtaccess(t, t.TempDir(), "site", body)
			findings, ranges := AuditHtaccessFile(path)
			if len(findings) != 0 || len(ranges) != 0 {
				t.Errorf("harmless target: findings=%+v ranges=%v", findings, ranges)
			}
			var scheduled []alert.Finding
			checkHtaccessFile(context.Background(), path, htaccessSuspiciousPatterns, htaccessSafePatterns, &scheduled)
			if len(scheduled) != 0 {
				t.Errorf("harmless target: scheduled findings=%+v", scheduled)
			}
		})
	}
}

func TestHtaccessEnvironmentPreludePreservesTargetPunctuation(t *testing.T) {
	for _, body := range []string{
		"SetEnv PHP_VALUE \"auto_prepend_file=/tmp/wordfence-waf.php,payload\"\n",
		"SetEnv PHP_VALUE \"auto_append_file=/tmp/wordfence-waf.php]payload\"\n",
	} {
		t.Run(body, func(t *testing.T) {
			path := writeHtaccess(t, t.TempDir(), "site", body)
			findings, ranges := AuditHtaccessFile(path)
			if countByCheck(findings, "htaccess_injection") != 1 || len(ranges) != 1 {
				t.Errorf("suspicious target: findings=%+v ranges=%v", findings, ranges)
			}
		})
	}
}

func TestHtaccessEnvironmentPreludeChecksEveryTarget(t *testing.T) {
	root := setupHtaccessCleanRoots(t)
	for _, body := range []string{
		"RewriteRule .* - [E=NOTE:auto_prepend_file='/etc/csm-prelude.php',E=PHP_VALUE:auto_append_file=/tmp/x.php]\n",
		"RewriteRule \"^auto_prepend_file '/etc/csm-prelude.php'$\" - [E=%1:auto_append_file=/tmp/x.php]\n",
	} {
		t.Run(body, func(t *testing.T) {
			path := writeHtaccess(t, root, "site", body)
			findings, ranges := AuditHtaccessFile(path)
			if countByCheck(findings, "htaccess_injection") == 0 || len(ranges) != 1 {
				t.Errorf("hidden target: findings=%+v ranges=%v", findings, ranges)
			}
			var scheduled []alert.Finding
			checkHtaccessFile(context.Background(), path, htaccessSuspiciousPatterns, htaccessSafePatterns, &scheduled)
			if countByCheck(scheduled, "htaccess_injection") == 0 {
				t.Errorf("hidden target: scheduled findings=%+v", scheduled)
			}
			if v := VerifyFinding("htaccess_injection_realtime", "", "", path); !v.Checked || v.Resolved {
				t.Errorf("hidden target: verification=%+v", v)
			}
			if result := ApplyFix(context.Background(), "htaccess_injection_realtime", "", "", path); !result.Success {
				t.Errorf("hidden target: manual fix=%+v", result)
			}
			if got, err := os.ReadFile(path); err != nil || len(got) != 0 {
				t.Errorf("cleaned content=%q error=%v", got, err)
			}
		})
	}
}

func TestHtaccessPreludeTargetCannotTriggerHandlerAbuse(t *testing.T) {
	for _, body := range []string{
		"SetEnv PHP_VALUE \"auto_prepend_file=/etc/addhandler.haxor.php\"\n",
		"RewriteCond %{REQUEST_URI} addhandler.haxor [NC]\nRewriteRule .* - [F,L]\n",
	} {
		t.Run(body, func(t *testing.T) {
			path := writeHtaccess(t, t.TempDir(), "site", body)
			findings, ranges := AuditHtaccessFile(path)
			if len(findings) != 0 || len(ranges) != 0 {
				t.Errorf("inert handler text: findings=%+v ranges=%v", findings, ranges)
			}
		})
	}
}

func TestHtaccessPluginPreludeRetainsDirectiveWithTargetInComment(t *testing.T) {
	root := setupHtaccessCleanRoots(t)
	const body = "php_value auto_prepend_file /home/example/other/wp-content/advanced-headers.php # auto_append_file /tmp/x.php\n"
	path := writeHtaccess(t, root, "site", body)
	findings, ranges := AuditHtaccessFile(path)
	if countByCheck(findings, "htaccess_auto_prepend") != 1 || countByCheck(findings, "htaccess_injection") != 0 || len(ranges) != 0 {
		t.Errorf("retained prepend: findings=%+v ranges=%v", findings, ranges)
	}
}

func TestHtaccessEnvironmentPreludeCleanRemovesConditionChain(t *testing.T) {
	root := setupHtaccessCleanRoots(t)
	const before = "RewriteCond %{REQUEST_URI} ^/allowed$\nRewriteRule .* - [L]\n"
	const keep = "RewriteRule ^index.php$ - [L]\n"
	const malicious = "RewriteCond %{HTTP:X-N} \\\n(.+)\n# condition still applies\n\nRewriteRule .* - [E=%1:auto_prepend_file=/tmp/x.php]\n"
	path := writeHtaccess(t, root, "site", before+malicious+keep)
	if result := ApplyFix(context.Background(), "htaccess_injection_realtime", "", "", path); !result.Success {
		t.Fatalf("manual fix=%+v", result)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != before+keep {
		t.Errorf("cleaned content=%q error=%v, want %q", got, err, before+keep)
	}
}

// PHP-FPM reads PHP_VALUE from the FastCGI parameters, and Apache passes
// environment variables through as parameters, so a prelude set through an
// environment variable runs like php_value does. The variable name is no
// evidence either: Apache expands an E= name, so a request header can supply
// it. The target is the evidence wherever the line carries one.
var htaccessPreludeThroughEnvironment = []string{
	"SetEnv PHP_VALUE \"auto_prepend_file=/tmp/x.php\"\n",
	"RewriteRule .* - [E=PHP_VALUE:auto_prepend_file=/tmp/x.php]\n",
	"RewriteCond %{HTTP:X-N} (.+)\nRewriteRule .* - [E=%1:auto_prepend_file=/tmp/x.php]\n",
}

func TestHtaccessPreludeThroughEnvironmentIsReported(t *testing.T) {
	for _, body := range htaccessPreludeThroughEnvironment {
		path := filepath.Join(t.TempDir(), ".htaccess")
		if err := os.WriteFile(path, []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
		var findings []alert.Finding
		checkHtaccessFile(context.Background(), path, []string{"auto_prepend_file"}, nil, &findings)
		if countByCheck(findings, "htaccess_injection") != 1 {
			t.Errorf("scheduled findings for %q = %+v, want one htaccess_injection", body, findings)
		}
	}
}

// Really Simple Security writes its prelude as a php_value directive; that is
// the only form kept out of cleaning. Its filename behind an environment
// variable is an ordinary prelude, so the finding is cleanable.
func TestHtaccessPluginPreludeNameThroughEnvironmentIsCleanable(t *testing.T) {
	findings, ranges := AuditHtaccessContent("/home/example/public_html/.htaccess",
		[]byte("SetEnv PHP_VALUE \"auto_prepend_file=/home/example/other/wp-content/advanced-headers.php\"\n"))
	if got := countByCheck(findings, "htaccess_injection"); got != 1 {
		t.Errorf("findings = %+v, want one htaccess_injection", findings)
	}
	if len(ranges) != 1 {
		t.Errorf("removal ranges = %v, want the directive", ranges)
	}
}
