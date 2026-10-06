package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

func TestHtaccessGenericFindingUsesSharedCleaner(t *testing.T) {
	withSimulatedProcessSignal(t)
	root := t.TempDir()
	oldRoots, oldBackup := fixHtaccessAllowedRoots, htaccessBackupDirRoot
	fixHtaccessAllowedRoots, htaccessBackupDirRoot = []string{root}, t.TempDir()
	t.Cleanup(func() { fixHtaccessAllowedRoots, htaccessBackupDirRoot = oldRoots, oldBackup })

	cases := []struct{ name, directive, want string }{
		{"handler remap", "AddHandler application/x-httpd-php .jpg", ""},
		{"scoped proxy handler", "<FilesMatch \"\\.jpg$\">\nSetHandler proxy:unix:/run/site.sock|fcgi://localhost\n</FilesMatch>", "<FilesMatch \"\\.jpg$\">\n</FilesMatch>\n"},
		{"tamper token", "SetEnv PAYLOAD base64_decode(c29tZQ==)", ""},
		{"function restriction removed", "php_value disable_functions none", ""},
		{"prelude with a safe comment", "php_value auto_prepend_file /tmp/prelude.php # litespeed", ""},
		{"legacy WAF block", "<IfModule mod_security.c>\nSecFilterEngine Off\nSecFilterScanPOST Off\n</IfModule>", "<IfModule mod_security.c>\n</IfModule>\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeHtaccess(t, root, tc.name, tc.directive+"\n")
			findings, ranges := AuditHtaccessFile(path)
			if len(findings) == 0 || len(ranges) == 0 {
				t.Fatalf("audit findings=%+v ranges=%+v, want a cleanable finding", findings, ranges)
			}
			for _, check := range []string{"htaccess_injection", "htaccess_injection_realtime"} {
				if err := os.WriteFile(path, []byte(tc.directive+"\n"), 0644); err != nil {
					t.Fatal(err)
				}
				if v := VerifyFinding(check, "", "", path); !v.Checked || v.Resolved {
					t.Fatalf("verification before cleaning = %+v", v)
				}
				if result := ApplyFix(context.Background(), check, "", "", path); !result.Success {
					t.Fatalf("manual %s result = %+v", check, result)
				}
				if v := VerifyFinding(check, "", "", path); !v.Checked || !v.Resolved {
					t.Fatalf("verification after cleaning = %+v", v)
				}
				got, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if string(got) != tc.want {
					t.Fatalf("cleaned = %q, want %q", got, tc.want)
				}
			}
		})
	}
}

func TestHtaccessCommentedHandlerAndDefensiveRewriteStayClean(t *testing.T) {
	for _, body := range []string{
		"# AddHandler cgi-script .haxor\n",
		"RewriteCond %{QUERY_STRING} base64_decode [NC,OR]\nRewriteRule .* - [F,L]\n",
	} {
		path := filepath.Join(t.TempDir(), ".htaccess")
		if err := os.WriteFile(path, []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
		var findings []alert.Finding
		checkHtaccessFile(context.Background(), path, []string{"addhandler", "base64_decode"}, nil, &findings)
		if len(findings) != 0 {
			t.Errorf("benign content %q has findings: %+v", body, findings)
		}
	}
}

// Automatic cleaning acts on the per-pattern detectors only. The generic token
// scanner also reports directives a site may depend on, such as a PHP handler
// for .html pages; removing one of those unasked would serve the PHP source as
// text. Its findings keep the manual fix.
func TestHtaccessGenericFindingIsNotCleanedAutomatically(t *testing.T) {
	withSimulatedProcessSignal(t)
	root := t.TempDir()
	oldRoots, oldBackup := fixHtaccessAllowedRoots, htaccessBackupDirRoot
	fixHtaccessAllowedRoots, htaccessBackupDirRoot = []string{root}, t.TempDir()
	t.Cleanup(func() { fixHtaccessAllowedRoots, htaccessBackupDirRoot = oldRoots, oldBackup })
	const body = "RewriteEngine On\nAddHandler application/x-httpd-php .html\n"
	path := writeHtaccess(t, root, "public_html", body)
	cfg := &config.Config{StatePath: t.TempDir()}
	cfg.AutoResponse.Enabled, cfg.AutoResponse.CleanHtaccess = true, true
	for _, check := range []string{"htaccess_injection", "htaccess_injection_realtime", "htaccess_handler_abuse"} {
		if actions := AutoCleanHtaccess(cfg, []alert.Finding{{Check: check, FilePath: path}}); len(actions) != 0 {
			t.Errorf("%s automatic actions = %+v, want none", check, actions)
		}
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != body {
		t.Fatalf("content = %q, error = %v, want unchanged", got, err)
	}
}

func TestHtaccessOversizedResponsesPreserveFile(t *testing.T) {
	withSimulatedProcessSignal(t)
	sink := withActionSink(t)
	root, backup := t.TempDir(), t.TempDir()
	oldRoots, oldBackup := fixHtaccessAllowedRoots, htaccessBackupDirRoot
	fixHtaccessAllowedRoots, htaccessBackupDirRoot = []string{root}, backup
	t.Cleanup(func() { fixHtaccessAllowedRoots, htaccessBackupDirRoot = oldRoots, oldBackup })
	path := writeHtaccess(t, root, "site", "SecFilterEngine Off\n")
	if err := os.Truncate(path, htaccessMaxFileBytes+1); err != nil {
		t.Fatal(err)
	}
	original, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, check := range []string{"htaccess_injection", "htaccess_injection_realtime", "htaccess_security_disabled"} {
		if result := ApplyFix(context.Background(), check, "", "", path); !result.Refused || !strings.Contains(result.Error, "too large") {
			t.Errorf("oversized manual %s result = %+v, want size refusal", check, result)
		}
		if v := VerifyFinding(check, "", "", path); v.Checked || v.Resolved || !strings.Contains(v.Detail, "too large") {
			t.Errorf("oversized %s verification = %+v, want unchecked", check, v)
		}
	}
	cfg := &config.Config{StatePath: t.TempDir()}
	cfg.AutoResponse.Enabled, cfg.AutoResponse.CleanHtaccess = true, true
	findings, _ := AuditHtaccessFile(path)
	if len(findings) != 1 {
		t.Fatalf("oversized audit findings = %+v, want one coverage alert", findings)
	}
	if actions := AutoCleanHtaccess(cfg, findings); len(actions) != 0 {
		t.Errorf("oversized automatic actions = %+v, want no edit", actions)
	}
	if current, err := os.Stat(path); err != nil || !sameFileSnapshot(original, current) {
		t.Errorf("oversized file changed: current=%v error=%v", current, err)
	}
	if entries, err := os.ReadDir(backup); err != nil || len(entries) != 0 {
		t.Errorf("oversized file created backups: entries=%v error=%v", entries, err)
	}
	cleans := 0
	for _, rec := range sink.records {
		if rec.Op != "respond.clean_file" {
			continue
		}
		cleans++
		if rec.Result != actionlog.Refused {
			t.Errorf("oversized cleaning action = %s, want refused", rec.Result)
		}
	}
	// The coverage finding never reaches automatic cleaning, so it cannot
	// spend an automatic response on a refusal every scan.
	if cleans != 3 {
		t.Errorf("cleaning actions = %d, want the three manual refusals only", cleans)
	}
}

// A per-pattern finding hands the file to the cleaner, which must remove only
// the per-pattern directives. A generic finding in the same file keeps its
// manual fix, and each re-check follows the action that answers it.
func TestHtaccessAutoCleanLeavesGenericFindingsAlone(t *testing.T) {
	withSimulatedProcessSignal(t)
	root := t.TempDir()
	oldRoots, oldBackup := fixHtaccessAllowedRoots, htaccessBackupDirRoot
	fixHtaccessAllowedRoots, htaccessBackupDirRoot = []string{root}, t.TempDir()
	t.Cleanup(func() { fixHtaccessAllowedRoots, htaccessBackupDirRoot = oldRoots, oldBackup })
	const generic = "keep\nAddHandler application/x-httpd-php .html\n"
	path := writeHtaccess(t, root, "public_html", generic+"SecRuleEngine Off\n")
	cfg := &config.Config{StatePath: t.TempDir()}
	cfg.AutoResponse.Enabled, cfg.AutoResponse.CleanHtaccess = true, true

	actions := AutoCleanHtaccess(cfg, []alert.Finding{{Check: "htaccess_security_disabled", FilePath: path}})
	if len(actions) != 1 || !strings.HasPrefix(actions[0].Message, "AUTO-CLEAN: ") {
		t.Fatalf("automatic actions = %+v", actions)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != generic {
		t.Fatalf("content = %q, error = %v, want %q", got, err, generic)
	}
	if v := VerifyFinding("htaccess_security_disabled", "", "", path); !v.Checked || !v.Resolved {
		t.Errorf("per-pattern re-check after cleaning = %+v, want resolved", v)
	}
	if v := VerifyFinding("htaccess_injection", "", "", path); !v.Checked || v.Resolved {
		t.Errorf("generic re-check before its fix = %+v, want unresolved", v)
	}
	if result := ApplyFix(context.Background(), "htaccess_injection", "", "", path); !result.Success {
		t.Fatalf("manual generic fix = %+v", result)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "keep\n" {
		t.Fatalf("content after generic fix = %q, error = %v", got, err)
	}
	if v := VerifyFinding("htaccess_injection", "", "", path); !v.Checked || !v.Resolved {
		t.Errorf("generic re-check after its fix = %+v, want resolved", v)
	}
}
