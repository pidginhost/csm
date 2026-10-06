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
			cfg := &config.Config{StatePath: t.TempDir()}
			cfg.AutoResponse.Enabled, cfg.AutoResponse.CleanHtaccess = true, true
			for _, check := range []string{"htaccess_injection", "htaccess_injection_realtime"} {
				for _, automatic := range []bool{false, true} {
					if err := os.WriteFile(path, []byte(tc.directive+"\n"), 0644); err != nil {
						t.Fatal(err)
					}
					if v := VerifyFinding(check, "", "", path); !v.Checked || v.Resolved {
						t.Fatalf("verification before cleaning = %+v", v)
					}
					if automatic {
						actions := AutoCleanHtaccess(cfg, []alert.Finding{{Check: check, FilePath: path}})
						if len(actions) != 1 || !strings.HasPrefix(actions[0].Message, "AUTO-CLEAN: ") {
							t.Fatalf("automatic %s actions = %+v", check, actions)
						}
					} else if result := ApplyFix(context.Background(), check, "", "", path); !result.Success {
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

func TestHtaccessResponseUsesCleanSettingInsteadOfQuarantine(t *testing.T) {
	withSimulatedProcessSignal(t)
	root := t.TempDir()
	oldRoots, oldBackup := fixHtaccessAllowedRoots, htaccessBackupDirRoot
	fixHtaccessAllowedRoots, htaccessBackupDirRoot = []string{root}, t.TempDir()
	t.Cleanup(func() { fixHtaccessAllowedRoots, htaccessBackupDirRoot = oldRoots, oldBackup })
	path := writeHtaccess(t, root, "site", "AddHandler cgi-script .haxor\n")
	cfg := &config.Config{StatePath: t.TempDir()}
	cfg.AutoResponse.Enabled, cfg.AutoResponse.QuarantineFiles = true, true
	findings := []alert.Finding{{Severity: alert.Critical, Check: "htaccess_handler_abuse", FilePath: path}}
	if actions := AutoQuarantineFiles(cfg, findings); len(actions) != 0 {
		t.Fatalf("quarantine actions = %+v, want none for .htaccess findings", actions)
	}
	if findings[0].AutoFileResponseEvaluated {
		t.Fatal("quarantine consumed a finding that belongs to automatic htaccess cleaning")
	}
	if actions := AutoCleanHtaccess(cfg, findings); len(actions) != 0 {
		t.Fatalf("cleaning disabled: actions = %+v", actions)
	}
	cfg.AutoResponse.CleanHtaccess = true
	if actions := AutoCleanHtaccess(cfg, findings); len(actions) != 1 || !strings.HasPrefix(actions[0].Message, "AUTO-CLEAN: ") {
		t.Fatalf("cleaning enabled: actions = %+v", actions)
	}
	if got, err := os.ReadFile(path); err != nil || len(got) != 0 {
		t.Fatalf("cleaned content = %q, error = %v", got, err)
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
	if cleans != 4 {
		t.Errorf("cleaning actions = %d, want three manual refusals and one automatic refusal", cleans)
	}
}
