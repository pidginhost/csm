package checks

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

func TestHtaccessHandlerAbuseRequiresExtensionArgument(t *testing.T) {
	root := setupHtaccessCleanRoots(t)
	for _, body := range []string{
		"AddHandler x-custom.haxor .html\n",
		"AddHandler x-custom .html # .haxor\n",
		"AddHandler x-custom .haxor-backup\n",
		"AddHandler x-custom.haxor\n",
		"AddHandler \"x-custom .haxor\" .html\n",
		"AddHandler x-custom \".html .haxor\"\n",
	} {
		t.Run(body, func(t *testing.T) {
			path := writeHtaccess(t, root, "public_html", body)
			var scheduled []alert.Finding
			checkHtaccessFile(context.Background(), path, htaccessSuspiciousPatterns, htaccessSafePatterns, &scheduled)
			if got := countByCheck(scheduled, "htaccess_handler_abuse"); got != 0 {
				t.Errorf("scheduled handler findings = %d, want none", got)
			}
			if findings, _ := AuditHtaccessFile(path); countByCheck(findings, "htaccess_handler_abuse") != 0 {
				t.Errorf("audit reported handler abuse: %+v", findings)
			}
			if findings, ranges := auditHtaccessPatterns(path, []byte(body)); len(findings) != 0 || len(ranges) != 0 {
				t.Errorf("automatic audit findings=%+v ranges=%v, want neither", findings, ranges)
			}
			if result := CleanHtaccessFile(path); result.Success {
				t.Errorf("cleaner removed inert handler text: %+v", result)
			}
			if got, err := os.ReadFile(path); err != nil || string(got) != body {
				t.Fatalf("content=%q error=%v, want unchanged", got, err)
			}
		})
	}
}

func TestHtaccessHandlerAbuseReportsOneFindingPerDirective(t *testing.T) {
	root := setupHtaccessCleanRoots(t)
	for _, directive := range []string{
		"AddHandler x-custom .haxor .cgix .suspected .haxor\n",
		"AddHandler x-custom HAXOR cgix\n",
		"AddHandler x-custom \".haxor\" \\\n.cgix\n",
	} {
		t.Run(directive, func(t *testing.T) {
			const keep = "RewriteEngine On\nAddHandler application/x-httpd-php .html\n"
			path := writeHtaccess(t, root, "public_html", keep+directive)
			var scheduled []alert.Finding
			checkHtaccessFile(context.Background(), path, htaccessSuspiciousPatterns, htaccessSafePatterns, &scheduled)
			if got := countByCheck(scheduled, "htaccess_handler_abuse"); got != 1 {
				t.Errorf("scheduled handler findings=%d, want one", got)
			}
			if findings, _ := AuditHtaccessFile(path); countByCheck(findings, "htaccess_handler_abuse") != 1 {
				t.Errorf("audit handler findings=%+v, want one", findings)
			}
			findings, ranges := auditHtaccessPatterns(path, []byte(keep+directive))
			if len(findings) != 1 || len(ranges) != 1 || string(applyRangeRemoval([]byte(keep+directive), ranges)) != keep {
				t.Errorf("automatic audit findings=%+v ranges=%v, want one removable directive", findings, ranges)
			}
			if result := ApplyFix(context.Background(), "htaccess_handler_abuse", "", "", path); !result.Success {
				t.Fatalf("manual fix=%+v", result)
			}
			if got, err := os.ReadFile(path); err != nil || string(got) != keep {
				t.Fatalf("content=%q error=%v, want %q", got, err, keep)
			}
			if err := os.WriteFile(path, []byte(keep+directive), 0644); err != nil {
				t.Fatal(err)
			}
			cfg := &config.Config{StatePath: t.TempDir()}
			cfg.AutoResponse.Enabled, cfg.AutoResponse.CleanHtaccess = true, true
			if actions := AutoCleanHtaccess(cfg, findings); len(actions) != 1 {
				t.Fatalf("automatic actions=%+v, want one clean", actions)
			}
			if got, err := os.ReadFile(path); err != nil || string(got) != keep {
				t.Fatalf("automatic content=%q error=%v, want %q", got, err, keep)
			}
			if v := VerifyFinding("htaccess_handler_abuse", "", "", path); !v.Checked || !v.Resolved {
				t.Errorf("handler re-check=%+v, want resolved", v)
			}
			if v := VerifyFinding("htaccess_injection", "", "", path); !v.Checked || v.Resolved {
				t.Errorf("generic re-check=%+v, want the .html mapping reported", v)
			}
		})
	}
}

func TestHtaccessHandlerAbuseHonorsActiveCGIOptions(t *testing.T) {
	for _, tc := range []struct {
		body string
		want int
	}{
		{"Options -ExecCGI\nAddHandler cgi-script .haxor\n", 0},
		{"# Options -ExecCGI\nAddHandler cgi-script .haxor\n", 1},
		{"Options -ExecCGI\nOptions +ExecCGI\nAddHandler cgi-script .haxor\n", 1},
		{"Options -ExecCGI\nAddHandler application/x-httpd-php .haxor\n", 1},
	} {
		t.Run(tc.body, func(t *testing.T) {
			findings, _ := AuditHtaccessContent("/home/example/public_html/.htaccess", []byte(tc.body))
			if got := countByCheck(findings, "htaccess_handler_abuse"); got != tc.want {
				t.Errorf("handler findings=%d, want %d: %+v", got, tc.want, findings)
			}
		})
	}
}

func TestHtaccessAutoCleanRequiresRemovableContent(t *testing.T) {
	root := setupHtaccessCleanRoots(t)
	sink := withActionSink(t)
	for _, body := range []string{
		"php_value auto_prepend_file /home/example/other/wp-content/advanced-headers.php\n",
		"AddHandler application/x-httpd-php .html\n",
	} {
		t.Run(body, func(t *testing.T) {
			path := writeHtaccess(t, root, "public_html", body)
			cfg := &config.Config{StatePath: t.TempDir()}
			cfg.AutoResponse.Enabled, cfg.AutoResponse.CleanHtaccess = true, true
			// Include a stale finding as well as any retained finding from the audit.
			findings, _ := AuditHtaccessFile(path)
			findings = append(findings, alert.Finding{Check: "htaccess_handler_abuse", FilePath: path})
			before := len(sink.records)
			if actions := AutoCleanHtaccess(cfg, findings); len(actions) != 0 {
				t.Errorf("automatic actions=%+v, want none", actions)
			}
			for _, f := range findings {
				if f.AutoFileResponseEvaluated {
					t.Errorf("finding without removable content reached automatic response: %+v", f)
				}
			}
			for _, rec := range sink.records[before:] {
				if strings.HasPrefix(rec.Op, "respond.") {
					t.Errorf("unremovable content produced action: %+v", rec)
				}
			}
			if got, err := os.ReadFile(path); err != nil || string(got) != body {
				t.Fatalf("content=%q error=%v, want unchanged", got, err)
			}
		})
	}
}
