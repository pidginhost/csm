package checks

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/store"
)

// withFakePHPFiles serves files from an in-memory map so auditPHP sees a
// fixed set of php.ini, scan-dir and FPM pool files.
func withFakePHPFiles(t *testing.T, files map[string]string) {
	t.Helper()
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			var out []string
			for name := range files {
				if ok, _ := filepath.Match(pattern, name); ok {
					out = append(out, name)
				}
			}
			sort.Strings(out)
			return out, nil
		},
		readFile: func(name string) ([]byte, error) {
			if c, ok := files[name]; ok {
				return []byte(c), nil
			}
			return nil, os.ErrNotExist
		},
	})
}

func withPHPAuditNow(t *testing.T, now time.Time) {
	t.Helper()
	old := phpAuditNow
	phpAuditNow = func() time.Time { return now }
	t.Cleanup(func() { phpAuditNow = old })
}

func auditResultByName(results []store.AuditResult, name string) (store.AuditResult, bool) {
	for _, r := range results {
		if r.Name == name {
			return r, true
		}
	}
	return store.AuditResult{}, false
}

func TestAuditPHPVersionEOLFollowsSecuritySupportDates(t *testing.T) {
	files := map[string]string{}
	for _, v := range []string{"56", "74", "81", "82", "83", "84", "85", "86"} {
		files["/opt/cpanel/ea-php"+v+"/root/etc/php.ini"] = ""
	}
	withFakePHPFiles(t, files)
	withMockCmd(t, &mockCmd{})

	cases := []struct {
		now  time.Time
		want map[string]string
	}{
		{
			now: time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC),
			want: map[string]string{
				"56": "fail", "74": "fail", "81": "fail",
				"82": "pass", "83": "pass", "84": "pass", "85": "pass", "86": "pass",
			},
		},
		{
			now:  time.Date(2026, 12, 31, 23, 0, 0, 0, time.UTC),
			want: map[string]string{"82": "pass"},
		},
		{
			now:  time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
			want: map[string]string{"82": "fail", "83": "pass"},
		},
	}
	for _, tc := range cases {
		withPHPAuditNow(t, tc.now)
		results := auditPHP("cpanel")
		for v, want := range tc.want {
			r, ok := auditResultByName(results, "php_version_"+v)
			if !ok {
				t.Fatalf("%s: php_version_%s missing", tc.now.Format("2006-01-02"), v)
			}
			if r.Status != want {
				t.Errorf("%s: php_version_%s = %s, want %s", tc.now.Format("2006-01-02"), v, r.Status, want)
			}
		}
	}
}

func TestAuditPHPUploadProgress(t *testing.T) {
	const ini = "/opt/cpanel/ea-php84/root/etc/php.ini"
	const scan = "/opt/cpanel/ea-php84/root/etc/php.d/"
	cases := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{"default on", map[string]string{ini: "[Session]\nsession.save_handler = files\n"}, "warn"},
		{"explicit on", map[string]string{ini: "session.upload_progress.enabled = On\n"}, "warn"},
		{"off in php.ini", map[string]string{ini: "session.upload_progress.enabled = Off\n"}, "pass"},
		{"commented out", map[string]string{ini: ";session.upload_progress.enabled = Off\n"}, "warn"},
		{"off in scan dir", map[string]string{
			ini:                   "session.upload_progress.enabled = On\n",
			scan + "zz-local.ini": "session.upload_progress.enabled = Off\n",
		}, "pass"},
		{"later scan file wins", map[string]string{
			ini:                 "",
			scan + "10-off.ini": "session.upload_progress.enabled = Off\n",
			scan + "20-on.ini":  "session.upload_progress.enabled = 1\n",
		}, "warn"},
		{"quoted zero with comment", map[string]string{ini: "session.upload_progress.enabled = \"0\" ; disabled\n"}, "pass"},
		{"empty value", map[string]string{ini: "session.upload_progress.enabled =\n"}, "pass"},
		{"non-ini file ignored", map[string]string{
			ini:                  "",
			scan + "off.ini.bak": "session.upload_progress.enabled = Off\n",
		}, "warn"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withFakePHPFiles(t, tc.files)
			withMockCmd(t, &mockCmd{})
			r, ok := auditResultByName(auditPHP("cpanel"), "php_upload_progress_84")
			if !ok {
				t.Fatal("php_upload_progress_84 missing")
			}
			if r.Status != tc.want {
				t.Errorf("status = %s, want %s (%s)", r.Status, tc.want, r.Message)
			}
		})
	}
}

func TestAuditPHPBareServerReadsScanDir(t *testing.T) {
	withFakePHPFiles(t, map[string]string{
		"/etc/php/8.3/cli/php.ini":           "expose_php = On\n",
		"/etc/php/8.3/cli/conf.d/99-ops.ini": "session.upload_progress.enabled = Off\nexpose_php = Off\n",
	})
	withMockCmd(t, &mockCmd{
		runContext: func(_ context.Context, name string, args ...string) ([]byte, error) {
			if name != "php" || len(args) != 1 {
				return nil, os.ErrNotExist
			}
			switch args[0] {
			case "-i":
				return []byte("Loaded Configuration File => /etc/php/8.3/cli/php.ini\n" +
					"Scan this dir for additional .ini files => /etc/php/8.3/cli/conf.d\n"), nil
			case "-v":
				return []byte("PHP 8.3.6 (cli) (built: Apr 15 2026)\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})
	results := auditPHP("bare")
	for name, want := range map[string]string{
		"php_upload_progress_83": "pass",
		"php_expose_83":          "pass",
	} {
		r, ok := auditResultByName(results, name)
		if !ok {
			t.Fatalf("%s missing", name)
		}
		if r.Status != want {
			t.Errorf("%s = %s, want %s", name, r.Status, want)
		}
	}
}

func TestAuditPHPUploadProgressBooleanSyntax(t *testing.T) {
	for _, value := range []string{"1.0", "1foo", "1e-2", "0|1", "!0", `"1&0"`, `"0"|"1"`, "PHP_INT_MAX", "${CSM_UPLOAD:-1}", `"Off`, "\"1\nsession.upload_progress.enabled = Off\n\""} {
		t.Run(value, func(t *testing.T) {
			withFakePHPFiles(t, map[string]string{
				"/opt/cpanel/ea-php84/root/etc/php.ini": "session.upload_progress.enabled = " + value + "\n",
			})
			withMockCmd(t, &mockCmd{})
			r, ok := auditResultByName(auditPHP("cpanel"), "php_upload_progress_84")
			if !ok || r.Status != "warn" {
				t.Fatalf("enabled or unresolved value %q: got %+v, present %v", value, r, ok)
			}
		})
	}
}

func TestAuditPHPUploadProgressScopes(t *testing.T) {
	const ini = "/opt/cpanel/ea-php84/root/etc/php.ini"
	const scan = "/opt/cpanel/ea-php84/root/etc/php.d/"
	const pools = "/opt/cpanel/ea-php84/root/etc/php-fpm.d/"
	for _, tc := range []struct {
		name  string
		files map[string]string
		want  string
	}{
		{"pool cannot disable global", map[string]string{
			ini:                "session.upload_progress.enabled = On\n",
			pools + "www.conf": "[www]\nphp_admin_value[session.upload_progress.enabled] = Off\n",
		}, "warn"},
		{"separate pools", map[string]string{
			ini:              "session.upload_progress.enabled = Off\n",
			pools + "a.conf": "[a]\nphp_admin_value[session.upload_progress.enabled] = On\n",
			pools + "z.conf": "[z]\nphp_admin_value[session.upload_progress.enabled] = Off\n",
		}, "warn"},
		{"pool flag", map[string]string{
			ini:                "session.upload_progress.enabled = Off\n",
			pools + "www.conf": "[www]\nphp_admin_flag[session.upload_progress.enabled] = On\n",
		}, "warn"},
		{"all off", map[string]string{
			ini:                "session.upload_progress.enabled = Off\n",
			pools + "www.conf": "[www]\nphp_flag[session.upload_progress.enabled] = Off\n",
		}, "pass"},
		{"path does not disable global", map[string]string{
			ini:                   "session.upload_progress.enabled = On\n",
			scan + "99-local.ini": "[PATH=/srv/www/one]\nsession.upload_progress.enabled = Off\n",
		}, "warn"},
		{"host remains enabled", map[string]string{
			ini:                   "session.upload_progress.enabled = Off\n[HOST=one.example]\nsession.upload_progress.enabled = On\n",
			scan + "99-local.ini": "session.upload_progress.enabled = Off\n",
		}, "warn"},
		{"same host overridden", map[string]string{
			ini:                   "session.upload_progress.enabled = Off\n[HOST=one.example]\nsession.upload_progress.enabled = On\n",
			scan + "99-local.ini": "[HOST=ONE.example]\nsession.upload_progress.enabled = Off\n",
		}, "pass"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withFakePHPFiles(t, tc.files)
			withMockCmd(t, &mockCmd{})
			r, ok := auditResultByName(auditPHP("cpanel"), "php_upload_progress_84")
			if !ok || r.Status != tc.want {
				t.Fatalf("got %+v, present %v; want %s", r, ok, tc.want)
			}
		})
	}
}

func TestAuditPHPUploadProgressUnreadableDropIn(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			switch pattern {
			case "/opt/cpanel/ea-php*/root/etc/php.ini":
				return []string{"/opt/cpanel/ea-php84/root/etc/php.ini"}, nil
			case "/opt/cpanel/ea-php84/root/etc/php.d/*.ini":
				return []string{"/opt/cpanel/ea-php84/root/etc/php.d/99-local.ini"}, nil
			}
			return nil, nil
		},
		readFile: func(name string) ([]byte, error) {
			if filepath.Base(name) == "php.ini" {
				return []byte("session.upload_progress.enabled = Off\n"), nil
			}
			return nil, os.ErrPermission
		},
	})
	withMockCmd(t, &mockCmd{})
	r, ok := auditResultByName(auditPHP("cpanel"), "php_upload_progress_84")
	if !ok || r.Status != "warn" {
		t.Fatalf("unreadable override must not pass: %+v, present %v", r, ok)
	}
}

func TestAuditPHPBareServerScanFileOrder(t *testing.T) {
	withFakePHPFiles(t, map[string]string{
		"/etc/php/php.ini":             "session.upload_progress.enabled = Off\n",
		"/etc/php/first/99-local.ini":  "session.upload_progress.enabled = Off\n",
		"/etc/php/second/01-local.ini": "session.upload_progress.enabled = On\n",
	})
	withMockCmd(t, &mockCmd{
		runContext: func(_ context.Context, name string, args ...string) ([]byte, error) {
			if name == "php" && len(args) == 1 {
				switch args[0] {
				case "-i":
					return []byte("Loaded Configuration File => /etc/php/php.ini\n" +
						"Scan this dir for additional .ini files => /etc/php/first:/etc/php/second\n" +
						"Additional .ini files parsed => /etc/php/first/99-local.ini,\n/etc/php/second/01-local.ini\n\n"), nil
				case "-v":
					return []byte("PHP 8.3.6 (cli)\n"), nil
				}
			}
			return nil, os.ErrNotExist
		},
	})
	r, ok := auditResultByName(auditPHP("bare"), "php_upload_progress_83")
	if !ok || r.Status != "warn" {
		t.Fatalf("last scan directory must win: %+v, present %v", r, ok)
	}
}

func TestAuditPHPUploadProgressDisabledSyntax(t *testing.T) {
	for _, value := range []string{"Off", "No", "False", "None", "", `"0" ; disabled`, "Off ; ${CSM_UPLOAD}", "1&0", `"0|1"`, "0.5", "-0", `"Of""f"`} {
		t.Run(value, func(t *testing.T) {
			withFakePHPFiles(t, map[string]string{
				"/opt/cpanel/ea-php84/root/etc/php.ini": "session.upload_progress.enabled = " + value + "\n",
			})
			withMockCmd(t, &mockCmd{})
			r, ok := auditResultByName(auditPHP("cpanel"), "php_upload_progress_84")
			if !ok || r.Status != "pass" {
				t.Fatalf("disabled value %q: got %+v, present %v", value, r, ok)
			}
		})
	}
}

func TestPHPAuditScopesPreservePrecedence(t *testing.T) {
	settings := phpAuditINI{"": {}}
	settings.merge("session.upload_progress.enabled = Off\n[PATH=/srv/www/]\nsession.upload_progress.enabled = On\n[Session]\nsession.upload_progress.enabled = Off\n", false)
	if settings.settingDisabled(phpUploadProgressKey, nil) {
		t.Fatal("global off must not hide conditional on")
	}
	settings.merge("[PATH = /srv/www]\nsession.upload_progress.enabled = Off\n", false)
	pools := phpAuditINI{}
	pools.merge("[www]\nphp_admin_flag[session.upload_progress.enabled] = Off\nphp_flag[session.upload_progress.enabled] = On\n", true)
	if !settings.settingDisabled(phpUploadProgressKey, pools) {
		t.Fatal("later conditional off and admin off must take precedence")
	}
	pools.merge("[www]\nphp_admin_value[session.upload_progress.enabled] = On\n", true)
	if settings.settingDisabled(phpUploadProgressKey, pools) {
		t.Fatal("later pool admin on must take precedence")
	}
}

func TestPHPAuditScannedFiles(t *testing.T) {
	for _, tc := range []struct {
		info  string
		files []string
		known bool
	}{
		{"Scan this dir for additional .ini files => /etc/php.d\n", nil, false},
		{"Additional .ini files parsed => (none)\n\n", nil, true},
		{"Additional .ini files parsed => /etc/php.d/99.ini,\n/etc/php-local/01.ini\n\nOther => ignored\n", []string{"/etc/php.d/99.ini", "/etc/php-local/01.ini"}, true},
	} {
		files, known := phpAuditScannedFiles(tc.info)
		if known != tc.known || !slices.Equal(files, tc.files) {
			t.Fatalf("%q: got %v, %v; want %v, %v", tc.info, files, known, tc.files, tc.known)
		}
	}
}

func TestAuditPHPFatalErrorBacktraces(t *testing.T) {
	const ini = "/opt/cpanel/ea-php85/root/etc/php.ini"
	const scan = "/opt/cpanel/ea-php85/root/etc/php.d/"
	const pools = "/opt/cpanel/ea-php85/root/etc/php-fpm.d/"
	for _, tc := range []struct {
		name  string
		files map[string]string
		want  string
	}{
		{"default on", map[string]string{ini: ""}, "warn"},
		{"explicit on", map[string]string{ini: "fatal_error_backtraces = On\n"}, "warn"},
		{"off in scan dir", map[string]string{
			ini:             "",
			scan + "zz.ini": "fatal_error_backtraces = Off\n",
		}, "pass"},
		{"pool turns it on", map[string]string{
			ini:                "fatal_error_backtraces = Off\n",
			pools + "www.conf": "[www]\nphp_admin_flag[fatal_error_backtraces] = On\n",
		}, "warn"},
		{"pool keeps it off", map[string]string{
			ini:                "fatal_error_backtraces = Off\n",
			pools + "www.conf": "[www]\nphp_value[fatal_error_backtraces] = Off\n",
		}, "pass"},
		{"host section on", map[string]string{
			ini: "fatal_error_backtraces = Off\n[HOST=one.example]\nfatal_error_backtraces = 1\n",
		}, "warn"},
		{"upload progress pool value does not leak", map[string]string{
			ini:                "fatal_error_backtraces = Off\n",
			pools + "www.conf": "[www]\nphp_admin_flag[session.upload_progress.enabled] = On\n",
		}, "pass"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withFakePHPFiles(t, tc.files)
			withMockCmd(t, &mockCmd{})
			r, ok := auditResultByName(auditPHP("cpanel"), "php_fatal_error_backtraces_85")
			if !ok || r.Status != tc.want {
				t.Fatalf("got %+v, present %v; want %s", r, ok, tc.want)
			}
		})
	}
}

func TestAuditPHPFatalErrorBacktracesOnlyFromPHP85(t *testing.T) {
	withFakePHPFiles(t, map[string]string{
		"/opt/cpanel/ea-php84/root/etc/php.ini": "",
		"/opt/cpanel/ea-php86/root/etc/php.ini": "",
	})
	withMockCmd(t, &mockCmd{})
	results := auditPHP("cpanel")
	if r, ok := auditResultByName(results, "php_fatal_error_backtraces_84"); ok {
		t.Errorf("PHP 8.4 has no fatal_error_backtraces setting, got %+v", r)
	}
	if r, ok := auditResultByName(results, "php_fatal_error_backtraces_86"); !ok || r.Status != "warn" {
		t.Errorf("PHP 8.6 default must warn: %+v, present %v", r, ok)
	}
}

func TestAuditPHPVersionEOLPointsToVendorBackports(t *testing.T) {
	withFakePHPFiles(t, map[string]string{"/opt/cpanel/ea-php74/root/etc/php.ini": ""})
	withMockCmd(t, &mockCmd{})
	withPHPAuditNow(t, time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC))
	r, ok := auditResultByName(auditPHP("cpanel"), "php_version_74")
	if !ok || r.Status != "fail" {
		t.Fatalf("PHP 7.4 must fail as end of life: %+v, present %v", r, ok)
	}
	if strings.Contains(r.Fix, "receive no security patches") || !strings.Contains(r.Fix, "backport") {
		t.Errorf("EOL fix text must point to vendor backports, got %q", r.Fix)
	}
}
