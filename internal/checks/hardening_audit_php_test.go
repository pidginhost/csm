package checks

import (
	"context"
	"os"
	"path/filepath"
	"sort"
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
