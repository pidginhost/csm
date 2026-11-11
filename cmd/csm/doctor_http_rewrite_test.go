package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
)

// The row says whether web findings can produce automatic responses: a
// detected rewrite is an accepted state, an unreadable configuration is
// something to correct.
func TestWebRewriteDoctorCheck(t *testing.T) {
	for _, tc := range []struct {
		name         string
		in           checks.HTTPRewrite
		status       string
		message, fix []string
	}{
		{"no web server", checks.HTTPRewrite{State: checks.RewriteNone}, "ok", []string{"no web server"}, nil},
		{"direct", checks.HTTPRewrite{State: checks.RewriteNone, Server: "nginx"}, "ok", []string{"nginx configuration sets no client address rewriting"}, nil},
		{"rewritten", checks.HTTPRewrite{State: checks.RewriteActive, Server: "litespeed", Directive: "useIpInProxyHeader 2", File: "/usr/local/lsws/conf/httpd_config.xml"}, "ok",
			[]string{"litespeed", "replaced client address", "useIpInProxyHeader 2", "/usr/local/lsws/conf/httpd_config.xml", "no automatic response", "existing blocking is unchanged"}, nil},
		{"proxy protocol", checks.HTTPRewrite{State: checks.RewriteActive, Server: "apache", Directive: "RemoteIPProxyProtocol On", File: "/etc/apache2/conf.d/proxy.conf"}, "ok",
			[]string{"apache logs a replaced client address", "RemoteIPProxyProtocol On", "/etc/apache2/conf.d/proxy.conf"}, nil},
		{"unknown", checks.HTTPRewrite{State: checks.RewriteUnknown, Server: "apache", Reason: "no Apache configuration file was found"}, "warn",
			[]string{"no Apache configuration file was found", "no automatic response"}, []string{"root", "web server configuration"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := webRewriteDoctorCheck(tc.in)
			if got.Name != "web client addresses" || got.Status != tc.status {
				t.Fatalf("check = %+v, want status %s", got, tc.status)
			}
			for _, want := range tc.message {
				if !strings.Contains(got.Message, want) {
					t.Errorf("message %q lacks %q", got.Message, want)
				}
			}
			for _, want := range tc.fix {
				if !strings.Contains(got.Fix, want) {
					t.Errorf("fix %q lacks %q", got.Fix, want)
				}
			}
			if len(tc.fix) == 0 && got.Fix != "" {
				t.Errorf("an accepted state offers a fix: %q", got.Fix)
			}
			if strings.Contains(got.Message, "request header") {
				t.Errorf("message %q claims a request header for every rewrite", got.Message)
			}
			raw, err := json.Marshal(DoctorReport{Checks: []DoctorCheck{got}})
			var back DoctorReport
			if err != nil || json.Unmarshal(raw, &back) != nil || len(back.Checks) != 1 || back.Checks[0] != got {
				t.Errorf("row does not survive --json: %s, %v", raw, err)
			}
		})
	}
}

// Doctor reads the web server itself, so the row appears even while the
// daemon is down.
func TestDoctorReportsWebRewriteWithoutTheDaemon(t *testing.T) {
	prev := doctorHTTPRewrite
	t.Cleanup(func() { doctorHTTPRewrite = prev })
	doctorHTTPRewrite = func(bool) checks.HTTPRewrite {
		return checks.HTTPRewrite{State: checks.RewriteActive, Server: "apache", Directive: "RemoteIPHeader CF-Connecting-IP", File: "/etc/apache2/conf.d/remoteip.conf"}
	}
	report := buildDoctorReport(func() (*config.Config, error) { return validDoctorConfig(), nil }, func() ([]byte, error) { return nil, errors.New("daemon down") }, integrityOK)
	for _, c := range report.Checks {
		if c.Name == "web client addresses" {
			if !strings.Contains(c.Message, "RemoteIPHeader CF-Connecting-IP") {
				t.Fatalf("row = %+v", c)
			}
			return
		}
	}
	t.Fatalf("no web client addresses row in %+v", report.Checks)
}

// The production reader applies the loaded config's web_server: settings
// before detection and reads the files, never the daemon's published state;
// detection cached before those settings leaves the row unknown.
func TestDoctorHTTPRewriteProductionReader(t *testing.T) {
	prevRead, prevInstall, prevState := doctorHTTPRewrite, doctorPlatformOverrides, checks.CurrentHTTPRewrite()
	t.Cleanup(func() {
		doctorHTTPRewrite, doctorPlatformOverrides = prevRead, prevInstall
		platform.ResetForTest()
		checks.SetHTTPRewrite(prevState)
	})
	doctorHTTPRewrite, doctorPlatformOverrides = productionDoctorHTTPRewrite, productionDoctorPlatformOverrides
	checks.SetHTTPRewrite(checks.HTTPRewrite{State: checks.RewriteActive, Server: "nginx", Directive: "set_real_ip_from 198.51.100.0/24", File: "/elsewhere.conf"})
	root := t.TempDir()
	main := filepath.Join(root, "nginx.conf")
	cfg := validDoctorConfig()
	cfg.WebServer.Type = "nginx"
	cfg.WebServer.ConfigDir = root
	row := func(reset bool) DoctorCheck {
		t.Helper()
		if reset {
			platform.ResetForTest()
		}
		report := buildDoctorReport(func() (*config.Config, error) { return cfg, nil }, func() ([]byte, error) { return nil, errors.New("daemon down") }, integrityOK)
		var rows []DoctorCheck
		for _, c := range report.Checks {
			if c.Name == "web client addresses" {
				rows = append(rows, c)
			}
		}
		if len(rows) != 1 {
			t.Fatalf("web client addresses rows = %+v", rows)
		}
		return rows[0]
	}
	for _, tc := range []struct {
		body, status string
		want         []string
	}{
		{"http { server { listen 80; } }\n", "ok", []string{"nginx configuration sets no client address rewriting"}},
		{"http { set_real_ip_from 192.0.2.0/24; }\n", "ok", []string{"set_real_ip_from 192.0.2.0/24", main}},
		{"http { include missing.conf; }\n", "warn", []string{main}},
	} {
		if err := os.WriteFile(main, []byte(tc.body), 0o600); err != nil {
			t.Fatal(err)
		}
		got := row(true)
		if got.Status != tc.status {
			t.Fatalf("%q: row = %+v, want status %s", tc.body, got, tc.status)
		}
		for _, w := range tc.want {
			if !strings.Contains(got.Message, w) {
				t.Fatalf("%q: message %q lacks %q", tc.body, got.Message, w)
			}
		}
	}
	platform.ResetForTest()
	platform.Detect()
	if got := row(false); got.Status != "warn" || !strings.Contains(got.Message, "web_server: settings were not applied") {
		t.Fatalf("detection cached before the settings: row = %+v", got)
	}
}
