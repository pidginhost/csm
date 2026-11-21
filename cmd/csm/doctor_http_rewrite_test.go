package main

import (
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
			[]string{"litespeed", "replaced client address", "useIpInProxyHeader 2", "/usr/local/lsws/conf/httpd_config.xml", "no automatic response", "refused IP blocks stay refused"}, nil},
		{"proxy protocol", checks.HTTPRewrite{State: checks.RewriteActive, Server: "apache", Directive: "RemoteIPProxyProtocol On", File: "/etc/apache2/conf.d/proxy.conf"}, "ok",
			[]string{"apache logs a replaced client address", "RemoteIPProxyProtocol On", "/etc/apache2/conf.d/proxy.conf"}, nil},
		{"unknown", checks.HTTPRewrite{State: checks.RewriteUnknown, Server: "apache", Reason: "no Apache configuration file was found"}, "warn",
			[]string{"no Apache configuration file was found", "no automatic response"}, []string{"root", "web server configuration"}},
		{"apache format", checks.HTTPRewrite{State: checks.RewriteActive, Server: "apache", Format: true}, "ok",
			[]string{"refused IP blocks stay refused"}, nil},
		{"nginx format", checks.HTTPRewrite{State: checks.RewriteActive, Server: "nginx", Format: true}, "ok",
			[]string{"refused IP blocks stay refused"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := webRewriteDoctorCheck(tc.in, &config.Config{})
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
			if tc.in.State == checks.RewriteActive {
				final := tc.in.Server == platform.WSLiteSpeed || tc.in.Format
				if strings.Contains(got.Message, "existing blocking is unchanged") == final {
					t.Errorf("message misstates the legacy block policy: %q", got.Message)
				}
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

type peerLogStatInfo struct {
	os.FileInfo
	mod time.Time
}

func (f peerLogStatInfo) ModTime() time.Time { return f.mod }

// The web peer log row says whether CSM can verify rewritten client
// addresses on this host, and what to do when it cannot.
func TestDoctorWebPeerLogRow(t *testing.T) {
	now := time.Unix(1795200000, 0)
	cpanel := platform.Info{Panel: platform.PanelCPanel, WebServer: platform.WSLiteSpeed, AccessLogPaths: []string{"/usr/local/apache/logs/access_log"}}
	active := checks.HTTPRewrite{State: checks.RewriteActive, Server: platform.WSLiteSpeed, Directive: "useIpInProxyHeader 2"}
	files := func(m map[string]time.Time) func(string) (os.FileInfo, error) {
		return func(path string) (os.FileInfo, error) {
			if at, ok := m[path]; ok {
				return peerLogStatInfo{mod: at}, nil
			}
			return nil, os.ErrNotExist
		}
	}
	fresh := map[string]time.Time{
		"/etc/apache2/conf.d/csm-peer-log.conf": now.Add(-time.Hour),
		"/var/log/csm-web/peer.log":             now.Add(-time.Minute),
		"/usr/local/apache/logs/access_log":     now.Add(-time.Minute),
	}
	stale := map[string]time.Time{
		"/etc/apache2/conf.d/csm-peer-log.conf": now.Add(-time.Hour),
		"/var/log/csm-web/peer.log":             now.Add(-time.Hour),
		"/usr/local/apache/logs/access_log":     now.Add(-time.Minute),
	}
	fronted := cpanel
	fronted.FrontProxied = true
	suexecOff := cpanel
	suexecOff.ServerRunsSiteCode = true
	for _, tc := range []struct {
		name   string
		info   platform.Info
		r      checks.HTTPRewrite
		files  map[string]time.Time
		status string
		says   string
	}{
		{"direct host", cpanel, checks.HTTPRewrite{State: checks.RewriteNone}, nil, "ok", "not needed"},
		{"fronted", fronted, active, fresh, "warn", "nginx"},
		{"suexec off", suexecOff, active, fresh, "warn", "suEXEC"},
		{"buffered logs", cpanel, checks.HTTPRewrite{State: checks.RewriteActive, Server: platform.WSApache, Directive: "RemoteIPHeader X-Forwarded-For", BufferedLogs: true}, fresh, "warn", "BufferedLogs"},
		{"fronted without rewrite", fronted, checks.HTTPRewrite{State: checks.RewriteNone}, fresh, "warn", "nginx"},
		{"unsupported", platform.Info{WebServer: platform.WSNginx}, checks.HTTPRewrite{State: checks.RewriteNone}, nil, "ok", "not used"},
		{"not installed", cpanel, active, nil, "warn", "csm webserver-integration install"},
		{"not written", cpanel, active, stale, "warn", "not writing"},
		{"active", cpanel, active, fresh, "ok", "active"},
		{"peer still recent", cpanel, active, map[string]time.Time{
			"/etc/apache2/conf.d/csm-peer-log.conf": now.Add(-time.Hour),
			"/var/log/csm-web/peer.log":             now.Add(-14 * time.Minute),
			"/usr/local/apache/logs/access_log":     now,
		}, "ok", "active"},
		{"quiet host", cpanel, active, map[string]time.Time{
			"/etc/apache2/conf.d/csm-peer-log.conf": now.Add(-time.Hour),
			"/var/log/csm-web/peer.log":             now.Add(-time.Hour),
			"/usr/local/apache/logs/access_log":     now.Add(-time.Hour),
		}, "ok", "active"},
	} {
		got := webPeerLogDoctorCheck(tc.info, tc.r, files(tc.files), now)
		if got.Name != "web peer log" || got.Status != tc.status || !strings.Contains(got.Message, tc.says) {
			t.Errorf("%s: row = %+v, want %s mentioning %q", tc.name, got, tc.status, tc.says)
		}
	}
}

func TestDoctorWebPeerUnverifiedSuExecRecovery(t *testing.T) {
	got := webPeerLogDoctorCheck(platform.Info{WebServer: platform.WSLiteSpeed, ServerRunsSiteCode: true}, checks.HTTPRewrite{}, nil, time.Now())
	if got.Status != "warn" || !strings.Contains(got.Message, "cannot be verified") {
		t.Fatalf("unknown isolation must warn without claiming it is known off: %+v", got)
	}
	if !strings.Contains(got.Fix, "reload LiteSpeed, then restart CSM") {
		t.Fatalf("recovery must reload the server before starting a fresh peer reader: %+v", got)
	}
}

// The rewrite row says when nginx's real_ip setup lets web findings block as
// on a direct host.
func TestDoctorRewriteRowNginxVerified(t *testing.T) {
	t.Cleanup(checks.SetCloudflarePrefixesForTest([]netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}))
	r := checks.HTTPRewrite{State: checks.RewriteActive, Server: platform.WSNginx, Directive: "set_real_ip_from 198.51.100.0/24", File: "/etc/nginx/nginx.conf",
		RealIP: &checks.NginxRealIP{Headers: []string{"CF-Connecting-IP"}, From: []string{"198.51.100.0/24"}}}
	if got := webRewriteDoctorCheck(r, &config.Config{}); got.Status != "ok" || !strings.Contains(got.Message, "verified") {
		t.Fatalf("verified nginx row = %+v, want it to say verified", got)
	}
	r.RealIP = &checks.NginxRealIP{Headers: []string{"X-Forwarded-For"}, From: []string{"198.51.100.0/24"}}
	if got := webRewriteDoctorCheck(r, &config.Config{}); strings.Contains(got.Message, "verified") {
		t.Fatalf("unverified nginx row = %+v", got)
	}
}

func TestDoctorNginxProxyProtocolRefusalIsFinal(t *testing.T) {
	r := checks.HTTPRewrite{State: checks.RewriteActive, Server: platform.WSNginx, ProxyProtocol: true,
		RealIP: &checks.NginxRealIP{Headers: []string{"proxy_protocol"}, From: []string{"198.51.100.0/24"}}}
	for _, cfg := range []*config.Config{nil, {}} {
		got := webRewriteDoctorCheck(r, cfg)
		if !strings.Contains(got.Message, "refused IP blocks stay refused") || strings.Contains(got.Message, "existing blocking is unchanged") {
			t.Fatalf("unsafe PROXY protocol must not advertise legacy blocks: %+v", got)
		}
	}
}
