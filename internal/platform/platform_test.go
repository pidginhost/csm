package platform

import (
	"strings"
	"testing"
)

func TestInfo_Families(t *testing.T) {
	tests := []struct {
		name       string
		os         OSFamily
		wantDebian bool
		wantRHEL   bool
	}{
		{"ubuntu", OSUbuntu, true, false},
		{"debian", OSDebian, true, false},
		{"alma", OSAlma, false, true},
		{"rocky", OSRocky, false, true},
		{"rhel", OSRHEL, false, true},
		{"cloudlinux", OSCloudLinux, false, true},
		{"unknown", OSUnknown, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := Info{OS: tt.os}
			if got := i.IsDebianFamily(); got != tt.wantDebian {
				t.Errorf("IsDebianFamily() = %v, want %v", got, tt.wantDebian)
			}
			if got := i.IsRHELFamily(); got != tt.wantRHEL {
				t.Errorf("IsRHELFamily() = %v, want %v", got, tt.wantRHEL)
			}
		})
	}
}

func TestInfo_IsCPanel(t *testing.T) {
	if (Info{Panel: PanelCPanel}).IsCPanel() != true {
		t.Error("cPanel panel should report IsCPanel() = true")
	}
	if (Info{Panel: PanelNone}).IsCPanel() != false {
		t.Error("no panel should report IsCPanel() = false")
	}
}

func TestPopulatePaths_UbuntuNginx(t *testing.T) {
	i := Info{OS: OSUbuntu, WebServer: WSNginx}
	populatePaths(&i)
	if len(i.AccessLogPaths) == 0 || i.AccessLogPaths[0] != "/var/log/nginx/access.log" {
		t.Errorf("Ubuntu+Nginx access log paths = %v", i.AccessLogPaths)
	}
	if len(i.ErrorLogPaths) == 0 || i.ErrorLogPaths[0] != "/var/log/nginx/error.log" {
		t.Errorf("Ubuntu+Nginx error log paths = %v", i.ErrorLogPaths)
	}
}

func TestPopulatePaths_AlmaApache(t *testing.T) {
	i := Info{OS: OSAlma, WebServer: WSApache}
	populatePaths(&i)
	if len(i.AccessLogPaths) == 0 || i.AccessLogPaths[0] != "/var/log/httpd/access_log" {
		t.Errorf("Alma+Apache access log paths = %v", i.AccessLogPaths)
	}
	if len(i.ErrorLogPaths) == 0 || i.ErrorLogPaths[0] != "/var/log/httpd/error_log" {
		t.Errorf("Alma+Apache error log paths = %v", i.ErrorLogPaths)
	}
}

func TestPopulatePaths_DebianApache(t *testing.T) {
	i := Info{OS: OSUbuntu, WebServer: WSApache}
	populatePaths(&i)
	if len(i.AccessLogPaths) == 0 || i.AccessLogPaths[0] != "/var/log/apache2/access.log" {
		t.Errorf("Ubuntu+Apache access log paths = %v", i.AccessLogPaths)
	}
}

func TestPopulatePaths_CPanelOverlay(t *testing.T) {
	i := Info{OS: OSCloudLinux, Panel: PanelCPanel, WebServer: WSApache}
	populatePaths(&i)
	if len(i.AccessLogPaths) == 0 || i.AccessLogPaths[0] != "/usr/local/apache/logs/access_log" {
		t.Fatalf("cPanel access logs should be preferred, got %v", i.AccessLogPaths)
	}
	found := false
	for _, p := range i.AccessLogPaths[1:] {
		if p == "/var/log/httpd/access_log" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("cPanel overlay missing from access logs: %v", i.AccessLogPaths)
	}
}

func TestPopulatePaths_NoWebServer(t *testing.T) {
	i := Info{OS: OSUbuntu, WebServer: WSNone}
	populatePaths(&i)
	if len(i.AccessLogPaths) != 0 {
		t.Errorf("WSNone should yield empty AccessLogPaths, got %v", i.AccessLogPaths)
	}
	if len(i.ErrorLogPaths) != 0 {
		t.Errorf("WSNone should yield empty ErrorLogPaths, got %v", i.ErrorLogPaths)
	}
	if len(i.ModSecAuditLogPaths) != 0 {
		t.Errorf("WSNone should yield empty ModSecAuditLogPaths, got %v", i.ModSecAuditLogPaths)
	}
}

func TestPopulatePaths_LiteSpeed(t *testing.T) {
	i := Info{OS: OSCloudLinux, WebServer: WSLiteSpeed}
	populatePaths(&i)
	if len(i.AccessLogPaths) == 0 || !strings.Contains(i.AccessLogPaths[0], "lsws") {
		t.Errorf("LiteSpeed should have lsws paths, got %v", i.AccessLogPaths)
	}
}

func TestSelectWebServer_CPanelPrefersApacheOverReverseProxyNginx(t *testing.T) {
	got := selectWebServer(PanelCPanel, map[string]bool{
		"nginx": true,
		"httpd": true,
	}, true, true)
	if got != WSApache {
		t.Errorf("selectWebServer() = %q, want apache", got)
	}
}

func TestSelectWebServer_CPanelPrefersLiteSpeed(t *testing.T) {
	got := selectWebServer(PanelCPanel, map[string]bool{
		"nginx":   true,
		"httpd":   true,
		"lshttpd": true,
	}, true, true)
	if got != WSLiteSpeed {
		t.Errorf("selectWebServer() = %q, want litespeed", got)
	}
}

func TestSelectWebServer_NonCPanelPrefersRunningNginx(t *testing.T) {
	got := selectWebServer(PanelNone, map[string]bool{
		"nginx": true,
		"httpd": true,
	}, true, true)
	if got != WSNginx {
		t.Errorf("selectWebServer() = %q, want nginx", got)
	}
}

func TestApplyOverrides_WebServerReplacesPaths(t *testing.T) {
	// Start with an Apache info; override to Nginx should rebuild paths.
	base := Info{OS: OSUbuntu, WebServer: WSApache}
	populatePaths(&base)
	if base.AccessLogPaths[0] != "/var/log/apache2/access.log" {
		t.Fatalf("precondition failed: %v", base.AccessLogPaths)
	}

	got := applyOverrides(base, Overrides{WebServer: WSNginx})
	if got.WebServer != WSNginx {
		t.Errorf("WebServer = %q, want nginx", got.WebServer)
	}
	if len(got.AccessLogPaths) == 0 || got.AccessLogPaths[0] != "/var/log/nginx/access.log" {
		t.Errorf("Nginx override should produce nginx paths, got %v", got.AccessLogPaths)
	}
}

func TestApplyOverrides_ExplicitPaths(t *testing.T) {
	base := Info{OS: OSUbuntu, WebServer: WSNginx}
	populatePaths(&base)

	got := applyOverrides(base, Overrides{
		AccessLogPaths: []string{"/srv/custom/access.log"},
		ErrorLogPaths:  []string{"/srv/custom/error.log"},
	})

	if len(got.AccessLogPaths) != 1 || got.AccessLogPaths[0] != "/srv/custom/access.log" {
		t.Errorf("AccessLogPaths = %v, want [/srv/custom/access.log]", got.AccessLogPaths)
	}
	if len(got.ErrorLogPaths) != 1 || got.ErrorLogPaths[0] != "/srv/custom/error.log" {
		t.Errorf("ErrorLogPaths = %v, want [/srv/custom/error.log]", got.ErrorLogPaths)
	}
	// WebServer and other fields untouched
	if got.WebServer != WSNginx {
		t.Errorf("WebServer should be unchanged, got %q", got.WebServer)
	}
}

func TestApplyOverrides_WebServerAndPaths(t *testing.T) {
	// Both WebServer and explicit paths: explicit paths win (applied after
	// populatePaths), WebServer value is what the operator asked for.
	base := Info{OS: OSUbuntu, WebServer: WSApache}
	populatePaths(&base)

	got := applyOverrides(base, Overrides{
		WebServer:      WSNginx,
		AccessLogPaths: []string{"/srv/access.log"},
	})

	if got.WebServer != WSNginx {
		t.Errorf("WebServer = %q, want nginx", got.WebServer)
	}
	if len(got.AccessLogPaths) != 1 || got.AccessLogPaths[0] != "/srv/access.log" {
		t.Errorf("Explicit AccessLogPaths should win, got %v", got.AccessLogPaths)
	}
	// Error logs should come from populatePaths(Nginx) since no override
	if len(got.ErrorLogPaths) == 0 || got.ErrorLogPaths[0] != "/var/log/nginx/error.log" {
		t.Errorf("ErrorLogPaths should fall back to nginx defaults, got %v", got.ErrorLogPaths)
	}
}

func TestApplyOverrides_EmptyLeavesOriginal(t *testing.T) {
	base := Info{OS: OSUbuntu, WebServer: WSNginx}
	populatePaths(&base)
	original := Info{
		WebServer:      base.WebServer,
		AccessLogPaths: append([]string(nil), base.AccessLogPaths...),
	}

	got := applyOverrides(base, Overrides{})

	if got.WebServer != original.WebServer {
		t.Errorf("empty override changed WebServer: %q → %q", original.WebServer, got.WebServer)
	}
	if len(got.AccessLogPaths) != len(original.AccessLogPaths) || got.AccessLogPaths[0] != original.AccessLogPaths[0] {
		t.Errorf("empty override changed AccessLogPaths: %v → %v", original.AccessLogPaths, got.AccessLogPaths)
	}
}

func TestApplyOverrides_ConfigDirs(t *testing.T) {
	base := Info{OS: OSUbuntu, WebServer: WSApache, ApacheConfigDir: "/etc/apache2"}
	got := applyOverrides(base, Overrides{
		ApacheConfigDir: "/opt/custom/apache",
		NginxConfigDir:  "/opt/custom/nginx",
	})
	if got.ApacheConfigDir != "/opt/custom/apache" {
		t.Errorf("ApacheConfigDir = %q, want /opt/custom/apache", got.ApacheConfigDir)
	}
	if got.NginxConfigDir != "/opt/custom/nginx" {
		t.Errorf("NginxConfigDir = %q, want /opt/custom/nginx", got.NginxConfigDir)
	}
}

func TestApplyOverrides_PanelCPanel(t *testing.T) {
	// Override a non-cPanel host to look like cPanel. The Panel override
	// must fire BEFORE populatePaths so the cPanel log overlay gets added.
	base := Info{OS: OSUbuntu, WebServer: WSApache}
	got := applyOverrides(base, Overrides{
		Panel:     PanelCPanel,
		WebServer: WSApache, // forces path rebuild
	})
	if !got.IsCPanel() {
		t.Error("Panel override should flip IsCPanel to true")
	}
	// Path rebuild with Panel=cpanel should include the cPanel Apache overlay
	found := false
	for _, p := range got.AccessLogPaths {
		if p == "/usr/local/apache/logs/access_log" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Panel=cpanel + Apache rebuild should include cPanel overlay, got %v", got.AccessLogPaths)
	}
}

func TestApplyOverrides_PanelWithoutWebServerRebuild(t *testing.T) {
	// Panel override alone (without WebServer override) should set the
	// Panel field but NOT rebuild paths — that's the operator's intent.
	base := Info{OS: OSUbuntu, WebServer: WSNginx, Panel: PanelNone}
	populatePaths(&base)
	originalPathsLen := len(base.AccessLogPaths)

	got := applyOverrides(base, Overrides{Panel: PanelCPanel})
	if got.Panel != PanelCPanel {
		t.Errorf("Panel = %q, want cpanel", got.Panel)
	}
	if len(got.AccessLogPaths) != originalPathsLen {
		t.Errorf("Panel-only override should not change paths, len %d → %d", originalPathsLen, len(got.AccessLogPaths))
	}
}

func TestSetOverrides_BeforeDetect(t *testing.T) {
	ResetForTest()
	ok := SetOverrides(Overrides{WebServer: WSNginx})
	if !ok {
		t.Fatal("SetOverrides should succeed before Detect()")
	}
	info := Detect()
	if info.WebServer != WSNginx {
		t.Errorf("Detect after SetOverrides should return nginx, got %q", info.WebServer)
	}
}

func TestSetOverrides_AfterDetect(t *testing.T) {
	ResetForTest()
	_ = Detect() // freeze the cache

	ok := SetOverrides(Overrides{WebServer: WSApache})
	if ok {
		t.Error("SetOverrides should fail after Detect() has cached")
	}
}

func TestResetForTest_ClearsCache(t *testing.T) {
	ResetForTest()
	first := Detect()

	ResetForTest()
	SetOverrides(Overrides{WebServer: WSNginx})
	second := Detect()

	if second.WebServer != WSNginx {
		t.Errorf("after ResetForTest, Detect should return fresh+override, got %q", second.WebServer)
	}
	// Touch first to make linter happy
	_ = first
}
