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
	found := false
	for _, p := range i.AccessLogPaths {
		if p == "/usr/local/apache/logs/access_log" {
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
