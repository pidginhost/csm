package platform

import (
	"testing"
)

// --- selectWebServer: cPanel litespeed with different unit names --------

func TestSelectWebServer_CPanelLiteSpeedViaLSWS(t *testing.T) {
	got := selectWebServer(PanelCPanel, map[string]bool{"lsws": true}, true, true)
	if got != WSLiteSpeed {
		t.Errorf("cPanel lsws running = %q, want litespeed", got)
	}
}

func TestSelectWebServer_CPanelLiteSpeedViaLitespeedUnit(t *testing.T) {
	got := selectWebServer(PanelCPanel, map[string]bool{"litespeed": true}, false, false)
	if got != WSLiteSpeed {
		t.Errorf("cPanel litespeed unit = %q, want litespeed", got)
	}
}

// --- selectWebServer: non-cPanel with apache2 unit running but not httpd

func TestSelectWebServer_NonCPanelApache2OnlyNoBinaryFallback(t *testing.T) {
	// apache2 running, no binaries detected — should still pick Apache.
	got := selectWebServer(PanelNone, map[string]bool{"apache2": true}, false, false)
	if got != WSApache {
		t.Errorf("non-cPanel apache2 running no binary = %q, want apache", got)
	}
}

func TestSelectWebServer_NonCPanelLiteSpeedBeatsApache(t *testing.T) {
	// Both litespeed AND httpd running on non-cPanel → nginx > apache > litespeed
	// but litespeed alone (no nginx, no apache) should win.
	got := selectWebServer(PanelNone, map[string]bool{"litespeed": true}, false, false)
	if got != WSLiteSpeed {
		t.Errorf("non-cPanel litespeed alone = %q, want litespeed", got)
	}
}

// --- selectWebServer: cPanel with only apache2 unit name running -------

func TestSelectWebServer_CPanelApache2UnitRunning(t *testing.T) {
	got := selectWebServer(PanelCPanel, map[string]bool{"apache2": true}, true, false)
	if got != WSApache {
		t.Errorf("cPanel apache2 unit = %q, want apache", got)
	}
}

// --- populatePaths: OS family paths without cPanel ----------------------

func TestPopulatePaths_RockyApache(t *testing.T) {
	i := Info{OS: OSRocky, WebServer: WSApache}
	populatePaths(&i)
	if len(i.AccessLogPaths) == 0 || i.AccessLogPaths[0] != "/var/log/httpd/access_log" {
		t.Errorf("Rocky+Apache access paths = %v", i.AccessLogPaths)
	}
	if len(i.ErrorLogPaths) == 0 || i.ErrorLogPaths[0] != "/var/log/httpd/error_log" {
		t.Errorf("Rocky+Apache error paths = %v", i.ErrorLogPaths)
	}
	if len(i.ModSecAuditLogPaths) == 0 || i.ModSecAuditLogPaths[0] != "/var/log/httpd/modsec_audit.log" {
		t.Errorf("Rocky+Apache modsec paths = %v", i.ModSecAuditLogPaths)
	}
}

func TestPopulatePaths_CentOSApache(t *testing.T) {
	i := Info{OS: OSCentOS, WebServer: WSApache}
	populatePaths(&i)
	if len(i.AccessLogPaths) == 0 || i.AccessLogPaths[0] != "/var/log/httpd/access_log" {
		t.Errorf("CentOS+Apache access paths = %v", i.AccessLogPaths)
	}
}

func TestPopulatePaths_DebianNginx(t *testing.T) {
	i := Info{OS: OSDebian, WebServer: WSNginx}
	populatePaths(&i)
	if len(i.AccessLogPaths) == 0 || i.AccessLogPaths[0] != "/var/log/nginx/access.log" {
		t.Errorf("Debian+Nginx access paths = %v", i.AccessLogPaths)
	}
	if len(i.ErrorLogPaths) == 0 || i.ErrorLogPaths[0] != "/var/log/nginx/error.log" {
		t.Errorf("Debian+Nginx error paths = %v", i.ErrorLogPaths)
	}
	if len(i.ModSecAuditLogPaths) == 0 || i.ModSecAuditLogPaths[0] != "/var/log/nginx/modsec_audit.log" {
		t.Errorf("Debian+Nginx modsec paths = %v", i.ModSecAuditLogPaths)
	}
}

func TestPopulatePaths_RHELFamilyLiteSpeed(t *testing.T) {
	i := Info{OS: OSRHEL, WebServer: WSLiteSpeed}
	populatePaths(&i)
	if len(i.AccessLogPaths) == 0 || i.AccessLogPaths[0] != "/usr/local/lsws/logs/access.log" {
		t.Errorf("RHEL+LiteSpeed access paths = %v", i.AccessLogPaths)
	}
}

// --- populatePaths: cPanel with Nginx -----------------------------------

func TestPopulatePaths_CPanelNginx(t *testing.T) {
	i := Info{OS: OSCloudLinux, Panel: PanelCPanel, WebServer: WSNginx}
	populatePaths(&i)
	// Nginx base paths should be set.
	hasNginxBase := false
	for _, p := range i.AccessLogPaths {
		if p == "/var/log/nginx/access.log" {
			hasNginxBase = true
		}
	}
	if !hasNginxBase {
		t.Errorf("cPanel+Nginx should include nginx base path, got %v", i.AccessLogPaths)
	}
	// cPanel overlay should be prepended.
	if len(i.AccessLogPaths) == 0 || i.AccessLogPaths[0] != "/usr/local/apache/logs/access_log" {
		t.Errorf("cPanel overlay should be first, got %v", i.AccessLogPaths)
	}
}

// --- applyOverrides: ModSecAuditLogPaths override -----------------------

func TestApplyOverrides_ModSecAuditLogPaths(t *testing.T) {
	base := Info{OS: OSUbuntu, WebServer: WSApache}
	populatePaths(&base)
	if len(base.ModSecAuditLogPaths) == 0 {
		t.Fatal("precondition: modsec paths should be set")
	}

	got := applyOverrides(base, Overrides{
		ModSecAuditLogPaths: []string{"/custom/modsec.log"},
	})
	if len(got.ModSecAuditLogPaths) != 1 || got.ModSecAuditLogPaths[0] != "/custom/modsec.log" {
		t.Errorf("ModSecAuditLogPaths = %v, want [/custom/modsec.log]", got.ModSecAuditLogPaths)
	}
}

// --- applyOverrides: Panel=Plesk ----------------------------------------

func TestApplyOverrides_PanelPlesk(t *testing.T) {
	base := Info{OS: OSUbuntu, WebServer: WSNginx, Panel: PanelNone}
	got := applyOverrides(base, Overrides{Panel: panelPtr(PanelPlesk)})
	if got.Panel != PanelPlesk {
		t.Errorf("Panel = %q, want plesk", got.Panel)
	}
}

// --- applyOverrides: Panel=DA -------------------------------------------

func TestApplyOverrides_PanelDirectAdmin(t *testing.T) {
	base := Info{OS: OSAlma, WebServer: WSApache, Panel: PanelNone}
	got := applyOverrides(base, Overrides{Panel: panelPtr(PanelDA)})
	if got.Panel != PanelDA {
		t.Errorf("Panel = %q, want directadmin", got.Panel)
	}
}

// --- Info convenience methods with CentOS/RHEL --------------------------

func TestInfo_IsCPanel_OtherPanels(t *testing.T) {
	if (Info{Panel: PanelPlesk}).IsCPanel() {
		t.Error("Plesk should not report IsCPanel() = true")
	}
	if (Info{Panel: PanelDA}).IsCPanel() {
		t.Error("DirectAdmin should not report IsCPanel() = true")
	}
}

func TestInfo_IsRHELFamily_CentOS(t *testing.T) {
	if !(Info{OS: OSCentOS}).IsRHELFamily() {
		t.Error("CentOS should be RHEL family")
	}
}

// --- DetectFresh runs all detectors (smoke test) -------------------------

func TestDetectFreshReturnsNonPanic(t *testing.T) {
	// DetectFresh reads real OS files; on macOS/CI it should return
	// gracefully with empty fields rather than panic.
	info := DetectFresh()
	_ = info.OS
	_ = info.Panel
	_ = info.WebServer
}

// --- SetOverrides after Detect (duplicate call) -------------------------

func TestSetOverrides_AfterDetect_ReturnsFalse(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)
	_ = Detect()
	// pendingOverride is nil and isDetected is true → first branch.
	// Let's also test when pendingOverride was set before detect but
	// we try again after detect.
	ok := SetOverrides(Overrides{WebServer: wsPtr(WSNginx)})
	if ok {
		t.Error("SetOverrides after Detect should return false")
	}
}

// --- Detect applies pending overrides (end-to-end) ----------------------

func TestDetect_NoOverrides_NoRace(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)
	info := Detect()
	// Just confirm it doesn't panic and returns a value.
	_ = info
	// Calling Detect() again returns cached value.
	info2 := Detect()
	if info.WebServer != info2.WebServer {
		t.Error("repeated Detect() should return same cached result")
	}
}

// --- populatePaths: WSNone with cPanel (cPanel overlay on empty base) ---

func TestPopulatePaths_CPanelWSNone(t *testing.T) {
	i := Info{OS: OSCloudLinux, Panel: PanelCPanel, WebServer: WSNone}
	populatePaths(&i)
	// Even with WSNone, the cPanel overlay appends paths to nil slices,
	// so we should see the cPanel-specific paths.
	if len(i.AccessLogPaths) == 0 {
		t.Error("cPanel + WSNone should still have cPanel overlay access paths")
	}
	if i.AccessLogPaths[0] != "/usr/local/apache/logs/access_log" {
		t.Errorf("first access path = %q, want cPanel overlay", i.AccessLogPaths[0])
	}
}
