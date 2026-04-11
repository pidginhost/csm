package platform

import (
	"testing"
)

// --- selectWebServer exhaustive branch coverage -----------------------

func TestSelectWebServer_CPanelFallsBackToApacheBinary(t *testing.T) {
	got := selectWebServer(PanelCPanel, map[string]bool{}, true, false)
	if got != WSApache {
		t.Errorf("cPanel apache-binary-only = %q, want apache", got)
	}
}

func TestSelectWebServer_CPanelFallsBackToNginxBinary(t *testing.T) {
	got := selectWebServer(PanelCPanel, map[string]bool{}, false, true)
	if got != WSNginx {
		t.Errorf("cPanel nginx-binary-only = %q, want nginx", got)
	}
}

func TestSelectWebServer_CPanelNothingReturnsNone(t *testing.T) {
	got := selectWebServer(PanelCPanel, map[string]bool{}, false, false)
	if got != WSNone {
		t.Errorf("cPanel nothing = %q, want none", got)
	}
}

func TestSelectWebServer_CPanelRunningNginxOnly(t *testing.T) {
	got := selectWebServer(PanelCPanel, map[string]bool{"nginx": true}, false, true)
	if got != WSNginx {
		t.Errorf("cPanel nginx-running-only = %q, want nginx", got)
	}
}

func TestSelectWebServer_NonCPanelApacheRunning(t *testing.T) {
	got := selectWebServer(PanelNone, map[string]bool{"httpd": true}, true, false)
	if got != WSApache {
		t.Errorf("non-cPanel httpd running = %q, want apache", got)
	}
}

func TestSelectWebServer_NonCPanelApache2UnitName(t *testing.T) {
	got := selectWebServer(PanelNone, map[string]bool{"apache2": true}, true, false)
	if got != WSApache {
		t.Errorf("non-cPanel apache2 running = %q, want apache", got)
	}
}

func TestSelectWebServer_NonCPanelLiteSpeedRunning(t *testing.T) {
	got := selectWebServer(PanelNone, map[string]bool{"lsws": true}, false, false)
	if got != WSLiteSpeed {
		t.Errorf("non-cPanel lsws running = %q, want litespeed", got)
	}
}

func TestSelectWebServer_NonCPanelLiteSpeedVariantUnits(t *testing.T) {
	// lshttpd and "litespeed" unit names must also count.
	if got := selectWebServer(PanelNone, map[string]bool{"lshttpd": true}, false, false); got != WSLiteSpeed {
		t.Errorf("lshttpd variant = %q, want litespeed", got)
	}
	if got := selectWebServer(PanelNone, map[string]bool{"litespeed": true}, false, false); got != WSLiteSpeed {
		t.Errorf("litespeed variant = %q, want litespeed", got)
	}
}

func TestSelectWebServer_NonCPanelFallsBackToApacheBinary(t *testing.T) {
	got := selectWebServer(PanelNone, map[string]bool{}, true, false)
	if got != WSApache {
		t.Errorf("non-cPanel apache-binary-only = %q, want apache", got)
	}
}

func TestSelectWebServer_NonCPanelFallsBackToNginxBinary(t *testing.T) {
	got := selectWebServer(PanelNone, map[string]bool{}, false, true)
	if got != WSNginx {
		t.Errorf("non-cPanel nginx-binary-only = %q, want nginx", got)
	}
}

func TestSelectWebServer_NonCPanelEmptyReturnsNone(t *testing.T) {
	got := selectWebServer(PanelNone, map[string]bool{}, false, false)
	if got != WSNone {
		t.Errorf("non-cPanel nothing = %q, want none", got)
	}
}

// --- populatePaths LiteSpeed branches ----------------------------------

func TestPopulatePaths_CPanelLiteSpeed(t *testing.T) {
	// cPanel + LiteSpeed should still prepend the cPanel overlay log
	// paths, even though they're Apache-style paths — because cPanel's
	// LiteSpeed install is a drop-in replacement writing to the same dirs.
	i := Info{OS: OSCloudLinux, Panel: PanelCPanel, WebServer: WSLiteSpeed}
	populatePaths(&i)
	if len(i.AccessLogPaths) == 0 {
		t.Fatalf("cPanel+LiteSpeed should have access log paths populated, got empty")
	}
	if i.AccessLogPaths[0] != "/usr/local/apache/logs/access_log" {
		t.Errorf("cPanel overlay prepend failed, AccessLogPaths[0] = %q", i.AccessLogPaths[0])
	}
}

// --- SetOverrides: second call after override already pending ----------

func TestSetOverrides_SecondCallBeforeDetectStillAccepts(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)
	// First call installs an override.
	if ok := SetOverrides(Overrides{WebServer: wsPtr(WSNginx)}); !ok {
		t.Fatal("first SetOverrides should return true")
	}
	// Second call before Detect() has been invoked should also succeed
	// (it replaces the pending override) since isDetected is still false.
	if ok := SetOverrides(Overrides{WebServer: wsPtr(WSApache)}); !ok {
		t.Error("second SetOverrides before Detect should also be accepted")
	}
	// Detect applies the latest pending override.
	got := Detect().WebServer
	if got != WSApache {
		t.Errorf("latest pending override should win: got %q, want apache", got)
	}
}

// --- applyOverrides: Panel/WebServer pointer-vs-nil semantics ----------
//
// These tests verify the fix for the pointer-sentinel bug: before, the
// Override check was `if o.Panel != "" { info.Panel = o.Panel }`, which
// could not distinguish "not set" from "explicitly set to PanelNone"
// because PanelNone is the empty string. Same story for WebServer/WSNone.
//
// After the fix, Panel and WebServer are pointer types so nil means
// "leave auto-detected" and a pointer at PanelNone/WSNone forces the
// host to look panel-less / server-less.

func TestApplyOverrides_ExplicitPanelNoneDropsCPanelOverlay(t *testing.T) {
	// Start with a cPanel Apache config, then explicitly override panel
	// to PanelNone + WebServer to Apache. The rebuild of populatePaths
	// must see Panel=="" and therefore skip the cPanel overlay.
	base := Info{OS: OSCloudLinux, Panel: PanelCPanel, WebServer: WSApache}
	populatePaths(&base)
	hadCPanelOverlay := false
	for _, p := range base.AccessLogPaths {
		if p == "/usr/local/apache/logs/access_log" {
			hadCPanelOverlay = true
			break
		}
	}
	if !hadCPanelOverlay {
		t.Fatalf("precondition: cPanel base should have overlay path, got %v", base.AccessLogPaths)
	}

	overridden := applyOverrides(base, Overrides{
		Panel:     panelPtr(PanelNone),
		WebServer: wsPtr(WSApache), // force path rebuild
	})
	if overridden.Panel != PanelNone {
		t.Errorf("Panel override to PanelNone should stick, got %q", overridden.Panel)
	}
	for _, p := range overridden.AccessLogPaths {
		if p == "/usr/local/apache/logs/access_log" {
			t.Errorf("PanelNone override should drop cPanel overlay, still present in %v", overridden.AccessLogPaths)
		}
	}
}

func TestApplyOverrides_ExplicitWSNoneSticks(t *testing.T) {
	base := Info{OS: OSUbuntu, WebServer: WSApache}
	populatePaths(&base)

	overridden := applyOverrides(base, Overrides{WebServer: wsPtr(WSNone)})
	if overridden.WebServer != WSNone {
		t.Errorf("WebServer override to WSNone should stick, got %q", overridden.WebServer)
	}
}

func TestApplyOverrides_NilPanelLeavesAutoDetected(t *testing.T) {
	base := Info{OS: OSCloudLinux, Panel: PanelCPanel, WebServer: WSApache}
	populatePaths(&base)

	overridden := applyOverrides(base, Overrides{WebServer: wsPtr(WSNginx)})
	if overridden.Panel != PanelCPanel {
		t.Errorf("nil Panel override should preserve auto-detected cpanel, got %q", overridden.Panel)
	}
}

func TestApplyOverrides_NilWebServerLeavesAutoDetected(t *testing.T) {
	base := Info{OS: OSUbuntu, WebServer: WSApache}
	populatePaths(&base)

	overridden := applyOverrides(base, Overrides{Panel: panelPtr(PanelPlesk)})
	if overridden.WebServer != WSApache {
		t.Errorf("nil WebServer override should preserve auto-detected apache, got %q", overridden.WebServer)
	}
}
