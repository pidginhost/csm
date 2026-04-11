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
	if ok := SetOverrides(Overrides{WebServer: WSNginx}); !ok {
		t.Fatal("first SetOverrides should return true")
	}
	// Second call before Detect() has been invoked should also succeed
	// (it replaces the pending override) since isDetected is still false.
	if ok := SetOverrides(Overrides{WebServer: WSApache}); !ok {
		t.Error("second SetOverrides before Detect should also be accepted")
	}
	// Detect applies the latest pending override.
	got := Detect().WebServer
	if got != WSApache {
		t.Errorf("latest pending override should win: got %q, want apache", got)
	}
}

// --- applyOverrides: explicit panel override from none to plesk --------

func TestApplyOverrides_NoneToPleskKeepsBaseLogs(t *testing.T) {
	// Start with a non-cPanel config, override panel to Plesk. We use
	// Plesk (not PanelNone) because PanelNone is the empty string and
	// the override check `if o.Panel != ""` cannot distinguish it from
	// "no override" — see the DOCUMENTED_BUG_PLATFORM_OVERRIDE entry in
	// the remediation plan.
	base := Info{OS: OSUbuntu, Panel: PanelNone, WebServer: WSNginx}
	populatePaths(&base)

	overridden := applyOverrides(base, Overrides{Panel: PanelPlesk})
	if overridden.Panel != PanelPlesk {
		t.Errorf("Panel override = %q, want %q", overridden.Panel, PanelPlesk)
	}
}
