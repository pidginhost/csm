package platform

import "testing"

// Overrides are installed once, early, and several startup paths then call
// Detect. A later SetOverrides with the same values must report success,
// not "too late": only a genuinely different set arriving after detection
// is a lost override.
func TestSetOverridesRecognisesInstalledOverridesAfterDetect(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)

	ws := WSLiteSpeed
	o := Overrides{WebServer: &ws, AccessLogPaths: []string{"/var/log/lsws/access.log"}}
	if !SetOverrides(o) {
		t.Fatal("first SetOverrides before Detect must install")
	}
	if got := Detect().WebServer; got != WSLiteSpeed {
		t.Fatalf("Detect ignored the installed override: webserver = %q", got)
	}
	if !SetOverrides(o) {
		t.Fatal("re-installing the same overrides after Detect must report them as installed")
	}
	other := Overrides{AccessLogPaths: []string{"/var/log/httpd/access_log"}}
	if SetOverrides(other) {
		t.Fatal("different overrides after Detect must be reported as lost")
	}
}

func TestSetOverridesTreatsNilAndEmptySlicesAsIdentical(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)

	o := Overrides{}
	if !SetOverrides(o) {
		t.Fatal("first SetOverrides before Detect must install")
	}
	_ = Detect()

	equivalent := Overrides{
		AccessLogPaths:      []string{},
		ErrorLogPaths:       []string{},
		ModSecAuditLogPaths: []string{},
		DomlogGlobs:         []string{},
	}
	if !SetOverrides(equivalent) {
		t.Fatal("nil and empty override slices must describe the same installed overrides")
	}
}
