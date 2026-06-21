package platform

import "testing"

// DetectFreshWithOverrides re-probes the host (ignoring the one-shot Detect()
// cache) and applies the operator-configured overrides. The periodic ModSec
// registry refresh uses it so a detection that was wrong at boot -- e.g. a
// LiteSpeed host probed before lsws finished starting -- self-heals on the
// next refresh instead of staying wrong for the daemon's lifetime, while a
// configured web_server.type override still wins.

func TestDetectFreshWithOverrides_AppliesWebServerOverride(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)

	ws := WSLiteSpeed
	if !SetOverrides(Overrides{WebServer: &ws}) {
		t.Fatal("SetOverrides should install before any Detect()")
	}

	if got := DetectFreshWithOverrides().WebServer; got != WSLiteSpeed {
		t.Errorf("WebServer = %q, want %q (override must be applied)", got, WSLiteSpeed)
	}
}

func TestDetectFreshWithOverrides_NoOverrideMatchesDetectFresh(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)

	if got, want := DetectFreshWithOverrides().WebServer, DetectFresh().WebServer; got != want {
		t.Errorf("WebServer = %q, want %q (no override must equal DetectFresh)", got, want)
	}
}

func TestDetectFreshWithOverrides_AppliesInstalledOverrideAfterDetect(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)

	ws := WSLiteSpeed
	if !SetOverrides(Overrides{WebServer: &ws}) {
		t.Fatal("SetOverrides should install before Detect()")
	}
	_ = Detect()

	if got := DetectFreshWithOverrides().WebServer; got != WSLiteSpeed {
		t.Errorf("WebServer = %q, want %q (fresh detect must keep installed override)", got, WSLiteSpeed)
	}
}

func TestDetectFreshWithOverrides_IgnoresRejectedLateOverride(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)

	_ = Detect()

	const lateGlob = "/late-override-should-not-apply/*/access.log"
	if SetOverrides(Overrides{DomlogGlobs: []string{lateGlob}}) {
		t.Fatal("SetOverrides should reject calls after Detect()")
	}

	got := DetectFreshWithOverrides()
	for _, glob := range got.DomlogGlobs {
		if glob == lateGlob {
			t.Fatalf("fresh detect applied a rejected late override: %v", got.DomlogGlobs)
		}
	}
}
