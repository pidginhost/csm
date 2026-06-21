package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/modsec"
	"github.com/pidginhost/csm/internal/platform"
)

// A registry refresh that finds the vendor rule tree empty (e.g. cPanel
// modsec_assemble mid-rewrite, or a boot-time web-server mis-detection) must
// keep the previously-loaded healthy registry rather than blanking known pass
// and deny actions.
func TestRefreshModSecRegistry_KeepsHealthyWhenTreeEmpty(t *testing.T) {
	installModSecRegistryForTest(t, map[int]string{210710: "pass"})
	healthy := modsec.Global()
	if healthy == nil || healthy.Len() == 0 {
		t.Fatal("precondition: a healthy registry must be installed")
	}

	// Force detection to a web-server state with no rule directories so
	// BuildRegistry yields an empty registry regardless of host packages.
	platform.ResetForTest()
	t.Cleanup(platform.ResetForTest)
	ws := platform.WSNone
	platform.SetOverrides(platform.Overrides{WebServer: &ws})

	(&Daemon{}).refreshModSecRegistry()

	if got := modsec.Global(); got != healthy {
		t.Fatalf("refresh blanked a healthy registry when the rule tree was empty (rules now=%d)", got.Len())
	}
}
