package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// The relay evaluator and the auto-freezer captured the startup config
// pointer, so a reload that retuned or disabled them reported success while
// they kept running on the old values. They read the live config now.
func TestLiveConfigFnFollowsActiveConfig(t *testing.T) {
	prev := config.Active()
	t.Cleanup(func() { config.SetActive(prev) })

	startup := &config.Config{Hostname: "startup"}
	fn := liveConfigFn(startup)
	config.SetActive(nil)
	if fn() != startup {
		t.Fatal("without an active config the startup snapshot must be returned")
	}
	live := &config.Config{Hostname: "live"}
	config.SetActive(live)
	if fn() != live {
		t.Fatal("the active config must win once one is published")
	}
}
