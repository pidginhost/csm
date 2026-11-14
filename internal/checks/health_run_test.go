package checks

import (
	"context"
	"os"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
)

func TestCheckHealthRuns(t *testing.T) {
	stateDir := t.TempDir()
	cfg := &config.Config{StatePath: stateDir}
	// No external command resolves, on any host.
	withMockCmd(t, &mockCmd{})

	findings := CheckHealth(context.Background(), cfg, nil)

	for _, cmd := range platformRequiredCommands(platform.Detect()) {
		want := "Required command not found: " + cmd
		found := false
		for _, f := range findings {
			if f.Message == want {
				found = true
			}
		}
		if !found {
			t.Errorf("missing finding %q in %+v", want, findings)
		}
	}
	for _, f := range findings {
		if f.Check != "csm_health" || f.Severity != alert.Warning {
			t.Errorf("unexpected finding with a writable state dir: %+v", f)
		}
	}
	// The writability probe cleans up after itself.
	if entries, err := os.ReadDir(stateDir); err != nil || len(entries) != 0 {
		t.Errorf("state dir after CheckHealth = %v, %v; want empty", entries, err)
	}
}
