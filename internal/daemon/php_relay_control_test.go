package daemon

import (
	"context"
	"testing"

	"github.com/pidginhost/csm/internal/control"
)

func TestPHPRelayController_StatusReturnsBasicState(t *testing.T) {
	cfg := defaultPHPRelayCfg()
	eng := newEvaluator(newPerScriptWindow(), newPerIPWindow(64), newPerAccountWindow(5000), cfg, nil)
	eng.SetEffectiveAccountLimit(60)
	c := &PHPRelayController{
		eng: eng, ignores: newIgnoreList(), actionDryRun: &runtimeBool{},
		enabled: true, platform: "cpanel",
	}
	resp, err := c.Status(context.Background(), control.PHPRelayStatusRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.EffectiveAccountLimit != 60 {
		t.Errorf("EffectiveAccountLimit = %d", resp.EffectiveAccountLimit)
	}
	if resp.Platform != "cpanel" {
		t.Errorf("Platform = %q", resp.Platform)
	}
}
