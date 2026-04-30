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

func TestPHPRelayController_IgnoreFlow(t *testing.T) {
	c := &PHPRelayController{ignores: newIgnoreList()}
	resp, err := c.IgnoreScript(context.Background(), control.PHPRelayIgnoreScriptRequest{
		ScriptKey: "k:/p", ForHours: 1, AddedBy: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !c.ignores.Has("k:/p") {
		t.Error("ignore should be active")
	}
	if resp.ExpiresAt.IsZero() {
		t.Error("ExpiresAt must be set")
	}

	list, _ := c.IgnoreList(context.Background(), struct{}{})
	if len(list.Entries) != 1 {
		t.Errorf("expected 1 entry, got %d", len(list.Entries))
	}

	if _, err := c.Unignore(context.Background(), control.PHPRelayUnignoreRequest{ScriptKey: "k:/p"}); err != nil {
		t.Fatal(err)
	}
	if c.ignores.Has("k:/p") {
		t.Error("ignore should be cleared after Unignore")
	}
}
