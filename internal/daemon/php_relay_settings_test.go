package daemon

import (
	"context"
	"testing"

	"github.com/pidginhost/csm/internal/control"
)

func TestDryRunPrecedence_Runtime_Bbolt_Yaml(t *testing.T) {
	cfg := defaultPHPRelayCfg()
	cfg.AutoResponse.PHPRelay.DryRun = boolPtr(true) // yaml default

	db := openTestDB(t)
	eng := newEvaluator(newPerScriptWindow(), nil, nil, cfg, nil)
	c := &PHPRelayController{eng: eng, ignores: newIgnoreList(), actionDryRun: &runtimeBool{}, db: db}

	// No overrides yet -> yaml.
	eff, src := c.effectiveDryRun()
	if !eff || src != "csm.yaml" {
		t.Errorf("expected yaml=true, got eff=%v src=%v", eff, src)
	}

	// Persist false to bbolt.
	if _, err := c.DryRun(context.Background(), control.PHPRelayDryRunRequest{Mode: "off", Persist: true}); err != nil {
		t.Fatal(err)
	}
	c.actionDryRun.Reset()
	eff, src = c.effectiveDryRun()
	if eff || src != "bbolt" {
		t.Errorf("expected bbolt=false, got eff=%v src=%v", eff, src)
	}

	// Set runtime override to true; runtime wins.
	if _, err := c.DryRun(context.Background(), control.PHPRelayDryRunRequest{Mode: "on", Persist: false}); err != nil {
		t.Fatal(err)
	}
	eff, src = c.effectiveDryRun()
	if !eff || src != "runtime" {
		t.Errorf("expected runtime=true, got eff=%v src=%v", eff, src)
	}

	// reset --persist deletes bbolt; effective falls back to yaml.
	if _, err := c.DryRun(context.Background(), control.PHPRelayDryRunRequest{Mode: "reset", Persist: true}); err != nil {
		t.Fatal(err)
	}
	eff, src = c.effectiveDryRun()
	if !eff || src != "csm.yaml" {
		t.Errorf("expected fallback to yaml=true, got eff=%v src=%v", eff, src)
	}
}
