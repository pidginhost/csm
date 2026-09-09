package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func withIntegrationHooks(t *testing.T) (auditCalls, deployCalls *int) {
	t.Helper()
	origAudit, origDeploy := ensureAuditdRules, deployHostConfigs
	t.Cleanup(func() { ensureAuditdRules, deployHostConfigs = origAudit, origDeploy })

	audit, deploy := 0, 0
	ensureAuditdRules = func() (bool, error) { audit++; return false, nil }
	deployHostConfigs = func() { deploy++ }
	return &audit, &deploy
}

// Observe mode is the posture an operator picks to evaluate CSM without
// letting it edit the host. Startup must not write auditd rules, the WHM
// plugin, the ModSecurity section or the deploy script, none of which has a
// config switch of its own.
func TestObserveModeSkipsHostIntegrationDeploy(t *testing.T) {
	audit, deploy := withIntegrationHooks(t)

	cfg := &config.Config{Mode: config.ModeObserve}
	(&Daemon{cfg: cfg}).applyStartupIntegrations()

	if *audit != 0 {
		t.Errorf("observe mode deployed auditd rules (%d calls)", *audit)
	}
	if *deploy != 0 {
		t.Errorf("observe mode deployed host config files (%d calls)", *deploy)
	}
}

func TestEnforceModeDeploysHostIntegrations(t *testing.T) {
	audit, deploy := withIntegrationHooks(t)

	cfg := &config.Config{Mode: config.ModeEnforce}
	(&Daemon{cfg: cfg}).applyStartupIntegrations()

	if *audit != 1 {
		t.Errorf("auditd rules ensured %d times, want 1", *audit)
	}
	if *deploy != 1 {
		t.Errorf("host config deploy ran %d times, want 1", *deploy)
	}
}
