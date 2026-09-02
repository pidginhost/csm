package daemon

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

// Disabling php_relay (or retuning it) through a reload reported success
// while the evaluator kept firing on the startup snapshot. It must read the
// live config on every evaluation.
func TestEvaluatorHonoursLiveConfig(t *testing.T) {
	prev := config.Active()
	config.SetActive(nil)
	t.Cleanup(func() { config.SetActive(prev) })

	cfg := defaultPHPRelayCfg()
	cfg.EmailProtection.PHPRelay.FanoutDistinctScripts = 3
	cfg.EmailProtection.PHPRelay.FanoutWindowMin = 5
	cfg.EmailProtection.PHPRelay.FanoutDistinctRecipients = 1
	now := time.Unix(1_700_000_000, 0).UTC()
	ip := "192.0.2.99"
	// Fresh windows per evaluation: the per-path cooldown would otherwise
	// silence a second call regardless of configuration.
	evaluate := func() bool {
		psw := newPerScriptWindow()
		pip := newPerIPWindow(64)
		seedFanout(psw, pip, ip, now, [][]string{{"a@example.com"}, {"b@example.org"}, {"c@example.net"}})
		return fanoutFired(newEvaluator(psw, pip, nil, cfg, nil).evaluatePaths("kC:/", ip, "u", now))
	}

	if !evaluate() {
		t.Fatal("fixture does not fire Path 4 while enabled; the test cannot prove anything")
	}

	disabled := *cfg
	disabled.EmailProtection.PHPRelay.Enabled = false
	config.SetActive(&disabled)
	if evaluate() {
		t.Fatal("evaluator ignored the live config that disabled php_relay")
	}
}
