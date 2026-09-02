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

func TestEvaluatorSnapshotsLiveConfigOncePerEvaluation(t *testing.T) {
	cfg := defaultPHPRelayCfg()
	eng := newEvaluator(newPerScriptWindow(), newPerIPWindow(64), nil, cfg, nil)
	calls := 0
	eng.cfgFn = func() *config.Config {
		calls++
		return cfg
	}
	eng.evaluatePaths("example.test:/mail.php", "192.0.2.10", "acct", time.Now())
	if calls != 1 {
		t.Fatalf("config snapshots = %d, want 1 per evaluation", calls)
	}
}

func TestEvaluatorAccountLimitFollowsLiveConfig(t *testing.T) {
	prev := config.Active()
	config.SetActive(nil)
	t.Cleanup(func() { config.SetActive(prev) })

	startup := defaultPHPRelayCfg()
	startup.EmailProtection.PHPRelay.AccountVolumePerHour = 50
	accounts := newPerAccountWindow(5000)
	eng := newEvaluator(nil, nil, accounts, startup, nil)
	eng.SetAccountLimitSource(100, cpanelLimitOK)

	live := *startup
	live.EmailProtection.PHPRelay.AccountVolumePerHour = 2
	config.SetActive(&live)
	now := time.Now()
	line := "2026-09-02 12:00:00 1abcdefghijk-DEF <= info@example.com U=acct ID=1 B=redirect_resolver"
	if got := eng.parsePHPRelayAccountVolumeAt(line, now, now); len(got) != 0 {
		t.Fatalf("first message fired unexpectedly: %+v", got)
	}
	got := eng.parsePHPRelayAccountVolumeAt(line, now, now)
	if len(got) != 1 || got[0].Path != "volume_account" {
		t.Fatalf("live account limit was ignored: %+v", got)
	}
}
