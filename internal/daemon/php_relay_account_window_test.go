package daemon

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

func TestEffectiveAccountLimit_AutoDeriveDefault(t *testing.T) {
	cfg := &config.Config{}
	cfg.EmailProtection.PHPRelay.AccountVolumePerHour = 0
	eff, ok, _ := deriveEffectiveAccountLimit(cfg, 100, cpanelLimitOK)
	if !ok || eff != 60 {
		t.Errorf("derive(100) auto = %d ok=%v, want 60 true", eff, ok)
	}
}

func TestEffectiveAccountLimit_OperatorOverrideCapped(t *testing.T) {
	cfg := &config.Config{}
	cfg.EmailProtection.PHPRelay.AccountVolumePerHour = 90 // > 0.95 * 100 = 95
	eff, ok, capped := deriveEffectiveAccountLimit(cfg, 100, cpanelLimitOK)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if eff != 90 {
		t.Errorf("expected operator value preserved when below cap, got %d", eff)
	}
	if capped {
		t.Error("not capped here -- 90 < 95")
	}
}

func TestEffectiveAccountLimit_OperatorOverrideAboveCap(t *testing.T) {
	cfg := &config.Config{}
	cfg.EmailProtection.PHPRelay.AccountVolumePerHour = 200
	eff, ok, capped := deriveEffectiveAccountLimit(cfg, 100, cpanelLimitOK)
	if !ok || !capped {
		t.Fatalf("expected ok=true, capped=true, got ok=%v capped=%v", ok, capped)
	}
	if eff != 95 { // floor(0.95 * 100)
		t.Errorf("eff = %d, want 95", eff)
	}
}

func TestEffectiveAccountLimit_LowCpanelLimit_BelowFloor(t *testing.T) {
	cfg := &config.Config{}
	cfg.EmailProtection.PHPRelay.AccountVolumePerHour = 0
	eff, ok, _ := deriveEffectiveAccountLimit(cfg, 10, cpanelLimitOK)
	if !ok {
		t.Fatal("must remain enabled when cap < 20")
	}
	// cap = floor(0.95 * 10) = 9; auto target = max(20, min(60, 6)) = 20
	// effective = min(20, 9) = 9
	if eff != 9 {
		t.Errorf("eff = %d, want 9 (cap below floor)", eff)
	}
}

func TestEffectiveAccountLimit_DisabledByOperatorWithoutOverride(t *testing.T) {
	cfg := &config.Config{}
	cfg.EmailProtection.PHPRelay.AccountVolumePerHour = 0
	_, ok, _ := deriveEffectiveAccountLimit(cfg, 0, cpanelLimitDisabled)
	if ok {
		t.Error("Path 2b must be disabled when cpanel limit is off and no operator override")
	}
}

func TestEffectiveAccountLimit_DisabledByOperatorWithOverride(t *testing.T) {
	cfg := &config.Config{}
	cfg.EmailProtection.PHPRelay.AccountVolumePerHour = 150
	eff, ok, _ := deriveEffectiveAccountLimit(cfg, 0, cpanelLimitDisabled)
	if !ok || eff != 150 {
		t.Errorf("expected enabled with eff=150, got eff=%d ok=%v", eff, ok)
	}
}

func TestEffectiveAccountLimit_MissingAssumesDefault100(t *testing.T) {
	cfg := &config.Config{}
	cfg.EmailProtection.PHPRelay.AccountVolumePerHour = 0
	eff, ok, _ := deriveEffectiveAccountLimit(cfg, 0, cpanelLimitMissing)
	if !ok || eff != 60 {
		t.Errorf("missing should fall back to default 100 + auto-derive 60, got eff=%d ok=%v", eff, ok)
	}
}

func TestParsePHPRelayAccountVolume_FiresOnEffectiveLimit(t *testing.T) {
	cfg := defaultPHPRelayCfg()
	cfg.EmailProtection.PHPRelay.AccountVolumePerHour = 5
	pacct := newPerAccountWindow(5000)
	eng := newEvaluator(nil, nil, pacct, cfg, nil)
	eng.SetEffectiveAccountLimit(5)

	line := "2026-04-29 12:00:01 1abc-DEF <= info@occonsultingcy.com U=exampleuser ID=1168 B=redirect_resolver"

	var findings []alert.Finding
	for i := 0; i < 6; i++ {
		findings = append(findings, eng.parsePHPRelayAccountVolume(line, time.Now())...)
	}
	fired := 0
	for _, f := range findings {
		if f.Path == "volume_account" {
			fired++
			if f.CPUser != "exampleuser" {
				t.Errorf("CPUser = %q", f.CPUser)
			}
		}
	}
	if fired == 0 {
		t.Errorf("expected at least one volume_account finding, got %+v", findings)
	}
}

func TestParsePHPRelayAccountVolume_IgnoresNonRedirectResolver(t *testing.T) {
	cfg := defaultPHPRelayCfg()
	cfg.EmailProtection.PHPRelay.AccountVolumePerHour = 1
	pacct := newPerAccountWindow(5000)
	eng := newEvaluator(nil, nil, pacct, cfg, nil)
	eng.SetEffectiveAccountLimit(1)

	// Forwarder shape: no B=redirect_resolver.
	line := "2026-04-29 12:00:01 1abc-DEF <= bounce-mc.us1@mcsv.example U=exampleuser ID=1168"
	findings := eng.parsePHPRelayAccountVolume(line, time.Now())
	if len(findings) != 0 {
		t.Errorf("forwarder line must not feed Path 2b, got %+v", findings)
	}
}

func TestParsePHPRelayAccountVolume_CooldownSuppressesRefire(t *testing.T) {
	cfg := defaultPHPRelayCfg()
	cfg.EmailProtection.PHPRelay.AccountVolumePerHour = 1
	pacct := newPerAccountWindow(5000)
	eng := newEvaluator(nil, nil, pacct, cfg, nil)
	eng.SetEffectiveAccountLimit(1)

	line := "2026-04-29 12:00:01 1abc-DEF <= info@example.com U=exampleuser ID=1168 B=redirect_resolver"
	now := time.Now()
	a := eng.parsePHPRelayAccountVolume(line, now)
	if len(a) == 0 {
		t.Fatal("first call should fire")
	}
	b := eng.parsePHPRelayAccountVolume(line, now.Add(time.Minute))
	for _, f := range b {
		if f.Path == "volume_account" {
			t.Errorf("cooldown must suppress: %+v", f)
		}
	}
}
