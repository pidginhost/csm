package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadBytesForwardGuardDefaults(t *testing.T) {
	cfg, err := LoadBytes([]byte(""))
	if err != nil {
		t.Fatal(err)
	}
	fg := cfg.EmailProtection.ForwardGuard
	if fg.Enabled {
		t.Error("forward_guard must default OFF")
	}
	if !fg.DryRun {
		t.Error("forward_guard must default to dry_run=true (safety)")
	}
	if !fg.HoldSignals.BounceBackscatter || !fg.HoldSignals.SpamFlagged ||
		!fg.HoldSignals.Malware || !fg.HoldSignals.BadSenderIP || !fg.HoldSignals.AuthFail {
		t.Error("all hold signals default on (only matter once enabled)")
	}
	if fg.QuarantineRetentionDays != 14 {
		t.Errorf("retention = %d, want 14", fg.QuarantineRetentionDays)
	}
}

func TestLoadBytesForwardGuardExplicitFalseHonored(t *testing.T) {
	yaml := `
email_protection:
  forward_guard:
    dry_run: false
    hold_signals:
      bounce_backscatter: false
      spam_flagged: false
      malware: false
      bad_sender_ip: false
      auth_fail: false
`
	cfg, err := LoadBytes([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	fg := cfg.EmailProtection.ForwardGuard
	if fg.DryRun {
		t.Error("explicit dry_run:false overwritten by default-true")
	}
	if fg.HoldSignals.BounceBackscatter {
		t.Error("explicit bounce_backscatter:false overwritten")
	}
	if fg.HoldSignals.BadSenderIP {
		t.Error("explicit bad_sender_ip:false overwritten")
	}
	if fg.HoldSignals.SpamFlagged {
		t.Error("explicit spam_flagged:false overwritten")
	}
	if fg.HoldSignals.Malware {
		t.Error("explicit malware:false overwritten")
	}
	if fg.HoldSignals.AuthFail {
		t.Error("explicit auth_fail:false overwritten")
	}
}

func TestLoadBytesForwardGuardExplicitTrueHonored(t *testing.T) {
	yaml := `
email_protection:
  forward_guard:
    dry_run: true
    hold_signals:
      bounce_backscatter: true
      spam_flagged: true
      malware: true
      bad_sender_ip: true
      auth_fail: true
`
	cfg, err := LoadBytes([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	fg := cfg.EmailProtection.ForwardGuard
	if !fg.DryRun || !fg.HoldSignals.BounceBackscatter || !fg.HoldSignals.SpamFlagged ||
		!fg.HoldSignals.Malware || !fg.HoldSignals.BadSenderIP || !fg.HoldSignals.AuthFail {
		t.Fatalf("explicit true forward_guard values were not preserved: %+v", fg)
	}
}

func TestLoadBytesForwardGuardRetentionExplicitlySet(t *testing.T) {
	cfg, err := LoadBytes([]byte("email_protection:\n  forward_guard:\n    quarantine_retention_days: 30\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.EmailProtection.ForwardGuard.QuarantineRetentionDays != 30 {
		t.Errorf("retention = %d, want 30", cfg.EmailProtection.ForwardGuard.QuarantineRetentionDays)
	}
}

func TestLoadWithDirForwardGuardExplicitFalseHonoredInFragment(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "csm.yaml")
	confd := filepath.Join(dir, "conf.d")
	must(t, os.MkdirAll(confd, 0o700))
	must(t, os.WriteFile(main, []byte("hostname: main-host\n"), 0o600))
	must(t, os.WriteFile(filepath.Join(confd, "10-forward-guard.yaml"), []byte(`
email_protection:
  forward_guard:
    dry_run: false
    hold_signals:
      bounce_backscatter: false
      spam_flagged: false
      malware: false
      bad_sender_ip: false
      auth_fail: false
`), 0o600))

	cfg, err := LoadWithDir(main, confd)
	if err != nil {
		t.Fatal(err)
	}
	fg := cfg.EmailProtection.ForwardGuard
	if fg.DryRun {
		t.Error("conf.d explicit dry_run:false overwritten by default-true")
	}
	if fg.HoldSignals.BounceBackscatter || fg.HoldSignals.SpamFlagged ||
		fg.HoldSignals.Malware || fg.HoldSignals.BadSenderIP || fg.HoldSignals.AuthFail {
		t.Fatalf("conf.d explicit hold signal false overwritten: %+v", fg.HoldSignals)
	}
}

func TestLoadWithDirForwardGuardExplicitTrueHonoredInFragment(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "csm.yaml")
	confd := filepath.Join(dir, "conf.d")
	must(t, os.MkdirAll(confd, 0o700))
	must(t, os.WriteFile(main, []byte("hostname: main-host\n"), 0o600))
	must(t, os.WriteFile(filepath.Join(confd, "10-forward-guard.yaml"), []byte(`
email_protection:
  forward_guard:
    dry_run: true
    hold_signals:
      bounce_backscatter: true
      spam_flagged: true
      malware: true
      bad_sender_ip: true
      auth_fail: true
`), 0o600))

	cfg, err := LoadWithDir(main, confd)
	if err != nil {
		t.Fatal(err)
	}
	fg := cfg.EmailProtection.ForwardGuard
	if !fg.DryRun || !fg.HoldSignals.BounceBackscatter || !fg.HoldSignals.SpamFlagged ||
		!fg.HoldSignals.Malware || !fg.HoldSignals.BadSenderIP || !fg.HoldSignals.AuthFail {
		t.Fatalf("conf.d explicit true forward_guard values were not preserved: %+v", fg)
	}
}

func TestForwardGuardValidationRejectsEnforceWithNoEnforceableSignal(t *testing.T) {
	// enabled + not dry-run, but both routing-time-enforceable signals (bounce,
	// bad_sender_ip) are off and only the not-yet-enforceable signals are on.
	yaml := `
email_protection:
  forward_guard:
    enabled: true
    dry_run: false
    hold_signals:
      bounce_backscatter: false
      bad_sender_ip: false
      spam_flagged: true
      malware: true
      auth_fail: true
`
	if _, err := LoadBytes([]byte(yaml)); err == nil {
		t.Fatal("expected validation error: enforce mode with no enforceable signal")
	}
}

func TestForwardGuardValidationDisabledNeverErrors(t *testing.T) {
	yaml := `
email_protection:
  forward_guard:
    enabled: false
    dry_run: false
    quarantine_retention_days: 0
    hold_signals:
      bounce_backscatter: false
      spam_flagged: false
      malware: false
      bad_sender_ip: false
      auth_fail: false
`
	if _, err := LoadBytes([]byte(yaml)); err != nil {
		t.Fatalf("disabled forward_guard must not validate active-mode invariants: %v", err)
	}
}

func TestForwardGuardValidationAllowsEnforceWithEnforceableSignal(t *testing.T) {
	yaml := `
email_protection:
  forward_guard:
    enabled: true
    dry_run: false
    hold_signals:
      bounce_backscatter: true
      bad_sender_ip: false
`
	if _, err := LoadBytes([]byte(yaml)); err != nil {
		t.Fatalf("valid enforce config rejected: %v", err)
	}
}

func TestForwardGuardValidationAllowsDryRunWithUnenforceableOnly(t *testing.T) {
	// In dry-run, accounting may preview spam/malware/auth even though the exim
	// adapter cannot enforce them yet -- must not be rejected.
	yaml := `
email_protection:
  forward_guard:
    enabled: true
    dry_run: true
    hold_signals:
      bounce_backscatter: false
      bad_sender_ip: false
      spam_flagged: true
`
	if _, err := LoadBytes([]byte(yaml)); err != nil {
		t.Fatalf("valid dry-run config rejected: %v", err)
	}
}

func TestForwardGuardValidationRejectsZeroRetentionWhenEnabled(t *testing.T) {
	yaml := `
email_protection:
  forward_guard:
    enabled: true
    dry_run: true
    quarantine_retention_days: 0
`
	if _, err := LoadBytes([]byte(yaml)); err == nil {
		t.Fatal("expected validation error: zero retention while enabled")
	}
}
