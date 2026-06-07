package config

import "testing"

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
      bad_sender_ip: false
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
	// Signals not mentioned still default on.
	if !fg.HoldSignals.SpamFlagged || !fg.HoldSignals.Malware || !fg.HoldSignals.AuthFail {
		t.Error("unmentioned signals should still default on")
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
