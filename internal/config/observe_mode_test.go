package config

import (
	"strings"
	"testing"
)

func TestModeDefaultsToEnforce(t *testing.T) {
	cfg, err := LoadBytes([]byte("hostname: test\n"))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if cfg.Mode != ModeEnforce {
		t.Fatalf("mode = %q, want %q", cfg.Mode, ModeEnforce)
	}
	if cfg.ObserveMode() {
		t.Fatal("default config reports observe mode")
	}
}

func TestUnknownModeIsRejected(t *testing.T) {
	_, err := LoadBytes([]byte("hostname: test\nmode: audit\n"))
	if err == nil {
		t.Fatal("unknown mode accepted")
	}
	if !strings.Contains(err.Error(), "mode") {
		t.Fatalf("error does not name the mode key: %v", err)
	}
}

func TestObserveModeAcceptsDetectionOnlyConfig(t *testing.T) {
	cfg, err := LoadBytes([]byte("hostname: test\nmode: observe\n"))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if !cfg.ObserveMode() {
		t.Fatal("mode: observe does not report observe mode")
	}
}

// Observe mode never rewrites the operator's settings: a contradictory config
// is refused by name so nothing silently runs in a posture the operator did
// not choose. Rewriting the loaded struct instead would be persisted by the
// config re-signing path, which marshals the in-memory config back to disk.
func TestObserveModeRejectsEveryHostMutatingSwitch(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		key  string
	}{
		{"auto response", "auto_response:\n  enabled: true\n", "auto_response.enabled"},
		{"firewall", "firewall:\n  enabled: true\n", "firewall.enabled"},
		{"php shield", "php_shield:\n  enabled: true\n", "php_shield.enabled"},
		{"bpf enforcement", "bpf_enforcement:\n  enabled: true\n", "bpf_enforcement.enabled"},
		{"forward guard", "email_protection:\n  forward_guard:\n    enabled: true\n", "email_protection.forward_guard.enabled"},
		{"email av quarantine", "email_av:\n  enabled: true\n  quarantine_infected: true\n", "email_av.quarantine_infected"},
		{"php relay freeze", "auto_response:\n  php_relay:\n    freeze: true\n", "auto_response.php_relay.freeze"},
		{"mail auth restart", "auto_response:\n  mail_auth_recovery:\n    restart_enabled: true\n", "auto_response.mail_auth_recovery.restart_enabled"},
		{"virtual patch auto", "auto_response:\n  virtual_patch_exposed_files: auto\n", "auto_response.virtual_patch_exposed_files"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadBytes([]byte("hostname: test\nmode: observe\n" + tc.yaml))
			if err == nil {
				t.Fatalf("observe mode accepted %s", tc.key)
			}
			if !strings.Contains(err.Error(), tc.key) {
				t.Fatalf("error does not name %s: %v", tc.key, err)
			}
		})
	}
}

func TestObserveModeReportsEveryConflictAtOnce(t *testing.T) {
	_, err := LoadBytes([]byte("hostname: test\nmode: observe\nauto_response:\n  enabled: true\nfirewall:\n  enabled: true\n"))
	if err == nil {
		t.Fatal("observe mode accepted two conflicting switches")
	}
	for _, key := range []string{"auto_response.enabled", "firewall.enabled"} {
		if !strings.Contains(err.Error(), key) {
			t.Errorf("error does not name %s: %v", key, err)
		}
	}
}

// Manual virtual patching stays available: it only writes when an operator
// runs `csm virtual-patch`, which is an explicit action, not daemon behaviour.
func TestObserveModeAllowsManualVirtualPatch(t *testing.T) {
	if _, err := LoadBytes([]byte("hostname: test\nmode: observe\nauto_response:\n  virtual_patch_exposed_files: manual\n")); err != nil {
		t.Fatalf("observe mode rejected manual virtual patching: %v", err)
	}
}

func TestEnforceModeLeavesEveryStateSwitchAlone(t *testing.T) {
	cfg, err := LoadBytes([]byte("hostname: test\nauto_response:\n  enabled: true\nfirewall:\n  enabled: true\n"))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if !cfg.AutoResponse.Enabled || cfg.Firewall == nil || !cfg.Firewall.Enabled {
		t.Fatal("enforce mode altered the operator's switches")
	}
}

func TestValidateReportsTheActiveMode(t *testing.T) {
	cfg, err := LoadBytes([]byte("hostname: test\nmode: observe\nalerts:\n  email:\n    enabled: true\n    to: [ops@example.com]\n"))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if !hasResult(Validate(cfg), "ok", "mode") {
		t.Fatal("validation does not report the active mode")
	}
}
