package checks

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/bpf"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
)

// CheckHealth warns about missing required/optional commands and missing
// auditd rules. Drive it with mocked LookPath responses and platform
// overrides so we can exercise the cPanel/non-cPanel branches.

func TestCheckHealthPlainLinuxAllCommandsPresent(t *testing.T) {
	platform.ResetForTest()
	t.Cleanup(platform.ResetForTest)
	platform.SetOverrides(platform.Overrides{
		Panel: ptrPanel(platform.PanelNone),
	})
	withMockCmd(t, &mockCmd{
		lookPath: func(name string) (string, error) {
			return "/usr/bin/" + name, nil
		},
		run: func(name string, args ...string) ([]byte, error) {
			if name == "auditctl" {
				return []byte("-w /etc/shadow -p wa -k csm_shadow_change\n"), nil
			}
			return nil, nil
		},
	})

	got := CheckHealth(context.Background(), &config.Config{}, nil)
	for _, f := range got {
		if strings.Contains(f.Message, "Required command not found") {
			t.Errorf("no required-command findings expected, got %+v", f)
		}
	}
}

func TestCheckHealthUsesConfiguredStatePath(t *testing.T) {
	platform.ResetForTest()
	t.Cleanup(platform.ResetForTest)
	platform.SetOverrides(platform.Overrides{
		Panel: ptrPanel(platform.PanelNone),
	})
	withMockCmd(t, &mockCmd{
		lookPath: func(name string) (string, error) {
			return "/usr/bin/" + name, nil
		},
		run: func(name string, args ...string) ([]byte, error) {
			if name == "auditctl" {
				return []byte("-w /etc/shadow -p wa -k csm_shadow_change\n"), nil
			}
			return nil, nil
		},
	})

	statePath := t.TempDir()
	got := CheckHealth(context.Background(), &config.Config{StatePath: statePath}, nil)
	for _, f := range got {
		if strings.Contains(f.Message, "State directory not writable") {
			t.Fatalf("configured state path should be writable, got %+v", f)
		}
	}
}

func TestCheckHealthPlainLinuxMissingRequiredCommand(t *testing.T) {
	platform.ResetForTest()
	t.Cleanup(platform.ResetForTest)
	platform.SetOverrides(platform.Overrides{
		Panel: ptrPanel(platform.PanelNone),
	})
	withMockCmd(t, &mockCmd{
		lookPath: func(name string) (string, error) {
			if name == "find" || name == "auditctl" {
				return "", errors.New("not found")
			}
			return "/usr/bin/" + name, nil
		},
	})

	got := CheckHealth(context.Background(), &config.Config{}, nil)
	missingFind, missingAudit := false, false
	for _, f := range got {
		if strings.Contains(f.Message, "find") {
			missingFind = true
		}
		if strings.Contains(f.Message, "auditctl") {
			missingAudit = true
		}
	}
	if !missingFind {
		t.Error("expected a 'find' missing-command finding")
	}
	if !missingAudit {
		t.Error("expected an 'auditctl' missing-command finding")
	}
}

func TestCheckHealthCPanelRequiresExim(t *testing.T) {
	platform.ResetForTest()
	t.Cleanup(platform.ResetForTest)
	platform.SetOverrides(platform.Overrides{
		Panel: ptrPanel(platform.PanelCPanel),
	})
	withMockCmd(t, &mockCmd{
		lookPath: func(name string) (string, error) {
			if name == "exim" {
				return "", errors.New("not found")
			}
			return "/usr/bin/" + name, nil
		},
	})

	got := CheckHealth(context.Background(), &config.Config{}, nil)
	hasExim := false
	for _, f := range got {
		if strings.Contains(f.Message, "exim") && f.Severity == alert.Warning {
			hasExim = true
		}
	}
	if !hasExim {
		t.Errorf("expected exim missing-command finding on cPanel, got %+v", got)
	}
}

func TestCheckHealthCPanelReportsMissingWhmapi1AsOptional(t *testing.T) {
	platform.ResetForTest()
	t.Cleanup(platform.ResetForTest)
	platform.SetOverrides(platform.Overrides{
		Panel: ptrPanel(platform.PanelCPanel),
	})
	withMockCmd(t, &mockCmd{
		lookPath: func(name string) (string, error) {
			if name == "whmapi1" || name == "wp" {
				return "", errors.New("not found")
			}
			return "/usr/bin/" + name, nil
		},
	})

	got := CheckHealth(context.Background(), &config.Config{}, nil)
	hasWhmapi1, hasWP := false, false
	for _, f := range got {
		if strings.Contains(f.Message, "whmapi1") && strings.Contains(f.Message, "Optional") {
			hasWhmapi1 = true
		}
		if strings.Contains(f.Message, "wp") && strings.Contains(f.Message, "Optional") {
			hasWP = true
		}
	}
	if !hasWhmapi1 {
		t.Error("expected optional whmapi1 finding on cPanel")
	}
	if !hasWP {
		t.Error("expected optional wp finding")
	}
}

func TestCheckHealthNonCPanelDoesNotReportWhmapi1(t *testing.T) {
	platform.ResetForTest()
	t.Cleanup(platform.ResetForTest)
	platform.SetOverrides(platform.Overrides{
		Panel: ptrPanel(platform.PanelNone),
	})
	withMockCmd(t, &mockCmd{
		lookPath: func(string) (string, error) { return "", errors.New("nothing") },
	})

	got := CheckHealth(context.Background(), &config.Config{}, nil)
	for _, f := range got {
		if strings.Contains(f.Message, "whmapi1") {
			t.Errorf("non-cPanel host should not report whmapi1, got %+v", f)
		}
	}
}

func TestCheckHealthAuditdMissingCSMRulesEmitsWarning(t *testing.T) {
	platform.ResetForTest()
	t.Cleanup(platform.ResetForTest)
	platform.SetOverrides(platform.Overrides{
		Panel: ptrPanel(platform.PanelNone),
	})
	withMockCmd(t, &mockCmd{
		lookPath: func(name string) (string, error) { return "/usr/bin/" + name, nil },
		run: func(name string, args ...string) ([]byte, error) {
			if name == "auditctl" {
				// No CSM rules present.
				return []byte("No rules\n"), nil
			}
			return nil, nil
		},
	})

	got := CheckHealth(context.Background(), &config.Config{}, nil)
	hasAuditd := false
	for _, f := range got {
		if strings.Contains(f.Message, "auditd CSM rules not loaded") {
			hasAuditd = true
		}
	}
	if !hasAuditd {
		t.Error("expected auditd CSM rules warning")
	}
}

// --- platformRequiredCommands -----------------------------------------

func TestPlatformRequiredCommandsNonCPanel(t *testing.T) {
	info := platform.Info{Panel: platform.PanelNone}
	got := platformRequiredCommands(info)
	wantSet := map[string]bool{"find": true, "auditctl": true}
	for _, cmd := range got {
		if !wantSet[cmd] {
			t.Errorf("unexpected command in non-cPanel list: %s", cmd)
		}
		delete(wantSet, cmd)
	}
	if len(wantSet) != 0 {
		t.Errorf("missing commands: %v", wantSet)
	}
}

func setupCheckHealthBPFTest(t *testing.T) {
	t.Helper()
	platform.ResetForTest()
	t.Cleanup(platform.ResetForTest)
	platform.SetOverrides(platform.Overrides{Panel: ptrPanel(platform.PanelNone)})
	withMockCmd(t, &mockCmd{
		lookPath: func(name string) (string, error) { return "/usr/bin/" + name, nil },
		run: func(name string, _ ...string) ([]byte, error) {
			if name == "auditctl" {
				return []byte("-w /etc/shadow -p wa -k csm_shadow_change\n"), nil
			}
			return nil, nil
		},
	})
}

func validBPFEnforcementHealthConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := &config.Config{}
	cfg.Detection.ConnectionTrackerBackend = bpf.BackendAuto
	cfg.Detection.DirectSMTPEgress.Enabled = true
	cfg.Detection.DirectSMTPEgress.Backend = bpf.BackendAuto
	cfg.BPFEnforcement.Enabled = true
	cfg.BPFEnforcement.DirectSMTPEgress = true
	cfg.StatePath = t.TempDir()
	return cfg
}

func findBPFHealthFinding(findings []alert.Finding) (alert.Finding, bool) {
	for _, f := range findings {
		if f.Check == "csm_health" && strings.Contains(f.Message, "BPF") {
			return f, true
		}
	}
	return alert.Finding{}, false
}

func TestCheckHealth_WarnsWhenBPFEnforcementConfiguredButLegacy(t *testing.T) {
	setupCheckHealthBPFTest(t)
	bpf.SetActive("connection_tracker", bpf.BackendLegacy)
	t.Cleanup(func() { bpf.SetActive("connection_tracker", "") })

	got := CheckHealth(context.Background(), validBPFEnforcementHealthConfig(t), nil)
	f, found := findBPFHealthFinding(got)
	if !found {
		t.Fatalf("expected BPF-degraded csm_health finding, got %+v", got)
	}
	if f.Severity != alert.Warning {
		t.Errorf("BPF degraded finding severity = %v, want Warning", f.Severity)
	}
	if !strings.Contains(f.Message, "legacy backend") {
		t.Errorf("BPF degraded finding message = %q, want legacy backend", f.Message)
	}
}

func TestCheckHealth_WarnsWhenBPFEnforcementConfiguredButNoBackend(t *testing.T) {
	setupCheckHealthBPFTest(t)
	bpf.SetActive("connection_tracker", bpf.BackendNone)
	t.Cleanup(func() { bpf.SetActive("connection_tracker", "") })

	got := CheckHealth(context.Background(), validBPFEnforcementHealthConfig(t), nil)
	f, found := findBPFHealthFinding(got)
	if !found {
		t.Fatalf("expected BPF-degraded csm_health finding, got %+v", got)
	}
	if f.Severity != alert.Warning {
		t.Errorf("BPF degraded finding severity = %v, want Warning", f.Severity)
	}
	if !strings.Contains(f.Message, "no active backend") {
		t.Errorf("BPF degraded finding message = %q, want no active backend", f.Message)
	}
}

func TestCheckHealth_NoBPFWarningWhenBPFActive(t *testing.T) {
	setupCheckHealthBPFTest(t)
	bpf.SetActive("connection_tracker", bpf.BackendBPF)
	t.Cleanup(func() { bpf.SetActive("connection_tracker", "") })

	got := CheckHealth(context.Background(), validBPFEnforcementHealthConfig(t), nil)
	if f, found := findBPFHealthFinding(got); found {
		t.Errorf("unexpected BPF-degraded finding when backend=bpf: %+v", f)
	}
}

func TestCheckHealth_NoBPFWarningWhenEnforcementDisabled(t *testing.T) {
	setupCheckHealthBPFTest(t)
	bpf.SetActive("connection_tracker", bpf.BackendLegacy)
	t.Cleanup(func() { bpf.SetActive("connection_tracker", "") })

	cfg := validBPFEnforcementHealthConfig(t)
	cfg.BPFEnforcement.Enabled = false

	got := CheckHealth(context.Background(), cfg, nil)
	if f, found := findBPFHealthFinding(got); found {
		t.Errorf("unexpected BPF finding when enforcement disabled: %+v", f)
	}
}

func TestCheckHealth_NoBPFWarningWhenEnforcementGateDisabled(t *testing.T) {
	setupCheckHealthBPFTest(t)
	bpf.SetActive("connection_tracker", bpf.BackendLegacy)
	t.Cleanup(func() { bpf.SetActive("connection_tracker", "") })

	cfg := validBPFEnforcementHealthConfig(t)
	cfg.BPFEnforcement.DirectSMTPEgress = false

	got := CheckHealth(context.Background(), cfg, nil)
	if f, found := findBPFHealthFinding(got); found {
		t.Errorf("unexpected BPF finding when enforcement gate disabled: %+v", f)
	}
}

func TestPlatformRequiredCommandsCPanelIncludesExim(t *testing.T) {
	info := platform.Info{Panel: platform.PanelCPanel}
	got := platformRequiredCommands(info)
	found := false
	for _, cmd := range got {
		if cmd == "exim" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'exim' in cPanel required commands, got %v", got)
	}
}
