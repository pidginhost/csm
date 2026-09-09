package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall/rollback"
	"github.com/pidginhost/csm/internal/store"
)

func TestObserveModeReloadWaitsForRestart(t *testing.T) {
	for _, initial := range []string{config.ModeObserve, config.ModeEnforce} {
		t.Run(initial, func(t *testing.T) {
			cfg := &config.Config{Mode: initial}
			cfg.AutoResponse.DisableEnforceAFAlg = true
			path := filepath.Join(t.TempDir(), "csm.yaml")
			seedConfigAtPath(t, path, cfg)
			cfg, err := config.LoadWithDir(path, "")
			if err != nil {
				t.Fatal(err)
			}
			d := newDaemonForReloadTest(t, cfg)
			edited := *cfg
			edited.Mode = config.ModeObserve
			if initial == config.ModeObserve {
				edited.Mode = config.ModeEnforce
			}
			if err = config.Save(&edited); err != nil {
				t.Fatal(err)
			}
			d.reloadConfig()
			if d.Mode() != initial || d.currentCfg().Mode != initial {
				t.Fatalf("mode switched live: %q", d.Mode())
			}
			select {
			case finding := <-d.alertCh:
				if finding.Check != "config_reload_restart_required" || !strings.Contains(finding.Message, "mode") {
					t.Fatalf("reload finding = %+v", finding)
				}
			default:
				t.Fatal("missing restart-required finding")
			}
			onDisk, err := config.LoadWithDir(path, "")
			if err != nil {
				t.Fatal(err)
			}
			if onDisk.Mode != edited.Mode {
				t.Fatalf("pending mode overwritten: %q", onDisk.Mode)
			}
		})
	}
}

func TestObserveModeReloadRejectsHostActionWithoutRewriting(t *testing.T) {
	cfg := &config.Config{Mode: config.ModeObserve}
	cfg.AutoResponse.DisableEnforceAFAlg = true
	path := filepath.Join(t.TempDir(), "csm.yaml")
	seedConfigAtPath(t, path, cfg)
	cfg, err := config.LoadWithDir(path, "")
	if err != nil {
		t.Fatal(err)
	}
	d := newDaemonForReloadTest(t, cfg)
	edited := *cfg
	edited.AutoResponse.CopyFailKillProcess = true
	if err = config.Save(&edited); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	d.reloadConfig()
	if d.currentCfg() != cfg || cfg.AutoResponse.CopyFailKillProcess {
		t.Fatal("rejected reload changed the live config")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(before) {
		t.Fatalf("rejected reload rewrote config: err=%v", err)
	}
	select {
	case finding := <-d.alertCh:
		if finding.Check != "config_reload_error" || !strings.Contains(finding.Message, "auto_response.copy_fail_kill_process") {
			t.Fatalf("reload finding = %+v", finding)
		}
	default:
		t.Fatal("missing reload error")
	}
}

func TestObserveStartupRefusesPendingFirewallRecovery(t *testing.T) {
	for _, kind := range []string{"config expired", "config future", "rules expired", "rules future"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			cfgPath := filepath.Join(dir, "csm.yaml")
			body := "hostname: test\nmode: observe\nauto_response:\n  disable_enforce_af_alg: true\n"
			writeTestFile(t, cfgPath, body)
			// Keep startup isolated from real services and stop before watchers
			// even if the recovery gate is bypassed.
			writeTestFile(t, filepath.Join(dir, "systemctl"), "#!/bin/sh\nexit 0\n")
			if err := os.Chmod(filepath.Join(dir, "systemctl"), 0o700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			db, err := store.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			oldDB, oldManager, oldCfg := store.Global(), rollback.Global(), config.Active()
			store.SetGlobal(db)
			t.Cleanup(func() {
				if m := rollback.Global(); m != nil && m != oldManager {
					_ = m.Confirm()
				}
				rollback.SetGlobal(oldManager)
				store.SetGlobal(oldDB)
				config.SetActive(oldCfg)
				_ = db.Close()
			})
			deadline := time.Now().Add(-time.Hour)
			if strings.HasSuffix(kind, "future") {
				deadline = time.Now().Add(time.Hour)
			}
			marker, _, _ := firewallRollbackFiles(dir)
			if strings.HasPrefix(kind, "config") {
				if err = db.SaveFirewallRollback(store.FirewallRollback{PrevYAML: []byte("mode: enforce\n"), ExpiresAt: deadline}); err != nil {
					t.Fatal(err)
				}
			} else {
				if err = os.MkdirAll(filepath.Dir(marker), 0o700); err != nil {
					t.Fatal(err)
				}
				writeTestFile(t, marker, deadline.Format(time.RFC3339Nano))
			}
			cfg := &config.Config{Mode: config.ModeObserve, StatePath: dir, ConfigFile: cfgPath}
			cfg.Integrity.BinaryHash = "sha256:invalid"
			d := &Daemon{cfg: cfg, binaryPath: filepath.Join(dir, "absent-binary")}
			err = d.Run()
			if err == nil || !strings.Contains(err.Error(), "observe") || !strings.Contains(err.Error(), "pending firewall") {
				t.Errorf("startup error = %v, want observe-mode pending firewall error", err)
			}
			got, err := os.ReadFile(cfgPath)
			if err != nil || string(got) != body {
				t.Errorf("startup changed config: err=%v", err)
			}
			if strings.HasPrefix(kind, "config") {
				if _, ok := db.GetFirewallRollback(); !ok {
					t.Error("pending rollback was consumed")
				}
			} else {
				got, err := os.ReadFile(marker)
				if err != nil || string(got) != deadline.Format(time.RFC3339Nano) {
					t.Errorf("pending rules marker changed: err=%v", err)
				}
			}
		})
	}
}

func TestObserveStartupRecoveryGate(t *testing.T) {
	prev := store.Global()
	store.SetGlobal(nil)
	t.Cleanup(func() { store.SetGlobal(prev) })
	d := &Daemon{cfg: &config.Config{Mode: config.ModeObserve, StatePath: t.TempDir()}}
	if err := d.checkObserveStartupRecovery(); err != nil {
		t.Fatalf("startup with no pending recovery: %v", err)
	}
	writeTestFile(t, filepath.Join(d.cfg.StatePath, "firewall"), "not a directory")
	if err := d.checkObserveStartupRecovery(); err == nil || !strings.Contains(err.Error(), "cannot check pending firewall recovery") {
		t.Fatalf("unreadable recovery state accepted: %v", err)
	}
	d.cfg.Mode = config.ModeEnforce
	if err := d.checkObserveStartupRecovery(); err != nil {
		t.Fatalf("observe gate changed enforce startup: %v", err)
	}
}

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
