//go:build linux

package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
)

func TestFirewallStartupDoesNotRetryStatePreservationFailure(t *testing.T) {
	dir := t.TempDir()
	fwDir := filepath.Join(dir, "firewall")
	if err := os.Mkdir(fwDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("state.json", filepath.Join(fwDir, "state.json")); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Firewall: &firewall.FirewallConfig{Enabled: true}, StatePath: dir}
	d := New(cfg, nil, nil, "")
	attempts := 0
	d.startFirewallUsing(firewallStartupOps{
		newEngine: func(cfg *firewall.FirewallConfig, path string) (*firewall.Engine, error) {
			attempts++
			return firewall.NewEngine(cfg, path)
		},
		apply:  (*firewall.Engine).Apply,
		delays: []time.Duration{0, 0},
	})
	if attempts != 1 || d.fwEngine != nil || d.AutomationStatus().FirewallStartupError == "" {
		t.Fatalf("unsafe retry after a state refusal: attempts=%d engine=%p error=%q", attempts, d.fwEngine, d.fwStartupError)
	}
}

func TestFirewallStartupPublishesRecoveredEngine(t *testing.T) {
	const kept = "/var/lib/csm/firewall/state.json.unreadable-20260301T120000Z"
	cfg := &config.Config{Firewall: &firewall.FirewallConfig{Enabled: true}, StatePath: t.TempDir()}
	previousCfg := config.Active()
	config.SetActive(cfg)
	previousBlocker := incidentSprayBlocker
	firewallMetricsMu.RLock()
	previousMetricsEngine := firewallMetricsEngine
	firewallMetricsMu.RUnlock()
	t.Cleanup(func() {
		config.SetActive(previousCfg)
		checks.SetIPBlocker(nil)
		SetIncidentSprayBlocker(previousBlocker)
		setFirewallMetricsEngine(previousMetricsEngine)
	})
	d := New(cfg, nil, nil, "")
	defer close(d.stopCh)
	d.fwStartupError = "previous startup failure"
	previousHook := alert.CentralHook
	alerts := 0
	alert.SetCentralHook(func(f alert.Finding) {
		if f.Check == "firewall_state_unreadable" {
			alerts++
		}
	})
	t.Cleanup(func() { alert.SetCentralHook(previousHook) })
	var attempts []*firewall.Engine
	d.startFirewallUsing(firewallStartupOps{
		newEngine: firewall.NewEngine,
		apply: func(engine *firewall.Engine) error {
			if d.fwEngine != nil {
				t.Fatal("engine published before successful apply")
			}
			attempts = append(attempts, engine)
			if len(attempts) < 3 {
				return errors.New("temporary netlink failure")
			}
			return nil
		},
		setAside: func(engine *firewall.Engine) string {
			if engine == attempts[0] {
				return kept
			}
			return ""
		},
		delays: []time.Duration{0, 0},
	})
	if len(attempts) != 3 || d.fwEngine != attempts[2] {
		t.Fatalf("successful engine was not published after three attempts: %v", attempts)
	}
	if attempts[0] == attempts[1] || attempts[1] == attempts[2] || attempts[0] == attempts[2] {
		t.Fatal("startup reused an engine after a failed transaction")
	}
	status := d.AutomationStatus()
	if !status.FirewallEnabled || !status.FirewallManaged || status.FirewallStartupError != "" {
		t.Fatalf("recovery did not clear degraded firewall state: %+v", status)
	}
	if status.FirewallStateSetAside != kept || alerts != 1 {
		t.Fatalf("successful retry lost or repeated the kept state report: path=%q alerts=%d", status.FirewallStateSetAside, alerts)
	}
	if incidentSprayBlocker == nil {
		t.Fatal("recovery did not wire the incident blocker")
	}
}
