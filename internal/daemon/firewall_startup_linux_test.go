//go:build linux

package daemon

import (
	"errors"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
)

func TestFirewallStartupPublishesRecoveredEngine(t *testing.T) {
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
	if incidentSprayBlocker == nil {
		t.Fatal("recovery did not wire the incident blocker")
	}
}
