package daemon

import (
	"fmt"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
)

// loadEffectiveFirewallFromDisk reads csm.yaml (and conf.d) again and returns
// the firewall block the daemon would build rules from at its next start.
// A SIGHUP reload deliberately leaves restart-required blocks such as
// firewall untouched in the live config, so the re-apply commands, whose
// whole purpose is to apply an edited firewall block under a deadman,
// must read the file rather than the live snapshot.
func loadEffectiveFirewallFromDisk(configFile, confDir string) (*firewall.FirewallConfig, error) {
	if configFile == "" {
		return nil, fmt.Errorf("config file path unknown")
	}
	cfg, err := config.LoadWithDir(configFile, confDir)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", configFile, err)
	}
	for _, res := range config.Validate(cfg) {
		if res.Level == "error" && len(res.Field) >= 8 && res.Field[:8] == "firewall" {
			return nil, fmt.Errorf("%s: %s", res.Field, res.Message)
		}
	}
	effective := config.EffectiveFirewallConfig(cfg)
	if effective == nil || !effective.Enabled {
		return nil, fmt.Errorf("firewall is disabled in %s; re-apply would drop the ruleset", configFile)
	}
	return effective, nil
}

// refreshFirewallFromDisk installs the on-disk firewall block into the
// running engine and returns the configuration it replaced, so a rollback
// can put it back. The previous configuration is returned even when the
// engine holds none (nil) so callers can always restore.
func (d *Daemon) refreshFirewallFromDisk() (previous *firewall.FirewallConfig, err error) {
	if d.fwEngine == nil {
		return nil, fmt.Errorf("firewall engine not running")
	}
	cfg := d.currentCfg()
	effective, err := loadEffectiveFirewallFromDisk(cfg.ConfigFile, cfg.ConfigDir)
	if err != nil {
		return nil, err
	}
	previous = d.fwEngine.Config()
	d.fwEngine.SetConfig(effective)
	return previous, nil
}
