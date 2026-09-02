package daemon

import "github.com/pidginhost/csm/internal/checks"

// reconcileReputationWhitelist pushes the live config's reputation.whitelist
// into the running threat database. The field is tagged safe for hot reload,
// so a SIGHUP that only changes it reports success; without this push the
// threat database kept the startup list until a full restart. Called from the
// reload success path, mirroring reconcileVerifiedBots.
func (d *Daemon) reconcileReputationWhitelist() {
	cfg := d.activeOrStartupCfg()
	if cfg == nil {
		return
	}
	if db := checks.GetThreatDB(); db != nil {
		db.SetConfigWhitelist(cfg.Reputation.Whitelist)
	}
}
