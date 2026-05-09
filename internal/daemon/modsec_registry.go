package daemon

import (
	"time"

	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/modsec"
	"github.com/pidginhost/csm/internal/obs"
	"github.com/pidginhost/csm/internal/platform"
)

// modsecRegistryRefresh controls how often the rule-action registry is
// rebuilt from disk. ModSec rule files change rarely (vendor pack updates,
// cPanel modsec_assemble nightly run), so a coarse interval keeps the cost
// negligible while still picking up operator edits within minutes.
const modsecRegistryRefresh = 5 * time.Minute

// initModSecRegistry builds the rule-action registry once at startup and
// installs it as the package-level singleton. The registry tells the
// LiteSpeed log-line classifier which "triggered!" matches actually denied
// the request and which were pass-action informational rules. Without this,
// pass-action vendor rules (Comodo CWAF id 210710, 214930, ...) would be
// counted as denies, falsely escalating to a 24-hour auto-block of any IP
// that hits them three times in ten minutes.
//
// The build is failure-soft: missing rule directories yield an empty
// registry, which the classifier interprets the same way as the legacy
// behaviour (default to block on unknown rule). New installs and hosts
// without ModSecurity therefore see no behaviour change.
func (d *Daemon) initModSecRegistry() {
	d.refreshModSecRegistry()
	d.wg.Add(1)
	obs.Go("modsec-registry-refresh", d.modsecRegistryRefreshLoop)
}

func (d *Daemon) refreshModSecRegistry() {
	dirs := modsec.RuleDirs(platform.Detect())
	reg, err := modsec.BuildRegistry(dirs)
	if err != nil {
		csmlog.Warn("modsec rule-action registry build had errors", "err", err, "rules_loaded", reg.Len())
	}
	modsec.SetGlobal(reg)
	csmlog.Info("modsec rule-action registry loaded", "rules", reg.Len(), "dirs", len(dirs))
}

func (d *Daemon) modsecRegistryRefreshLoop() {
	defer d.wg.Done()
	ticker := time.NewTicker(modsecRegistryRefresh)
	defer ticker.Stop()
	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			d.refreshModSecRegistry()
		}
	}
}
