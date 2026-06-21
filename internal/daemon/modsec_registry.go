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
// registry. With no prior healthy registry, ambiguous LiteSpeed "triggered!"
// lines are warnings until a later refresh loads rule actions.
func (d *Daemon) initModSecRegistry() {
	d.refreshModSecRegistry()
	d.wg.Add(1)
	obs.Go("modsec-registry-refresh", d.modsecRegistryRefreshLoop)
}

func (d *Daemon) refreshModSecRegistry() {
	// DetectFreshWithOverrides (not the cached Detect) so a web-server
	// mis-detection at boot -- LiteSpeed probed before lsws finished starting,
	// which points RuleDirs at non-existent directories -- self-heals on a
	// later refresh once the host has settled, instead of staying wrong (and
	// the registry empty) for the daemon's lifetime.
	dirs := modsec.RuleDirs(platform.DetectFreshWithOverrides())
	reg, err := modsec.BuildRegistry(dirs)
	if err != nil {
		csmlog.Warn("modsec rule-action registry build had errors", "err", err, "rules_loaded", reg.Len())
	}
	// ReplaceGlobal keeps a previously-healthy registry rather than blanking
	// it to empty: the vendor rule tree is briefly empty during cPanel's
	// modsec_assemble rewrite, and a blank registry loses known pass and deny
	// actions.
	if !modsec.ReplaceGlobal(reg) {
		previousRules := 0
		if prev := modsec.Global(); prev != nil {
			previousRules = prev.Len()
		}
		csmlog.Warn("modsec rule-action registry refresh returned 0 rules; keeping previous rule actions",
			"previous_rules", previousRules, "dirs", len(dirs))
		return
	}
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
