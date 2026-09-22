package daemon

import (
	"time"

	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/modsec"
	"github.com/pidginhost/csm/internal/obs"
	"github.com/pidginhost/csm/internal/platform"
)

// modsecRegistryRefresh controls how often the rule-action registry is
// checked against disk. ModSec rule files change rarely (vendor pack updates,
// cPanel modsec_assemble nightly run), so a coarse interval keeps the cost
// negligible while still picking up operator edits within minutes.
const modsecRegistryRefresh = 5 * time.Minute

// Seams: the refresh probes the platform and parses the rule tree, and tests
// need to count both without a web server on the host.
var (
	// modsecProbeRuleDirs re-runs detection (not the cached Detect) so a
	// web-server mis-detection at boot -- LiteSpeed probed before lsws
	// finished starting, which points RuleDirs at non-existent directories --
	// self-heals on a later refresh instead of staying wrong for the daemon's
	// lifetime. Each call forks one process per candidate unit, which is why
	// refreshModSecRegistry stops calling it once a rule set has loaded.
	modsecProbeRuleDirs = func() []string { return modsec.RuleDirs(platform.DetectFreshWithOverrides()) }
	modsecBuildRegistry = modsec.BuildRegistry
)

// modsecRegistryState carries what the last refresh learned. Only the refresh
// path touches it: once at startup, then from the refresh goroutine.
type modsecRegistryState struct {
	dirs        []string
	fingerprint string
	// loaded records whether the last build produced a non-empty rule set
	// from these dirs. Otherwise the platform is probed on every refresh,
	// because an empty registry is exactly the symptom of detection having
	// resolved the wrong directories.
	loaded bool
}

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
	state := &d.modsecRegistry
	if !state.loaded || len(state.dirs) == 0 {
		state.dirs = modsecProbeRuleDirs()
	}

	fingerprint, present := modsec.RuleTreeFingerprint(state.dirs)
	if state.loaded && !present {
		// The directories the last detection resolved are gone: the web
		// server was swapped out, or the vendor pack removed. Detection has
		// to run again rather than keep reporting the old rule actions.
		state.loaded = false
		state.dirs = modsecProbeRuleDirs()
		fingerprint, _ = modsec.RuleTreeFingerprint(state.dirs)
	}
	if state.loaded && fingerprint != "" && fingerprint == state.fingerprint {
		// Only a complete fingerprint can establish that the rule contents
		// match the last successful build.
		return
	}

	reg, err := modsecBuildRegistry(state.dirs)
	if err != nil {
		csmlog.Warn("modsec rule-action registry build had errors", "err", err, "rules_loaded", reg.Len())
	}
	state.loaded = reg.Len() > 0
	state.fingerprint = ""
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
			"previous_rules", previousRules, "dirs", len(state.dirs))
		return
	}
	if err == nil {
		state.fingerprint = reg.Fingerprint()
	}
	csmlog.Info("modsec rule-action registry loaded", "rules", reg.Len(), "dirs", len(state.dirs))
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
