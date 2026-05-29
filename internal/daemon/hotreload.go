package daemon

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/integrity"
	"github.com/pidginhost/csm/internal/metrics"
	"github.com/pidginhost/csm/internal/store"
)

// Reload outcome labels for csm_config_reloads_total. Keep these in
// sync with docs/src/metrics.md.
const (
	reloadResultSuccess         = "success"
	reloadResultError           = "error"
	reloadResultRestartRequired = "restart_required"
	reloadResultNoop            = "noop"
)

var (
	reloadMetric     *metrics.CounterVec
	reloadMetricOnce sync.Once
)

// recordReloadResult bumps csm_config_reloads_total by one for the
// given outcome label, registering the metric on first use.
func recordReloadResult(result string) {
	reloadMetricOnce.Do(func() {
		reloadMetric = metrics.NewCounterVec(
			"csm_config_reloads_total",
			"SIGHUP config reload attempts, by outcome. result=success when safe fields were swapped in place; restart_required when the edit touched a field that needs a full restart (live config unchanged); error on YAML parse, validation, or re-sign failure (live config unchanged); noop when the edit was semantically identical to the running config.",
			[]string{"result"},
		)
		metrics.MustRegister("csm_config_reloads_total", reloadMetric)
	})
	reloadMetric.With(result).Inc()
}

// reloadConfig re-reads the on-disk csm.yaml plus configured drop-ins,
// validates it, diffs against the current live config, and - if every
// change is marked safe for live reload - installs the new config via
// config.SetActive. Only the main config file is re-signed; drop-ins are
// never written back into csm.yaml.
//
// Failure modes all leave the live config untouched:
//
//   - YAML parse error: Critical `config_reload_error` finding.
//   - Validation error: Critical `config_reload_error` finding.
//   - Restart-required fields changed: Warning
//     `config_reload_restart_required` finding, listing the offending
//     field names.
//   - Re-signing failure: Critical `config_reload_error` finding.
//
// ROADMAP item 7.
func (d *Daemon) reloadConfig() {
	oldCfg := d.activeOrStartupCfg()
	cfgPath := oldCfg.ConfigFile
	fmt.Fprintf(os.Stderr, "[%s] SIGHUP: reloading config from %s\n", ts(), cfgPath)

	newCfg, err := config.LoadWithDir(cfgPath, oldCfg.ConfigDir)
	if err != nil {
		recordReloadResult(reloadResultError)
		d.emitReloadFinding(alert.Critical, "config_reload_error",
			fmt.Sprintf("SIGHUP reload: parse failed (%v); keeping old config", err))
		return
	}

	for _, r := range config.Validate(newCfg) {
		if r.Level == "error" {
			recordReloadResult(reloadResultError)
			d.emitReloadFinding(alert.Critical, "config_reload_error",
				fmt.Sprintf("SIGHUP reload: validation error on %q: %s; keeping old config",
					r.Field, r.Message))
			return
		}
	}

	changes := config.Diff(oldCfg, newCfg)
	if len(changes) == 0 {
		recordReloadResult(reloadResultNoop)
		fmt.Fprintf(os.Stderr, "[%s] SIGHUP: no config changes detected\n", ts())
		return
	}

	if config.RestartRequired(changes) {
		var offenders []string
		for _, c := range changes {
			if c.Tag != config.TagSafe {
				offenders = append(offenders, c.Field)
			}
		}

		// The edit passed Validate, so the file on disk is
		// loadable. Re-sign integrity.config_hash to match the
		// edited content -- otherwise the next daemon restart
		// (systemd, manual, crash recovery) trips the startup
		// integrity check and crash-loops. Update the live cfg's
		// stored ConfigHash in lock-step so the periodic
		// integrity.Verify(currentCfg()) does not see a disk /
		// memory divergence and fire spurious tamper alerts.
		//
		// Any error re-signing degrades to "live config unchanged,
		// file unchanged, operator must rehash manually"; we still
		// emit the warning so they know to act.
		if err := d.signAndSaveReloadedConfig(oldCfg, newCfg); err == nil {
			resynced := *oldCfg
			resynced.Integrity = newCfg.Integrity
			resynced.ConfigFile = cfgPath
			resynced.ConfigDir = oldCfg.ConfigDir
			publishActiveConfig(&resynced, "SIGHUP")
		} else {
			fmt.Fprintf(os.Stderr, "[%s] config_reload_restart_required: re-sign failed (%v); file and live hash remain mismatched until operator runs `csm rehash`\n",
				ts(), err)
		}

		recordReloadResult(reloadResultRestartRequired)
		d.emitReloadFinding(alert.Warning, "config_reload_restart_required",
			fmt.Sprintf("SIGHUP reload: restart-required fields changed: %v; live config unchanged, main config re-signed if needed for next restart",
				offenders))
		return
	}

	if err := d.signAndSaveReloadedConfig(oldCfg, newCfg); err != nil {
		recordReloadResult(reloadResultError)
		d.emitReloadFinding(alert.Critical, "config_reload_error",
			fmt.Sprintf("SIGHUP reload: re-signing config failed: %v; live config unchanged", err))
		return
	}

	newCfg.ConfigFile = cfgPath
	newCfg.ConfigDir = oldCfg.ConfigDir
	if err := installAccountExtractorFromConfig(newCfg); err != nil {
		recordReloadResult(reloadResultError)
		d.emitReloadFinding(alert.Critical, "config_reload_error",
			fmt.Sprintf("SIGHUP reload: account extractor update failed: %v; live config unchanged", err))
		return
	}
	publishActiveConfig(newCfg, "SIGHUP")
	recordReloadResult(reloadResultSuccess)

	var names []string
	for _, c := range changes {
		names = append(names, c.Field)
	}
	fmt.Fprintf(os.Stderr, "[%s] SIGHUP: config reloaded; safe fields updated: %v\n", ts(), names)
}

// activeOrStartupCfg returns the current live config, falling back
// to d.cfg (the startup snapshot) if SetActive has not yet been
// called. Reload paths use this so the first reload diffs against
// the startup config, and every subsequent reload diffs against
// whatever the last successful reload installed.
//
// Also used by the tier-run hot paths (via currentCfg below) so a
// SIGHUP-driven threshold change reaches the next tick without a
// restart.
func (d *Daemon) activeOrStartupCfg() *config.Config {
	if c := config.Active(); c != nil {
		return c
	}
	return d.cfg
}

// currentCfg is the per-tick config accessor for hot paths. See
// ROADMAP item 7 for the threshold-tuning motivation.
func (d *Daemon) currentCfg() *config.Config {
	return d.activeOrStartupCfg()
}

func publishActiveConfig(cfg *config.Config, source string) {
	config.SetActive(cfg)
	purgeDryRunBlocksIfAutoResponseLive(cfg, source)
}

func purgeDryRunBlocksIfAutoResponseLive(cfg *config.Config, source string) {
	if cfg == nil || cfg.AutoResponseDryRunEnabled() {
		return
	}
	if sdb := store.Global(); sdb != nil {
		if removed := sdb.PurgeAllDryRunBlocks(); removed > 0 {
			fmt.Fprintf(os.Stderr, "[%s] %s: purged %d dry_run_blocks records (auto-response live)\n", ts(), source, removed)
		}
	}
}

// signAndSaveReloadedConfig re-computes integrity.config_hash for the main
// config file (and integrity.confd_hash for the conf.d fragments) when either
// changed across a SIGHUP. Drop-in fragment CONTENT is intentionally not
// written back into csm.yaml; only their digest is folded into confd_hash so
// a later Verify still passes. The binary hash is preserved from the prior
// live config; a SIGHUP reload cannot upgrade the binary, so it must not drift.
func (d *Daemon) signAndSaveReloadedConfig(oldCfg, newCfg *config.Config) error {
	currentHash, err := integrity.HashConfigStable(oldCfg.ConfigFile)
	if err != nil {
		return err
	}
	currentConfd, err := integrity.HashConfDir(oldCfg.ConfigDir)
	if err != nil {
		return err
	}
	if currentHash == oldCfg.Integrity.ConfigHash && currentConfd == oldCfg.Integrity.ConfdHash {
		newCfg.Integrity = oldCfg.Integrity
		return nil
	}
	configHash, confdHash, err := integrity.SignConfigFilePreserving(oldCfg.ConfigFile, oldCfg.ConfigDir, oldCfg.Integrity.BinaryHash)
	if err != nil {
		return err
	}
	newCfg.Integrity.BinaryHash = oldCfg.Integrity.BinaryHash
	newCfg.Integrity.ConfigHash = configHash
	newCfg.Integrity.ConfdHash = confdHash
	return nil
}

// emitReloadFinding logs to stderr and pushes a Finding into the
// daemon's alert channel. Non-blocking on channel saturation; the
// daemon's existing drop counter tracks those.
func (d *Daemon) emitReloadFinding(sev alert.Severity, check, msg string) {
	fmt.Fprintf(os.Stderr, "[%s] %s: %s\n", ts(), check, msg)
	finding := alert.Finding{
		Severity:  sev,
		Check:     check,
		Message:   msg,
		Timestamp: time.Now(),
	}
	select {
	case d.alertCh <- finding:
	default:
	}
}
