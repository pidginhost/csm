//go:build linux

package daemon

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/emailspool"
	"github.com/pidginhost/csm/internal/store"
)

// startPHPRelayLinux completes the PHP-relay wiring after the platform
// gate (in startPHPRelay) has confirmed cPanel + located exim. It is
// split out from daemon.go so the heavy linux-only types stay in this
// file; the cross-platform stub in php_relay_wiring_other.go keeps the
// darwin build clean.
//
// The whole pipeline is built up exactly once at daemon start; SIGHUP
// only reloads policies (handled in daemon.go where d.policies is
// already wired). Callers must not invoke this twice.
func startPHPRelayLinux(d *Daemon) {
	// 1. cPanel hourly limit + Path 2b derivation.
	limit, status := readCpanelHourlyLimit("/var/cpanel/cpanel.config")
	switch status {
	case cpanelLimitMissing, cpanelLimitUnparsable:
		emitPHPRelayFinding(d, alert.Warning, "email_php_relay_cpanel_limit_unreadable",
			"cpanel.config maxemailsperhour unreadable; assuming 100")
	}

	// 2. Policies (suspicious mailers, HTTP-proxy ranges). LoadPolicies
	// returns a usable Policies even on partial-failure so we always
	// have something to install on the daemon for SIGHUP reloads.
	pol, _ := emailspool.LoadPolicies(d.cfg.EmailProtection.PHPRelay.PoliciesDir)
	d.policies = pol

	// 3. Window state (per-script, per-IP, per-account).
	psw := newPerScriptWindow()
	pip := newPerIPWindow(64)
	pacct := newPerAccountWindow(5000)

	// 4. Evaluator. Wires the cPanel-derived effective account limit so
	// Path 2b activates as soon as the first message arrives.
	prMetrics := newPHPRelayMetrics()
	eng := newEvaluator(psw, pip, pacct, d.cfg, prMetrics)
	eng.SetPolicies(pol)
	eff, enabled, capped := deriveEffectiveAccountLimit(d.cfg, limit, status)
	if !enabled {
		emitPHPRelayFinding(d, alert.Warning, "email_php_relay_path2b_disabled",
			"Path 2b disabled: cPanel limit off and no operator override")
	}
	if capped {
		emitPHPRelayFinding(d, alert.Warning, "email_php_relay_account_volume_capped",
			"operator AccountVolumePerHour capped to 95% of cPanel hourly limit")
	}
	eng.SetEffectiveAccountLimit(eff)
	SetPHPRelayEvaluator(eng)

	// 5. msgIDIndex + persister. Bbolt access is via store.Global() --
	// the daemon does not hold a *store.DB directly; the global handle
	// is the same singleton the rest of the codebase uses (sigWatcher,
	// retention, etc.).
	bdb := store.Global()
	persister := newMsgIndexPersister(bdb, 4096, 100*time.Millisecond)
	persister.SetErrorCallback(func(f alert.Finding) {
		select {
		case d.alertCh <- f:
		default:
		}
	})
	persister.SetMetrics(prMetrics)
	persister.Start()
	d.phpRelayShutdown = append(d.phpRelayShutdown, persister.Stop)
	idx := newMsgIDIndex(persister, 200_000)

	// 6. ignoreList with bbolt-backed restore.
	ignores := newIgnoreList()
	ignores.SetStore(bdb)
	_ = ignores.Restore()

	// 7. cpanel user domains resolver (Path 4 helper).
	domains := newUserDomainsResolver()

	// 8. Controller (constructed before the freezer so DryRunFn can
	// thread the runtime/bbolt/yaml precedence into freeze decisions).
	runner := defaultRunner{}
	auditor := newStructuredAuditor(eximAuditWriter())
	d.phpRelayController = &PHPRelayController{
		eng:          eng,
		msgIndex:     idx,
		ignores:      ignores,
		actionDryRun: &runtimeBool{},
		db:           bdb,
		runner:       runner,
		eximBin:      eximBinary,
		auditor:      auditor,
		enabled:      true,
		platform:     "cpanel",
	}
	if d.controlListener != nil {
		d.controlListener.phprelay = d.phpRelayController
	}

	// 9. Spool pipeline (Flow A) + autoFreezer (post-emit hook).
	pipeline := newSpoolPipeline(eng, domains, pol, idx, ignores, func(f alert.Finding) {
		select {
		case d.alertCh <- f:
		default:
		}
	})
	freezer := newAutoFreezer(psw, d.cfg, "/var/spool/exim/input", eximBinary,
		runner, auditor, prMetrics, d.phpRelayController.DryRunFn())
	d.autoFreezer = freezer

	// 10. Startup walker BEFORE the watcher to rebuild script state for
	// messages already on the spool when the daemon starts.
	runStartupSpoolWalker("/var/spool/exim/input", pipeline)

	watcherFn := func(ctx context.Context) {
		w, err := newSpoolWatcher("/var/spool/exim/input", pipeline.OnFile)
		if err != nil {
			emitPHPRelayFinding(d, alert.Critical, "email_php_relay_watcher_failed", err.Error())
			return
		}
		w.SetMetrics(prMetrics)
		w.SetOverflowHandler(func() {
			emitPHPRelayFinding(d, alert.Critical, "email_php_relay_inotify_overflow",
				"inotify queue overflow; running bounded recovery scan")
			const phpRelayOverflowScanMax = 1000
			n, truncated := runRecoveryScan("/var/spool/exim/input", phpRelayOverflowScanMax, pipeline.OnFile)
			if truncated {
				emitPHPRelayFinding(d, alert.Critical, "email_php_relay_overflow_scan_truncated",
					fmt.Sprintf("overflow recovery capped at %d files; older messages skipped (Path 2b backstops)", phpRelayOverflowScanMax))
			}
			emitPHPRelayFinding(d, alert.Warning, "email_php_relay_inotify_overflow_recovered",
				fmt.Sprintf("recovery scan processed %d -H files", n))
		})
		w.Run(ctx)
	}
	sup := newSpoolSupervisor(watcherFn, 5)
	sup.OnFailed = func() {
		emitPHPRelayFinding(d, alert.Critical, "email_php_relay_watcher_failed", "supervisor exhausted restarts")
	}
	ctx := stopChContext(d)
	go sup.Run(ctx)

	// 11. Retrospective Path 2b scan over exim_mainlog so account-volume
	// alerts fire on the first hour boundary even after a daemon
	// restart that lost in-memory state.
	go ScanEximHistoryForPHPRelayAccountVolume("/var/log/exim_mainlog", eng, time.Now(), func(f alert.Finding) {
		select {
		case d.alertCh <- f:
		default:
		}
	})

	// 12. Flow E maintenance ticker.
	go runPHPRelayFlowE(d, ctx, psw, pip, pacct, idx, persister, ignores, prMetrics)
}

// runPHPRelayFlowE drives Phase E maintenance (TTL sweeps + metric
// gauges). Single source of truth for php_relay TTLs; runs until ctx is
// cancelled (which happens when d.stopCh closes).
func runPHPRelayFlowE(
	d *Daemon,
	ctx context.Context,
	psw *perScriptWindow,
	pip *perIPWindow,
	pacct *perAccountWindow,
	idx *msgIDIndex,
	persister *msgIndexPersister,
	ignores *ignoreList,
	m *phpRelayMetrics,
) {
	minTicker := time.NewTicker(1 * time.Minute)
	fiveMinTicker := time.NewTicker(5 * time.Minute)
	defer minTicker.Stop()
	defer fiveMinTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-minTicker.C:
			now := time.Now()
			_ = idx.SweepMemory(now.Add(-4 * time.Hour))
			if m != nil {
				m.MsgIDIndexSize.With("memory").Set(float64(idx.Len()))
			}
			if _, err := persister.SweepBolt(now.Add(-25 * time.Hour)); err != nil {
				emitPHPRelayFinding(d, alert.Warning, "email_php_relay_sweep_failed", err.Error())
			}
			if _, err := ignores.SweepBolt(now); err != nil {
				emitPHPRelayFinding(d, alert.Warning, "email_php_relay_sweep_failed", err.Error())
			}
			ignores.SweepExpired(now)
		case <-fiveMinTicker.C:
			now := time.Now()
			cutoff25h := now.Add(-25 * time.Hour)
			psw.PruneActiveMsgs(cutoff25h)
			psw.SweepIdle(cutoff25h)
			pip.SweepIdle(now.Add(-1 * time.Hour))
			pacct.SweepIdle(now.Add(-24 * time.Hour))
		}
	}
}

// emitPHPRelayFinding sends a finding through the daemon alert pipeline,
// dropping silently if the channel buffer is full (matches the existing
// startup-time alert pattern in daemon.go).
func emitPHPRelayFinding(d *Daemon, sev alert.Severity, check, msg string) {
	select {
	case d.alertCh <- alert.Finding{
		Severity:  sev,
		Check:     check,
		Message:   msg,
		Timestamp: time.Now(),
	}:
	default:
	}
}

// eximAuditWriter returns the writer used by the structured JSONL auditor.
// Defaults to /var/log/csm/php_relay_audit.jsonl on linux; the file is
// opened in append mode at startup. If the open fails (e.g. /var/log/csm
// not writable) the audit trail goes to stderr so we never silently lose
// it.
func eximAuditWriter() io.Writer {
	const path = "/var/log/csm/php_relay_audit.jsonl"
	if f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640); err == nil {
		return f
	}
	return os.Stderr
}

// stopChContext bridges the daemon's stopCh (chan struct{}) to a
// context.Context for components that take a ctx (spool watcher, Flow E
// ticker). The returned context is cancelled when stopCh closes.
func stopChContext(d *Daemon) context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-d.stopCh
		cancel()
	}()
	return ctx
}
