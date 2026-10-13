package daemon

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/antispam/hostfacts"
	"github.com/pidginhost/csm/internal/antispam/reconcile"
	"github.com/pidginhost/csm/internal/antispam/worker"
	"github.com/pidginhost/csm/internal/checks"
	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/obs"
	"github.com/pidginhost/csm/internal/platform"
)

// antispamProbeInterval is how often rspamd's scan socket is probed while
// antispam is enabled (spec section 7).
const antispamProbeInterval = 20 * time.Second

// antispamHealthChecks are the conditions the probe loop keeps current in
// the latest set. A recovery is a one-time notice, never a condition.
var antispamHealthChecks = []string{reconcile.CheckRspamdDown, reconcile.CheckScanError}

// antispamPing probes rspamd's scan socket; tests replace it.
var antispamPing = hostfacts.Ping

// antispamReconciler returns the host the antispam reconcile loop works on;
// tests replace it.
var antispamReconciler = func() reconcile.Reconciler {
	return reconcile.Reconciler{
		Collect:   hostfacts.Collect,
		Installed: hostfacts.CollectInstalled,
		Run:       worker.Run,
		Now:       time.Now,
	}
}

// startAntispam starts antispam reconciliation on a cPanel host: a pass at
// start, after each config reload, every 15 minutes, and 20 seconds after a
// busy lock (spec section 6.5). It also starts the rspamd probe. Shutdown
// cancels a running pass or probe.
func (d *Daemon) startAntispam() {
	if !platform.Detect().IsCPanel() {
		return
	}
	// Health state starts empty; findings kept from before a restart
	// describe an outage no longer tracked.
	checks.StoreLatestScanFindings(d.store, antispamHealthChecks, nil)
	d.syncAntispamHealth()
	r := antispamReconciler()
	loop := reconcile.NewLoop(func(ctx context.Context) reconcile.Outcome {
		return r.Pass(ctx, reconcile.DesiredFromConfig(d.currentCfg()))
	}, d.reportAntispam)
	d.antispamLoop.Store(loop)
	ctx := d.scanContext()
	d.wg.Add(2)
	obs.Go("antispam-reconcile", func() {
		defer d.wg.Done()
		loop.Run(ctx)
	})
	obs.Go("antispam-health", func() {
		defer d.wg.Done()
		d.antispamHealthLoop(ctx)
	})
}

// reconcileAntispam applies a config reload: health tracking follows the
// new switch and socket at once, and a pass reads the new config.
func (d *Daemon) reconcileAntispam() {
	if loop := d.antispamLoop.Load(); loop != nil {
		d.syncAntispamHealth()
		loop.Trigger()
	}
}

// syncAntispamHealth points health tracking at the configured socket while
// antispam is enabled. Disabling forgets every outage and scan error
// without a recovery notice (spec section 7).
func (d *Daemon) syncAntispamHealth() {
	as := d.currentCfg().EmailProtection.Antispam
	d.antispamHealth.SetEnabled(as.Enabled, as.RspamdSocket)
}

func (d *Daemon) antispamHealthLoop(ctx context.Context) {
	ticker := time.NewTicker(antispamProbeInterval)
	defer ticker.Stop()
	var last string
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			last = d.probeAntispam(ctx, now, last)
		}
	}
}

// probeAntispam pings rspamd while antispam is enabled and reports an
// outage or recovery. It then stores the health conditions in the latest set
// when they differ from last, the state it returns for the next probe.
func (d *Daemon) probeAntispam(ctx context.Context, now time.Time, last string) string {
	if as := d.currentCfg().EmailProtection.Antispam; as.Enabled {
		_, err := antispamPing(ctx, as.RspamdSocket)
		if ctx.Err() != nil {
			// Shutdown cut the probe short; rspamd did not fail.
			return last
		}
		d.reportAntispamHealth(d.antispamHealth.Ping(as.RspamdSocket, err, now))
	}
	active := d.antispamHealth.Active()
	var state strings.Builder
	for _, f := range active {
		state.WriteString(f.Key() + "\x00" + f.Details + "\x00")
	}
	if state.String() == last {
		return last
	}
	checks.StoreLatestScanFindings(d.store, antispamHealthChecks, active)
	return state.String()
}

// reportAntispamHealth delivers rspamd outage and recovery notices to
// history and notification directly. Alert-state dedup would hide a second
// outage on the same day, and spec section 7 wants one notice per outage.
func (d *Daemon) reportAntispamHealth(findings []alert.Finding) {
	if len(findings) == 0 {
		return
	}
	d.store.AppendHistory(findings)
	if err := alert.Dispatch(d.currentCfg(), findings); err != nil {
		csmlog.Warn("antispam health notification failed", "err", err)
	}
}

// reportAntispam keeps the findings of the checks a pass settled in the
// latest set, alerts on new ones, and logs a pass that did not complete.
func (d *Daemon) reportAntispam(out reconcile.Outcome) {
	if out.Err != nil && !errors.Is(out.Err, context.Canceled) {
		// A worker error can carry the worker's diagnostics across lines.
		csmlog.Warn("antispam reconcile did not complete", "err", strconv.Quote(out.Err.Error()))
	}
	d.processScanFindings(d.currentCfg(), out.Findings, out.Checks, "antispam")
}
