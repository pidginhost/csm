package daemon

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/pidginhost/csm/internal/antispam/hostfacts"
	"github.com/pidginhost/csm/internal/antispam/reconcile"
	"github.com/pidginhost/csm/internal/antispam/worker"
	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/obs"
	"github.com/pidginhost/csm/internal/platform"
)

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
// busy lock (spec section 6.5). Shutdown cancels a running pass.
func (d *Daemon) startAntispam() {
	if !platform.Detect().IsCPanel() {
		return
	}
	r := antispamReconciler()
	loop := reconcile.NewLoop(func(ctx context.Context) reconcile.Outcome {
		return r.Pass(ctx, reconcile.DesiredFromConfig(d.currentCfg()))
	}, d.reportAntispam)
	d.antispamLoop.Store(loop)
	ctx := d.scanContext()
	d.wg.Add(1)
	obs.Go("antispam-reconcile", func() {
		defer d.wg.Done()
		loop.Run(ctx)
	})
}

// reconcileAntispam asks for a pass after a config reload. The pass reads
// the config itself, so it always sees the latest one.
func (d *Daemon) reconcileAntispam() {
	if loop := d.antispamLoop.Load(); loop != nil {
		loop.Trigger()
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
