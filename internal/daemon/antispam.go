package daemon

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
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

type antispamHealthState struct {
	reconcile.Health
	// Serialize reloads with probe completion and latest-state publication,
	// but never hold mu across a socket probe or notification delivery.
	mu         sync.Mutex
	enabled    bool
	socket     string
	generation uint64
	latest     string
}

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
	r := antispamReconciler()
	loop := reconcile.NewLoop(func(ctx context.Context) reconcile.Outcome {
		return r.Pass(ctx, reconcile.DesiredFromConfig(d.currentCfg()))
	}, d.reportAntispam)
	d.antispamLoop.Store(loop)
	// Publish the reload target before reading initial health config so a
	// reload during setup is either picked up here or applies itself.
	d.syncAntispamHealth()
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
	h := &d.antispamHealth
	h.mu.Lock()
	defer h.mu.Unlock()
	as := d.currentCfg().EmailProtection.Antispam
	if as.Enabled != h.enabled || as.RspamdSocket != h.socket {
		// The same socket can be disabled and re-enabled while a probe runs.
		// Its result must not count toward the new tracking period.
		h.generation++
	}
	h.enabled, h.socket = as.Enabled, as.RspamdSocket
	h.SetEnabled(as.Enabled, as.RspamdSocket)
	d.storeAntispamHealthLocked()
}

func (d *Daemon) antispamHealthLoop(ctx context.Context) {
	ticker := time.NewTicker(antispamProbeInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			d.probeAntispam(ctx, now)
		}
	}
}

// probeAntispam pings rspamd while antispam is enabled and reports an
// outage or recovery. Current conditions are published before notification
// delivery, which may block on a sink.
func (d *Daemon) probeAntispam(ctx context.Context, now time.Time) {
	h := &d.antispamHealth
	h.mu.Lock()
	enabled, socket, generation := h.enabled, h.socket, h.generation
	h.mu.Unlock()
	if ctx.Err() != nil {
		return
	}
	var err error
	if enabled {
		_, err = antispamPing(ctx, socket)
	}
	h.mu.Lock()
	if ctx.Err() != nil || generation != h.generation {
		// Shutdown or reload cut this tracking period short.
		h.mu.Unlock()
		return
	}
	var findings []alert.Finding
	if enabled {
		findings = h.Ping(socket, err, now)
	}
	d.storeAntispamHealthLocked()
	h.mu.Unlock()
	d.reportAntispamHealth(findings)
}

// The caller holds antispamHealth.mu so a reload cannot clear health and
// then have an old snapshot overwrite the latest set.
func (d *Daemon) storeAntispamHealthLocked() {
	h := &d.antispamHealth
	active := h.Active()
	var state strings.Builder
	for _, f := range active {
		state.WriteString(f.Key() + "\x00" + f.Details + "\x00")
	}
	if state.String() == h.latest {
		return
	}
	checks.StoreLatestScanFindings(d.store, antispamHealthChecks, active)
	// A dismissal acknowledges one episode. Once the condition clears,
	// forget it, so the next episode notifies again.
	d.store.RearmAbsentDedupFindings(antispamHealthChecks, active)
	h.latest = state.String()
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
