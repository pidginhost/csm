package daemon

import (
	"time"

	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/mailfwd/adapter"
	"github.com/pidginhost/csm/internal/mailfwd/guard"
	"github.com/pidginhost/csm/internal/mailfwd/quarantine"
	"github.com/pidginhost/csm/internal/platform"
	"github.com/pidginhost/csm/internal/store"
)

// forwardGuardBadIPScore is the reputation score at/above which a sender IP is
// treated as bad for the forward-guard's bad_sender_ip signal.
const forwardGuardBadIPScore = 50

// forwardGuardRefreshInterval is how often the bad-IP lookup file is refreshed
// from the reputation DB. exim reads the lsearch file per lookup, so this only
// rewrites a file -- no exim rebuild or reload.
const forwardGuardRefreshInterval = 15 * time.Minute

// forwardGuardReconciler builds the reconciler for the current host. The guard
// is only active on cPanel/exim; elsewhere Reconcile/RefreshBadIPs are no-ops.
func (d *Daemon) forwardGuardReconciler() guard.Reconciler {
	return guard.Reconciler{
		Guard:  adapter.NewEximServiceAdapter(),
		Active: platform.Detect().IsCPanel() && !d.currentCfg().ObserveMode(),
		BadIPs: d.forwardGuardBadIPs,
	}
}

// forwardGuardBadIPs returns sender IPs the reputation DB scores as bad. Empty
// when the store is unavailable -- the guard then simply holds nothing on the
// bad-IP signal (the null-sender signal is unaffected).
func (d *Daemon) forwardGuardBadIPs() []string {
	db := store.Global()
	if db == nil {
		return nil
	}
	var ips []string
	for ip, e := range db.AllReputation() {
		if e.Score >= forwardGuardBadIPScore {
			ips = append(ips, ip)
		}
	}
	return ips
}

// reconcileForwardGuard installs or removes the exim forward-guard to match the
// current config. Errors are logged, never fatal: a guard failure must not take
// the daemon down or block mail (fail-open).
func (d *Daemon) reconcileForwardGuard() {
	fg := d.currentCfg().EmailProtection.ForwardGuard
	if err := d.forwardGuardReconciler().Reconcile(fg); err != nil {
		csmlog.Error("forward-guard reconcile failed", "err", err)
	}
}

// forwardQuarantineDir is a var so tests can prune a temporary Maildir.
var forwardQuarantineDir = adapter.QuarantineDir

// forwardGuardRefresher periodically refreshes the bad-IP lookup file while the
// guard is enforcing and ages held copies out of the quarantine.
func (d *Daemon) forwardGuardRefresher() {
	defer d.wg.Done()
	ticker := time.NewTicker(forwardGuardRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			fg := d.currentCfg().EmailProtection.ForwardGuard
			if err := d.forwardGuardReconciler().RefreshBadIPs(fg); err != nil {
				csmlog.Error("forward-guard bad-IP refresh failed", "err", err)
			}
			d.pruneForwardQuarantine()
		}
	}
}

// pruneForwardQuarantine deletes held forward copies older than
// quarantine_retention_days. Copies held while the guard was on must still
// age out after it is switched off, so only the retention value gates this;
// 0 keeps everything.
func (d *Daemon) pruneForwardQuarantine() {
	days := d.currentCfg().EmailProtection.ForwardGuard.QuarantineRetentionDays
	if days <= 0 {
		return
	}
	removed, err := quarantine.New(forwardQuarantineDir).PruneOlderThan(time.Duration(days) * 24 * time.Hour)
	if err != nil {
		csmlog.Error("forward-guard quarantine prune failed", "err", err)
		return
	}
	if removed > 0 {
		csmlog.Info("forward-guard quarantine pruned", "removed", removed, "retention_days", days)
	}
}
