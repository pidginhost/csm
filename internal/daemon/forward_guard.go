package daemon

import (
	"errors"
	"time"

	"github.com/pidginhost/csm/internal/eximlock"
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

// newForwardGuard builds the adapter that runs the forward-guard worker;
// tests replace it.
var newForwardGuard = adapter.NewEximServiceAdapter

// forwardGuardReconciler builds the reconciler for the current host. The guard
// is only active on cPanel/exim; elsewhere Reconcile/RefreshBadIPs are no-ops.
// In observe mode on cPanel, Reconcile only cancels pending worker requests.
func (d *Daemon) forwardGuardReconciler() guard.Reconciler {
	cpanel, observe := platform.Detect().IsCPanel(), d.currentCfg().ObserveMode()
	return guard.Reconciler{
		Guard:   newForwardGuard(),
		Active:  cpanel && !observe,
		BadIPs:  d.forwardGuardBadIPs,
		Observe: cpanel && observe,
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
// the daemon down or block mail (fail-open). A change refused because another
// CSM transaction, such as an antispam one, holds the Exim lock is logged as
// deferred; it and any failure are retried on the next refresh.
func (d *Daemon) reconcileForwardGuard() {
	d.forwardGuardRetry.Store(true)
	// No caller waits for an in-flight worker. Reloads reach here through the
	// loop, one at a time; any other overlapping call leaves its request for
	// the next refresh. Read config only after taking the lock.
	if !d.forwardGuardMu.TryLock() {
		csmlog.Info("forward-guard reconcile deferred to the next refresh: another reconcile is running",
			"refresh_interval", forwardGuardRefreshInterval)
		return
	}
	defer d.forwardGuardMu.Unlock()
	// Consume pending work before starting so success cannot erase a reload
	// request that arrives while this attempt is running.
	d.forwardGuardRetry.Store(false)
	fg := d.currentCfg().EmailProtection.ForwardGuard
	if err := d.forwardGuardReconciler().Reconcile(fg); err != nil {
		d.forwardGuardRetry.Store(true)
		if errors.Is(err, eximlock.ErrBusy) {
			csmlog.Info("forward-guard reconcile deferred to the next refresh: another CSM transaction holds the Exim lock",
				"refresh_interval", forwardGuardRefreshInterval)
			return
		}
		csmlog.Error("forward-guard reconcile failed", "err", err)
		return
	}
}

// forwardQuarantineDir is a var so tests can prune a temporary Maildir.
var forwardQuarantineDir = adapter.QuarantineDir

// wakeForwardGuard asks the forward-guard loop to reconcile with the latest
// config. It never blocks: a reload must not wait for a worker that can
// rebuild Exim for minutes. Wakes that arrive during a reconcile become one
// more reconcile after it.
func (d *Daemon) wakeForwardGuard() {
	select {
	case d.forwardGuardWake <- struct{}{}:
	default:
	}
}

// forwardGuardRefresher reconciles the guard when a reload wakes it, and
// periodically refreshes the bad-IP lookup file while the guard is enforcing
// and ages held copies out of the quarantine.
func (d *Daemon) forwardGuardRefresher() {
	defer d.wg.Done()
	ticker := time.NewTicker(forwardGuardRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-d.stopCh:
			return
		case <-d.forwardGuardWake:
			// A queued reload can win the select after shutdown starts.
			// Do not launch another potentially slow Exim rebuild then.
			select {
			case <-d.stopCh:
				return
			default:
			}
			d.reconcileForwardGuard()
		case <-ticker.C:
			d.refreshForwardGuard()
		}
	}
}

// refreshForwardGuard retries a failed reconcile, refreshes the bad-IP
// lookup and ages out held copies.
func (d *Daemon) refreshForwardGuard() {
	if d.forwardGuardRetry.Load() {
		d.reconcileForwardGuard()
	}
	fg := d.currentCfg().EmailProtection.ForwardGuard
	if err := d.forwardGuardReconciler().RefreshBadIPs(fg); err != nil {
		csmlog.Error("forward-guard bad-IP refresh failed", "err", err)
	}
	d.pruneForwardQuarantine()
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
