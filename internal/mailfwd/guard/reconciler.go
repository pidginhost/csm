package guard

import (
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/mailfwd/adapter"
)

// Reconciler drives the exim forward-guard from operator config. The daemon
// calls Reconcile on startup and on every config reload, and RefreshBadIPs on a
// schedule. It is the only thing that decides apply-vs-remove, so the live mail
// path and the dry-run path can never both be active.
type Reconciler struct {
	// Guard is the MTA adapter (nil on platforms without one).
	Guard adapter.ForwardGuard
	// Active gates the whole reconciler; the daemon sets it true only on a
	// cPanel/exim host. When false, Reconcile/RefreshBadIPs are no-ops.
	Active bool
	// BadIPs supplies the current bad-sender-IP set (from the reputation DB).
	BadIPs func() []string
}

// Reconcile installs the guard when it is enabled and enforcing, and removes it
// otherwise (disabled or dry-run). Dry-run never installs an MTA rule -- its
// accounting is CSM-side only.
func (r Reconciler) Reconcile(fg config.ForwardGuardConfig) error {
	if !r.Active || r.Guard == nil {
		return nil
	}
	if fg.Enabled && !fg.DryRun {
		return r.Guard.Apply(PolicyFromConfig(fg), r.badIPs())
	}
	return r.Guard.Remove()
}

// RefreshBadIPs rewrites the bad-IP lookup file while the guard is enforcing.
// It is a no-op when the guard is not installed, so it is safe to call on a
// timer regardless of config.
func (r Reconciler) RefreshBadIPs(fg config.ForwardGuardConfig) error {
	if !r.Active || r.Guard == nil || !fg.Enabled || fg.DryRun {
		return nil
	}
	return r.Guard.RefreshBadIPs(r.badIPs())
}

func (r Reconciler) badIPs() []string {
	if r.BadIPs == nil {
		return nil
	}
	return r.BadIPs()
}
