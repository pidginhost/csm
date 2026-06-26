package daemon

import (
	"context"
	"net"
	"path/filepath"
	"time"

	"github.com/pidginhost/csm/internal/firewall"
	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/mailranges"
	"github.com/pidginhost/csm/internal/obs"
)

const (
	mailRangesRefreshInterval = 12 * time.Hour
	mailRangesStartupDelay    = 5 * time.Minute
)

// mailRangesResolver is the DNS resolver for the periodic SPF-based refresh.
// Replaced in tests to avoid live network calls.
var mailRangesResolver mailranges.Resolver = net.DefaultResolver

// mailRangesReapplyFn applies updated provider nets to the firewall engine's
// DoS-exempt sets. Replaced in tests to inject reapply failures without
// requiring a live nftables connection.
var mailRangesReapplyFn = func(e *firewall.Engine, nets []*net.IPNet) error {
	return e.RefreshDOSExemptSets(nets)
}

func (d *Daemon) mailRangesCachePath() string {
	return filepath.Join(d.cfg.StatePath, "mailranges.json")
}

// initMailRanges loads the on-disk mail-provider range cache synchronously.
// This must be called before startFirewall() so that engine.SetDOSExemptProviderNets
// receives a full provider set and Apply() builds dos_exempt_nets from day zero.
//
// LoadCache errors are non-fatal: when the cache is absent or corrupt the
// embedded snapshot is published and the daemon continues. The error is
// logged so operators know the fallback is active.
func (d *Daemon) initMailRanges() {
	if err := mailranges.LoadCache(d.mailRangesCachePath()); err != nil {
		csmlog.Warn("mailranges: cache load failed, using embedded snapshot", "err", err)
	}
	d.wg.Add(1)
	obs.Go("mailranges-refresh", d.mailRangesRefreshLoop)
}

// mailRangesRefreshLoop periodically refreshes the mail-provider IP ranges
// (Google, Microsoft) so the firewall's DoS-exempt sets remain current.
// A short startup delay mirrors the botranges updater so the daemon does not
// hit external DNS before the host is fully settled.
func (d *Daemon) mailRangesRefreshLoop() {
	defer d.wg.Done()

	select {
	case <-d.stopCh:
		return
	case <-time.After(mailRangesStartupDelay):
	}
	d.doMailRangesRefresh()

	ticker := time.NewTicker(mailRangesRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			d.doMailRangesRefresh()
		}
	}
}

// doMailRangesRefresh runs one refresh cycle: resolves SPF records, updates
// the on-disk cache, and reapplies the firewall DoS-exempt sets. On reapply
// failure it restores the previous provider snapshot so the in-memory state
// stays consistent with what is actually live in nftables.
func (d *Daemon) doMailRangesRefresh() {
	cachePath := d.mailRangesCachePath()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	// Cancel in-flight DNS promptly on daemon shutdown.
	go func() {
		select {
		case <-d.stopCh:
			cancel()
		case <-ctx.Done():
		}
	}()

	// Snapshot the provider set before refresh so it can be restored if the
	// subsequent firewall reapply fails. The snapshot and the reapply must be
	// consistent: ProviderNets() must reflect what is in nftables.
	prev := mailranges.ProviderSnapshot()

	n, err := mailranges.Refresh(ctx, mailRangesResolver, cachePath)
	if err != nil {
		csmlog.Warn("mailranges: refresh error", "err", err)
	}
	if n == 0 {
		// All providers failed; Refresh did not update the active snapshot.
		return
	}

	csmlog.Info("mailranges: providers refreshed", "prefixes", n)

	if d.fwEngine == nil {
		return
	}
	if reapplyErr := mailRangesReapplyFn(d.fwEngine, mailranges.ProviderNets()); reapplyErr != nil {
		// Restore the previous snapshot so ProviderNets() reflects what is
		// actually in nftables, not the candidate update that failed to apply.
		// Auto-response subnets for the failed candidate are not pruned.
		mailranges.PublishProviderSnapshot(prev)
		csmlog.Warn("mailranges: firewall reapply failed; previous snapshot restored", "err", reapplyErr)
	}
}
