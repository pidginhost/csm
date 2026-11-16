package daemon

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"sync"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/obs"
	"github.com/pidginhost/csm/internal/platform"
)

// stalwartUnban lifts Stalwart's own bans of addresses CSM released, away
// from the request that released them. Any firewall release of one address
// adds it: an operator's, a hosting panel's self-service unban, or a DynDNS
// allow. Each address is pending at most once, so the set needs no cap. It has
// its own lifetime: adds come from request paths that can outlive the
// daemon's final wait, so its drain cannot join that wait.
type stalwartUnban struct {
	cfg func() *config.Config
	// ctx ends the call in flight when stop runs.
	ctx    context.Context
	cancel context.CancelFunc

	mu      sync.Mutex
	pending map[string]struct{}
	running bool
	stopped bool
	// done is closed when the last drain started has ended.
	done chan struct{}
}

// newStalwartUnban returns nil unless this host's mail server is Stalwart.
func newStalwartUnban(d *Daemon) *stalwartUnban {
	if detectMTA() != platform.MTAStalwart {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &stalwartUnban{cfg: d.currentCfg, ctx: ctx, cancel: cancel, pending: map[string]struct{}{}}
}

// add queues ip and returns at once. After stop it does nothing.
func (u *stalwartUnban) add(ip string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.stopped {
		return
	}
	u.pending[ip] = struct{}{}
	if u.running {
		return
	}
	u.running = true
	u.done = make(chan struct{})
	obs.Go("stalwart-unban", u.drain)
}

// stop ends the call in flight and returns once the drain has ended. No
// drain starts after it. It is safe to call more than once.
func (u *stalwartUnban) stop() {
	u.mu.Lock()
	u.stopped = true
	u.cancel()
	done := u.done
	u.mu.Unlock()
	if done != nil {
		<-done
	}
}

func (u *stalwartUnban) drain() {
	for {
		ip, ok := u.next()
		if !ok {
			return
		}
		// A call ended by stop is not a failure to report.
		if err := u.clear(u.ctx, ip); err != nil && u.ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "[%s] Stalwart may still refuse %s: %v\n", ts(), ip, err)
		}
	}
}

// next takes one pending address. When none is left or stop has run, it
// ends the drain under the lock, so add and stop always see a drain that is
// either still running or fully done.
func (u *stalwartUnban) next() (string, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if !u.stopped {
		for ip := range u.pending {
			delete(u.pending, ip)
			return ip, true
		}
	}
	u.running = false
	close(u.done)
	return "", false
}

// automaticBanReasons are the reasons Stalwart gives the bans it makes on
// its own. Any other reason, including one a later Stalwart adds, is left
// for the Stalwart admin.
var automaticBanReasons = map[string]bool{
	"rcptToFailure": true,
	"authFailure":   true,
	"loitering":     true,
	"portScanning":  true,
}

// clear lifts Stalwart's automatic bans of ip. Any other block is the
// Stalwart admin's decision and stays.
func (u *stalwartUnban) clear(ctx context.Context, ip string) error {
	client, err := stalwartClient(u.cfg())
	if err != nil {
		return err
	}
	lookupCtx, cancel := context.WithTimeout(ctx, stalwartCallTimeout)
	bans, err := client.BlockedIPs(lookupCtx, ip)
	cancel()
	if err != nil {
		return err
	}
	want, _ := netip.ParseAddr(ip)
	var ids, reasons []string
	foreign := false
	kept := map[string]bool{}
	for _, b := range bans {
		// A lookup is an exact match, but an entry for another address must
		// never be lifted on this one's behalf.
		if a, parseErr := netip.ParseAddr(b.Address); parseErr != nil || a.Unmap() != want.Unmap() {
			foreign = true
			continue
		}
		if !automaticBanReasons[b.Reason] {
			kept[describeBanReason(b.Reason)] = true
			continue
		}
		ids, reasons = append(ids, b.ID), append(reasons, b.Reason)
	}
	if foreign {
		fmt.Fprintf(os.Stderr, "[%s] Stalwart answered the lookup for %s with entries for other addresses; left them\n", ts(), ip)
	}
	for reason := range kept {
		fmt.Fprintf(os.Stderr, "[%s] Stalwart keeps its block of %s (%s)\n", ts(), ip, reason)
	}
	if len(ids) == 0 {
		// A lift whose reload was lost leaves a ban Stalwart enforces but
		// no longer lists. Reloading here lets a second unblock finish it.
		reloadCtx, cancelReload := context.WithTimeout(ctx, stalwartCallTimeout)
		defer cancelReload()
		if reloadErr := client.ReloadBlockedIPs(reloadCtx); reloadErr != nil {
			return fmt.Errorf("reloading Stalwart's ban list: %w", reloadErr)
		}
		return nil
	}
	deleteCtx, cancel := context.WithTimeout(ctx, stalwartCallTimeout)
	err = client.DeleteBlockedIPs(deleteCtx, ids)
	cancel()
	for _, reason := range reasons {
		rec := actionlog.Record{
			Op:     "operate.clear_stalwart_ban",
			Action: "delete_blocked_ip",
			Target: ip,
			Reason: reason,
			Result: actionlog.Applied,
		}
		if err != nil {
			rec.Result, rec.Error = actionlog.Failed, err.Error()
		}
		actionlog.Write(rec)
	}
	return err
}

// describeBanReason names a kept entry's reason for the log. Stalwart's
// reasons are plain words; anything else is not echoed.
func describeBanReason(reason string) string {
	if reason == "" {
		return "an unknown reason"
	}
	for _, c := range reason {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			return "an unknown reason"
		}
	}
	return "reason " + reason
}
