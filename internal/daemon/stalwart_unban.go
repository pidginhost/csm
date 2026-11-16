package daemon

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/obs"
	"github.com/pidginhost/csm/internal/platform"
)

// stalwartUnban lifts Stalwart's own bans of addresses CSM released, away
// from the request that released them. Only CSM's own releases add an
// address and each is pending at most once, so the set needs no cap. It has
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

// clear lifts Stalwart's automatic bans of ip. A block made by hand in
// Stalwart is the Stalwart admin's decision and stays.
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
	var ids, reasons []string
	manual := false
	for _, b := range bans {
		if b.Reason == "manual" {
			manual = true
			continue
		}
		ids, reasons = append(ids, b.ID), append(reasons, b.Reason)
	}
	if manual {
		fmt.Fprintf(os.Stderr, "[%s] Stalwart keeps its manual block of %s\n", ts(), ip)
	}
	if len(ids) == 0 {
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
