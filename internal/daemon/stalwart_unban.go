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
// address and each is pending at most once, so the set needs no cap.
type stalwartUnban struct {
	cfg  func() *config.Config
	stop <-chan struct{}
	wg   *sync.WaitGroup

	mu      sync.Mutex
	pending map[string]struct{}
	running bool
}

// newStalwartUnban returns nil unless this host's mail server is Stalwart.
func newStalwartUnban(d *Daemon) *stalwartUnban {
	if detectMTA() != platform.MTAStalwart {
		return nil
	}
	return &stalwartUnban{cfg: d.currentCfg, stop: d.stopCh, wg: &d.wg, pending: map[string]struct{}{}}
}

// add queues ip and returns at once. No drain starts once the daemon is
// stopping, so none can join its final wait late.
func (u *stalwartUnban) add(ip string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	select {
	case <-u.stop:
		return
	default:
	}
	u.pending[ip] = struct{}{}
	if u.running {
		return
	}
	u.running = true
	u.wg.Add(1)
	obs.Go("stalwart-unban", u.drain)
}

func (u *stalwartUnban) drain() {
	defer u.wg.Done()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-u.stop:
			cancel()
		case <-ctx.Done():
		}
	}()
	for {
		ip, ok := u.next()
		if !ok {
			return
		}
		if err := u.clear(ctx, ip); err != nil {
			fmt.Fprintf(os.Stderr, "[%s] Stalwart may still refuse %s: %v\n", ts(), ip, err)
		}
	}
}

// next takes one pending address. It ends the drain when none is left or the
// daemon is stopping; until the daemon stops, a later add starts a new one.
func (u *stalwartUnban) next() (string, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	select {
	case <-u.stop:
	default:
		for ip := range u.pending {
			delete(u.pending, ip)
			return ip, true
		}
	}
	u.running = false
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
