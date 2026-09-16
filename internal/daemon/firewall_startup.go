package daemon

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/mailranges"
	"github.com/pidginhost/csm/internal/obs"
	"github.com/pidginhost/csm/internal/store"
	"github.com/pidginhost/csm/internal/threatintel"
)

type firewallStartupOps struct {
	newEngine func(*firewall.FirewallConfig, string) (*firewall.Engine, error)
	apply     func(*firewall.Engine) error
	delays    []time.Duration
}

func (d *Daemon) startFirewall() {
	d.startFirewallUsing(firewallStartupOps{
		newEngine: firewall.NewEngine,
		apply:     (*firewall.Engine).Apply,
		delays:    []time.Duration{time.Second, 2 * time.Second},
	})
}

// Retry before publishing the engine or starting its consumers. Each attempt
// gets a fresh netlink transaction; a failed Apply preserves the kernel rules.
func retryFirewallStartup(stop <-chan struct{}, delays []time.Duration, attempt func() (*firewall.Engine, error)) (*firewall.Engine, error) {
	for i := 0; ; i++ {
		select {
		case <-stop:
			return nil, context.Canceled
		default:
		}
		engine, err := attempt()
		if err == nil {
			return engine, nil
		}
		if i == len(delays) {
			return nil, err
		}
		timer := time.NewTimer(delays[i])
		select {
		case <-stop:
			timer.Stop()
			return nil, context.Canceled
		case <-timer.C:
		}
	}
}

func (d *Daemon) startFirewallUsing(ops firewallStartupOps) {
	if err := checks.InitAutoBlockQueueHealth(d.cfg.StatePath); err != nil {
		csmlog.Error("auto-block retry state unreadable", "err", err)
	}
	effectiveFirewall := config.EffectiveFirewallConfig(d.cfg)
	if effectiveFirewall == nil || !effectiveFirewall.Enabled {
		return
	}

	engine, err := retryFirewallStartup(d.stopCh, ops.delays, func() (*firewall.Engine, error) {
		return d.prepareFirewall(effectiveFirewall, ops)
	})
	if err != nil {
		d.fwStartupError = err.Error()
		csmlog.Error("firewall remains unmanaged after startup attempts", "err", err)
		return
	}
	d.fwStartupError = ""

	// Apply does not consult the verdict callback. Install the shutdown
	// context only after a successful firewall setup so a failed init
	// does not leave behind a stopCh waiter.
	verdictCtx, cancelVerdict := context.WithCancel(context.Background())
	go func() {
		<-d.stopCh
		cancelVerdict()
	}()
	engine.SetShutdownContext(verdictCtx)

	d.setFirewallEngine(engine)
	// A crash can leave an action whose outcome nothing has proven yet, and
	// that blocks new mutations until it is settled.
	recoverFirewallActions(d.fwActions)

	// Set firewall engine for auto-blocking
	checks.SetIPBlocker(engine)
	// Prune auto-response subnet blocks that now intersect the DoS-exempt set.
	// The mail-provider cache is loaded (initMailRanges ran before startFirewall)
	// and Apply has completed, so the exempt set is current.
	checks.PruneExemptAutoSubnets(d.cfg, engine)
	// Wire the incident firewall hand-off through the ApplyBlock chokepoint
	// so the correlator distinguishes live mutation from dry-run and no-op
	// outcomes AND spray blocks leave the standard evidence trail.
	SetIncidentSprayBlocker(d.applyIncidentSprayBlock)

	fwState, _ := firewall.LoadState(d.cfg.StatePath)
	csmlog.Info("firewall active",
		"blocked_ips", len(fwState.Blocked),
		"allowed_ips", len(fwState.Allowed),
	)

	// Start Dynamic DNS resolver if configured. The same resolver
	// loop also services hostnames listed under infra_ips so they get
	// DNS-refreshed into the engine's infra-block guard; otherwise the
	// hostname entries would only protect operators whose IPs never
	// move, which defeats the point of listing them by name.
	infraHosts := infraHostnames(effectiveFirewall.InfraIPs)
	dynHosts := append([]string{}, effectiveFirewall.DynDNSHosts...)
	for _, h := range infraHosts {
		if !containsString(dynHosts, h) {
			dynHosts = append(dynHosts, h)
		}
	}
	if len(dynHosts) > 0 {
		resolver := firewall.NewDynDNSResolver(dynHosts, engine)
		resolver.SetInfraEngine(engine)
		for _, h := range infraHosts {
			resolver.RegisterInfraHost(h)
		}
		resolver.SetFindingSink(func(host string) {
			if !alert.TryEnqueue(d.alertCh, dynDNSUnresolvableFinding(host)) {
				atomic.AddInt64(&d.droppedAlerts, 1)
				fmt.Fprintf(os.Stderr, "[%s] alert channel full, dropping dyndns guard finding: %s\n", ts(), host)
			}
		})
		d.wg.Add(1)
		obs.Go("dyndns-resolver", func() {
			defer d.wg.Done()
			resolver.Run(d.stopCh)
		})
		csmlog.Info("DynDNS resolver active", "hosts", len(dynHosts), "infra_hosts", len(infraHosts))
	}

	// Start Cloudflare IP whitelist refresh if configured
	if d.cfg.Cloudflare.Enabled {
		d.wg.Add(1)
		obs.Go("cloudflare-refresh", d.cloudflareRefreshLoop)
		csmlog.Info("cloudflare IP whitelist enabled", "refresh_hours", d.cfg.Cloudflare.RefreshHours)
	}
}

func (d *Daemon) prepareFirewall(effectiveFirewall *firewall.FirewallConfig, ops firewallStartupOps) (*firewall.Engine, error) {
	engine, err := ops.newEngine(effectiveFirewall, d.cfg.StatePath)
	if err != nil {
		return nil, fmt.Errorf("initializing firewall: %w", err)
	}

	// Wire dry-run + verdict callbacks BEFORE Apply() and before the
	// engine is exposed via d.fwEngine / checks.SetIPBlocker. The
	// auto_response.dry_run safety default is "on": if any code path
	// reaches engine.BlockIP while these callbacks are still nil, the
	// engine treats dry-run as off and the block lands live, defeating
	// the operator's stated intent. Wiring before exposure removes the
	// boot-time race window entirely.
	engine.SetDryRunRecorder(func(ip, reason string, timeout time.Duration) {
		if db := store.Global(); db != nil {
			db.RecordDryRunBlock(ip, reason, timeout)
		}
	})
	engine.SetDryRunEnabledFunc(d.autoResponseDryRunEnabled)
	engine.SetVerdictAsker(d.askVerdictCallback)
	// The auto-block path skips published-crawler IPs so a high-volume bot is
	// never re-added to blocked_ips behind the operator allowlist. Built-in and
	// operator verified_bots ranges both flow through this lookup.
	engine.SetSoftAllowChecker(func(ip string) bool {
		parsed := net.ParseIP(ip)
		return parsed != nil && threatintel.IPInAnyVerifiedBotRange(parsed)
	})

	// Push the mail-provider ranges loaded by initMailRanges() into the engine
	// before Apply() so the dos_exempt_nets interval sets are populated in the
	// first nftables transaction. initMailRanges() runs before startFirewall()
	// so ProviderNets() always returns the cached or embedded snapshot here.
	engine.SetDOSExemptProviderNets(mailranges.ProviderNets())

	if err := ops.apply(engine); err != nil {
		return nil, fmt.Errorf("applying firewall: %w", err)
	}

	return engine, nil
}
