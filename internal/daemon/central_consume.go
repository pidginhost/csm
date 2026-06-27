package daemon

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"log"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/reporting"
)

const (
	centralRefreshDefault = 6 * time.Hour
	centralBlockThreshold = 80
	centralChallengeTTL   = 6 * time.Hour
	centralBlockTTL       = 24 * time.Hour
	centralActionQueue    = 1024
)

type centralQueuedAction struct {
	decision reporting.Decision
	ip       string
}

// documentationNets are reserved/non-routable ranges (RFC 5737 documentation,
// RFC 3849 IPv6 documentation, RFC 2544 benchmarking) that must never be acted
// on; they are not routable real attackers.
var documentationNets = mustCIDRs(
	"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "198.18.0.0/15", "2001:db8::/32",
)

// knownCentralAction reports whether s is a recognized central action policy.
func knownCentralAction(s string) bool {
	switch reporting.Action(s) {
	case reporting.ActionOff, reporting.ActionChallenge, reporting.ActionBlockIfLocalCorroborated:
		return true
	default:
		return false
	}
}

func mustCIDRs(cidrs ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// startCentralConsume wires the central scored-set consumer: it pulls and
// verifies the signed set on an interval and installs alert.CentralHook so a
// finding whose IP is in the set is escalated per the configured action. It
// returns the refresh loop, or nil when disabled/misconfigured.
func (d *Daemon) startCentralConsume() func() {
	alert.SetCentralHook(nil)

	cc := d.cfg.Reputation.Central
	if !cc.Enabled {
		return nil
	}
	if cc.SetURL == "" {
		log.Printf("central-intel: enabled but set_url is empty; consumer stays off")
		return nil
	}
	pubHex := os.Getenv(cc.PubkeyEnv)
	if raw, err := hex.DecodeString(pubHex); err != nil || len(raw) != ed25519.PublicKeySize {
		log.Printf("central-intel: %s must hold a 64-hex-char Ed25519 public key; consumer stays off", cc.PubkeyEnv)
		return nil
	}

	policy := reporting.ParseAction(cc.Action)
	if cc.Action != "" && !knownCentralAction(cc.Action) {
		log.Printf("central-intel: unrecognized action %q, defaulting to challenge", cc.Action)
	}
	threshold := cc.BlockThreshold
	if threshold <= 0 {
		threshold = centralBlockThreshold
	}
	interval := centralRefreshDefault
	if cc.RefreshInterval != "" {
		if d2, err := time.ParseDuration(cc.RefreshInterval); err == nil && d2 > 0 {
			interval = d2
		}
	}

	store := reporting.NewCentralStore(reporting.NewPuller(nil, cc.SetURL, pubHex))
	firebreak := d.centralFirebreak()
	actions := make(chan centralQueuedAction, centralActionQueue)
	var droppedActions atomic.Uint64

	alert.SetCentralHook(func(f alert.Finding) {
		a, ok := d.planCentralAction(store, policy, threshold, firebreak, f)
		if !ok {
			return
		}
		select {
		case actions <- a:
		default:
			droppedActions.Add(1)
		}
	})
	log.Printf("central-intel: enabled (action=%s, threshold=%d, refresh=%s)", policy, threshold, interval)

	return func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		logDropped := func() {
			if n := droppedActions.Swap(0); n > 0 {
				log.Printf("central-intel: action queue full; dropped %d action(s)", n)
			}
		}
		go func() {
			<-d.stopCh
			cancel()
		}()
		defer alert.SetCentralHook(nil)

		// Initial pull so the set is usable before the first interval.
		if err := store.Refresh(ctx); err != nil {
			log.Printf("central-intel: initial pull failed: %v", err)
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-d.stopCh:
				logDropped()
				return
			default:
			}
			select {
			case <-d.stopCh:
				logDropped()
				return
			case a := <-actions:
				d.performCentralAction(a)
			case <-ticker.C:
				logDropped()
				if err := store.Refresh(ctx); err != nil {
					log.Printf("central-intel: refresh failed: %v", err)
				}
			}
		}
	}
}

// applyCentral escalates a finding's IP when it appears in the central set. A
// finding firing on the IP is the node's local corroboration. Firebreaks and
// the action policy gate what happens; central data never blocks on its own.
func (d *Daemon) applyCentral(store *reporting.CentralStore, action reporting.Action, threshold int, firebreak func(string) bool, f alert.Finding) {
	a, ok := d.planCentralAction(store, action, threshold, firebreak, f)
	if !ok {
		return
	}
	d.performCentralAction(a)
}

func (d *Daemon) planCentralAction(store *reporting.CentralStore, action reporting.Action, threshold int, firebreak func(string) bool, f alert.Finding) (centralQueuedAction, bool) {
	ip := f.SourceIP
	if ip == "" {
		return centralQueuedAction{}, false
	}
	entry, found := store.Lookup(ip)
	dec := reporting.Decide(reporting.DecisionInput{
		Found:               found,
		Score:               entry.Score,
		Protected:           firebreak(ip),
		LocallyCorroborated: true, // a finding fired on this IP
	}, action, threshold)

	if dec == reporting.DecisionIgnore {
		return centralQueuedAction{}, false
	}
	return centralQueuedAction{decision: dec, ip: ip}, true
}

func (d *Daemon) performCentralAction(a centralQueuedAction) {
	switch a.decision {
	case reporting.DecisionChallenge:
		if d.ipList != nil {
			d.ipList.AddNonEscalating(a.ip, "central-intel", centralChallengeTTL)
		}
	case reporting.DecisionBlock:
		if d.fwEngine != nil {
			if err := d.fwEngine.BlockIP(a.ip, "central-intel (locally corroborated)", centralBlockTTL); err != nil {
				logCentralBlockFailure(a.ip, err)
			}
		}
	}
}

func logCentralBlockFailure(ip string, err error) {
	if isProtectedIPRefusal(err) {
		return
	}
	log.Printf("central-intel: block %s failed: %v", ip, err)
}

// centralFirebreak returns a predicate that reports whether an IP must never be
// acted on from central data: loopback/unspecified/private, documentation
// ranges, or an operator infra_ips entry.
func (d *Daemon) centralFirebreak() func(string) bool {
	infraEntries := d.cfg.InfraIPs
	if d.cfg.Firewall != nil {
		infraEntries = mergeInfraIPs(d.cfg.InfraIPs, d.cfg.Firewall.InfraIPs)
	}

	var infra []*net.IPNet
	for _, raw := range infraEntries {
		if _, n, err := net.ParseCIDR(raw); err == nil {
			infra = append(infra, n)
			continue
		}
		if ip := net.ParseIP(raw); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			infra = append(infra, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
		}
	}
	return func(s string) bool {
		ip := net.ParseIP(s)
		if ip == nil {
			return true // unparseable: never act
		}
		if ip.IsLoopback() || ip.IsUnspecified() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
			return true
		}
		for _, n := range documentationNets {
			if n.Contains(ip) {
				return true
			}
		}
		for _, n := range infra {
			if n.Contains(ip) {
				return true
			}
		}
		return false
	}
}
