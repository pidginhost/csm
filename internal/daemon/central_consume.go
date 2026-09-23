package daemon

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"log"
	"net"
	"os"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/reporting"
	"github.com/pidginhost/csm/internal/threatintel"
)

const (
	centralRefreshDefault = 6 * time.Hour
	centralBlockThreshold = 80
	centralChallengeTTL   = 6 * time.Hour
	centralBlockTTL       = 24 * time.Hour
	centralActionQueue    = 1024
)

type centralQueuedAction struct {
	findingID string
	decision  reporting.Decision
	ip        string
}

// documentationNets are reserved/non-routable ranges (RFC 5737 documentation,
// RFC 3849 IPv6 documentation, RFC 2544 benchmarking) that must never be acted
// on; they are not routable real attackers.
var documentationNets = mustCIDRs(
	"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "198.18.0.0/15", "2001:db8::/32",
)

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
	if cc.Action != "" && !reporting.IsValidAction(cc.Action) {
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
	consumer := newCentralActionConsumer(d.stopCh, centralActionQueue, interval, store.Refresh, d.performCentralAction)
	d.registerQueueSource("central", consumer)

	alert.SetCentralHook(func(f alert.Finding) {
		a, ok := d.planCentralAction(store, policy, threshold, firebreak, f)
		if !ok {
			return
		}
		consumer.enqueue(a)
	})
	log.Printf("central-intel: enabled (action=%s, threshold=%d, refresh=%s)", policy, threshold, interval)

	return func() {
		defer alert.SetCentralHook(nil)
		consumer.run()
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
	if err := d.performCentralAction(a); err != nil {
		logCentralBlockFailure(a.ip, err)
	}
}

func (d *Daemon) planCentralAction(store *reporting.CentralStore, action reporting.Action, threshold int, firebreak func(string) bool, f alert.Finding) (centralQueuedAction, bool) {
	// Response and coverage-health findings are not independent attacker
	// signals. Feeding them back into the consumer can schedule a redundant
	// block or attribute service degradation to an unrelated source IP.
	if f.Check == "auto_block" || f.Check == "reputation_quota_exhausted" || f.Check == "threat_feed_stale" {
		return centralQueuedAction{}, false
	}
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
	return centralQueuedAction{decision: dec, ip: ip, findingID: alert.FindingID(f)}, true
}

func (d *Daemon) performCentralAction(a centralQueuedAction) error {
	switch a.decision {
	case reporting.DecisionChallenge:
		if d.ipList != nil {
			d.ipList.AddNonEscalating(a.ip, "central-intel", centralChallengeTTL)
		}
	case reporting.DecisionBlock:
		res, err := checks.ApplyBlock(d.currentCfg(), checks.ApplyBlockRequest{
			IP:           a.ip,
			EngineReason: centralIntelBlockReason,
			Reason:       centralIntelBlockReason,
			TTL:          centralBlockTTL,
			Source:       checks.BlockSourceCentral,
			FindingID:    a.findingID,
		})
		d.recordAppliedBlocks(res.Findings)
		if err != nil {
			return err
		}
		log.Printf("central-intel: block %s outcome: %s", a.ip, res.Outcome)
	}
	return nil
}

func logCentralBlockFailure(ip string, err error) {
	// Protected IPs are never blockable and a host without a firewall
	// engine cannot block; both are expected, not failures.
	if isCentralBlockRefusal(err) {
		return
	}
	log.Printf("central-intel: block %s failed: %v", ip, err)
}

func isCentralBlockRefusal(err error) bool {
	return isProtectedIPRefusal(err) || errors.Is(err, checks.ErrNoIPBlocker)
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
		// A Cloudflare edge or a verified crawler in the scored set is not
		// an attacker to act on: challenging or blocking it hits every
		// visitor behind the edge, or delists the site.
		if checks.IsCloudflareIP(ip) || threatintel.IPInAnyVerifiedBotRange(ip) {
			return true
		}
		return false
	}
}
