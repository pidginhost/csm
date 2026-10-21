package daemon

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"log"
	"net"
	"os"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/reporting"
	"github.com/pidginhost/csm/internal/threatintel"
)

const (
	centralRefreshDefault = 6 * time.Hour
	centralBlockThreshold = 60
	centralChallengeTTL   = 6 * time.Hour
	centralBlockTTL       = 24 * time.Hour
	centralActionQueue    = 1024
)

type centralQueuedAction struct {
	findingID string
	decision  reporting.Decision
	ip        string
	// root is the local finding's admission evidence the action answers.
	root        admission.Evidence
	rootFinding alert.Finding
	rootErr     error
}

// documentationNets are reserved/non-routable ranges (RFC 5737 documentation,
// RFC 3849 IPv6 documentation, RFC 2544 benchmarking) that must never be acted
// on; they are not routable real attackers.
var documentationNets = mustCIDRs(
	"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "198.18.0.0/15", "2001:db8::/32",
)

// nonPublicNets are special-purpose ranges (IANA special-purpose registries)
// that net.IP's unicast and private predicates miss: "this network",
// carrier-grade NAT, IETF protocol assignments, the deprecated 6to4 relay
// anycast, the reserved block, deprecated IPv4-compatible and site-local IPv6,
// IPv6 discard-only and dummy sources, IETF IPv6 assignments, local-use
// translation and segment routing. None is a public source to report or act
// on; the central collector refuses them too.
var nonPublicNets = mustCIDRs(
	"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.88.99.0/24", "240.0.0.0/4",
	"::/96", "fec0::/10", "100::/64", "100:0:0:1::/64", "2001::/23",
	"64:ff9b:1::/48", "5f00::/16",
)

// teredoNet is carved out of 2001::/23: Teredo clients are real hosts that can
// send abusive traffic.
var teredoNet = mustCIDRs("2001::/32")[0]

// nat64Net and sixToFourNet embed an IPv4 source (RFC 6052, RFC 3056); the
// firebreak judges the embedded address.
var (
	nat64Net     = mustCIDRs("64:ff9b::/96")[0]
	sixToFourNet = mustCIDRs("2002::/16")[0]
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

// centralRefresh refreshes store and logs each success with its version, so an
// operator can check from the log that a node's signed pulls work.
func centralRefresh(store *reporting.CentralStore) func(context.Context) error {
	return func(ctx context.Context) error {
		if err := store.Refresh(ctx); err != nil {
			return err
		}
		// #nosec G706 -- version is uint64 formatted as decimal, with no log control characters.
		log.Printf("central-intel: refresh complete (version=%d)", store.Version())
		return nil
	}
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

	puller := reporting.NewPuller(nil, cc.SetURL, pubHex)
	if cc.AuthTarget != "" {
		node, ok := centralSigner(cc.AuthTarget, d.cfg.Reputation.Report.Targets)
		if !ok {
			log.Printf("central-intel: reputation.central.auth_target %q has no usable Ed25519 node key; consumer stays off", cc.AuthTarget)
			return nil
		}
		puller = reporting.NewSignedPuller(nil, cc.SetURL, pubHex, node, nil)
	}
	store := reporting.NewCentralStore(puller)
	firebreak := d.centralFirebreak()
	consumer := newCentralActionConsumer(d.stopCh, centralActionQueue, interval, centralRefresh(store), d.performCentralAction)
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
	// The local finding is the corroboration, so it must name the address
	// as an attacker. A response record, a health finding, the remote end
	// of an outbound connection, a customer login or an advisory does not.
	ip := f.SourceIP
	if ip == "" || !checks.AddressEvidence(f.Check, f.Severity) {
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
	root, rootErr := checks.PrepareAdmissionRoot(f, ip)
	return centralQueuedAction{decision: dec, ip: ip, findingID: alert.FindingID(f), root: root, rootFinding: f, rootErr: rootErr}, true
}

func (d *Daemon) performCentralAction(a centralQueuedAction) error {
	switch a.decision {
	case reporting.DecisionChallenge:
		if d.ipList != nil {
			checks.AnswerPreparedRoot(admission.KindChallenge, a.root, admission.EntryCentral, a.rootFinding, a.rootErr, centralChallengeTTL)
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
			Root:         a.root,
			Entry:        admission.EntryCentral,
			RootFinding:  a.rootFinding,
			RootErr:      a.rootErr,
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
	// Protected IPs are never blockable, a host without a firewall engine
	// cannot block, and automatic blocking may be switched off; all are
	// expected, not failures.
	if isCentralBlockRefusal(err) {
		return
	}
	log.Printf("central-intel: block %s failed: %v", ip, err)
}

func isCentralBlockRefusal(err error) bool {
	return isProtectedIPRefusal(err) || errors.Is(err, checks.ErrNoIPBlocker) || errors.Is(err, checks.ErrAutoBlockDisabled)
}

// centralFirebreak returns a predicate that reports whether an IP must never be
// acted on from central data or reported to it: anything not global unicast,
// private and other non-public ranges, documentation ranges, or an operator
// infra_ips entry.
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
	var protected func(ip net.IP) bool
	protected = func(ip net.IP) bool {
		if !ip.IsGlobalUnicast() || ip.IsPrivate() {
			return true
		}
		for _, n := range nonPublicNets {
			if n.Contains(ip) && !teredoNet.Contains(ip) {
				return true
			}
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
		// Check the original address before its embedded IPv4: operators
		// can protect the IPv6 host or prefix independently of that IPv4.
		if nat64Net.Contains(ip) {
			return protected(net.IPv4(ip[12], ip[13], ip[14], ip[15]))
		}
		if sixToFourNet.Contains(ip) {
			return protected(net.IPv4(ip[2], ip[3], ip[4], ip[5]))
		}
		return false
	}
	return func(s string) bool {
		ip := net.ParseIP(s)
		if ip == nil {
			return true // unparseable: never act
		}
		return protected(ip)
	}
}
