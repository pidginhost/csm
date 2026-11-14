package checks

import (
	"strings"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/reporting"
)

// AutomaticResponseAllowed reports whether cfg still allows an automatic
// response of kind for check, arriving on entry. These are the switches
// the legacy funnels test before they act; admission serves queued work
// later and tests them again. The check registry's own response policy
// was enforced when the work was minted. An unknown entry is not allowed.
func AutomaticResponseAllowed(cfg *config.Config, kind admission.Kind, entry admission.Entry, check string) bool {
	if cfg == nil || !CheckResponseEnabled(cfg, check) {
		return false
	}
	central := cfg.Reputation.Central.Enabled
	action := reporting.ParseAction(cfg.Reputation.Central.Action)
	if kind == admission.KindChallenge {
		// Challenges follow challenge routing, not the block switches.
		switch entry {
		case admission.EntryScan:
			return responseActionForCheck(cfg, check) == responseChallenge && !isHardBlockCheck(check) && (ResponsePolicyFor(check).Block != BlockWithCpanelLogins || cfg.AutoResponse.BlockCpanelLogins)
		case admission.EntryCentral:
			return cfg.Challenge.Enabled && central && action != reporting.ActionOff
		}
		return false
	}
	if !cfg.AutoResponse.Enabled || !cfg.AutoResponse.BlockIPs {
		return false
	}
	switch entry {
	case admission.EntryScan:
		return kind == admission.KindBlockIP && blockableCheck(check, cfg.AutoResponse.BlockCpanelLogins)
	case admission.EntryChallengeTimeout:
		return cfg.Challenge.Enabled
	case admission.EntryIncident:
		return cfg.Incidents.AutoBlock.Enabled && blocksAtSeverity(cfg.Incidents.AutoBlock.BlockAtSeverity)
	case admission.EntryIncidentSpray:
		s := cfg.Incidents.SpraySuppression
		return s.Enabled && !s.DryRun && blocksAtSeverity(s.BlockAtSeverity)
	case admission.EntryCentral:
		return central && action == reporting.ActionBlockIfLocalCorroborated
	case admission.EntryNetblock:
		return cfg.AutoResponse.NetBlock
	case admission.EntryPermblock:
		return cfg.AutoResponse.PermBlock
	case admission.EntryASNCrawl, admission.EntryMailSubnet:
		return true
	}
	return false
}

// BlocksAProxy reports whether queued block c would block a trusted proxy
// under cfg, or a known CDN or website-firewall edge that one of its roots
// may have seen relaying other people's requests, as the mint refuses it.
// roots loads c's root evidence and is read only for an edge.
func BlocksAProxy(cfg *config.Config, c admission.Candidate, roots func() []admission.Evidence) bool {
	addr, ok := c.Key.Target.Addr()
	if c.Key.Kind != admission.KindBlockIP || !ok {
		return false
	}
	ip := addr.String()
	if IsTrustedProxy(ip, cfg) {
		return true
	}
	if !KnownProxyPeer(ip, cfg) {
		return false
	}
	for _, e := range roots() {
		if producerMayRelay(e.Producer()) {
			return true
		}
	}
	return false
}

// producerMayRelay reports whether an address producer p reads can be an
// edge relaying other people's requests, as the mint judges it. The queue
// holds no proxied client, so a producer's trusted-chain reading never
// applies.
func producerMayRelay(p admission.ProducerID) bool {
	for _, entry := range producerTable {
		if entry.Spec.ID != p {
			continue
		}
		for _, kind := range []admission.Attribution{admission.AttributionPeer, admission.AttributionHTTPPeer, admission.AttributionDerived} {
			if entry.Spec.Attribution.Has(kind) && mayBeProxyEdge(kind, p) {
				return true
			}
		}
	}
	return false
}

// blocksAtSeverity reports whether an incident block_at_severity setting
// blocks at all; empty or unknown means detection only.
func blocksAtSeverity(s string) bool {
	switch strings.ToLower(s) {
	case "high", "critical":
		return true
	}
	return false
}
