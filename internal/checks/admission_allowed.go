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
	if cfg == nil {
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

// blocksAtSeverity reports whether an incident block_at_severity setting
// blocks at all; empty or unknown means detection only.
func blocksAtSeverity(s string) bool {
	switch strings.ToLower(s) {
	case "high", "critical":
		return true
	}
	return false
}
