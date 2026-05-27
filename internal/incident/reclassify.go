package incident

import (
	"strings"

	"github.com/pidginhost/csm/internal/alert"
)

// kindRank orders Kind values from weakest to strongest so the merge
// path can upgrade an incident's Kind when a stronger pattern appears
// later, but never downgrades. Higher number = stronger / more
// operator-attention.
var kindRank = map[Kind]int{
	KindWebAccountCompromise: 1,
	KindMailboxTakeover:      2,
	KindPostExploitProcess:   3,
	KindHostIntegrityRisk:    4,
	KindCredentialSpray:      3,
}

var compoundPostExploitWebChecks = map[string]struct{}{
	"webshell":                  {},
	"webshell_realtime":         {},
	"webshell_content_realtime": {},
	"new_webshell_file":         {},
	"obfuscated_php":            {},
	"obfuscated_php_realtime":   {},
	"php_shield_webshell":       {},
}

var compoundPostExploitNetworkChecks = map[string]struct{}{
	"c2_connection":          {},
	"backdoor_port":          {},
	"backdoor_port_outbound": {},
}

// maybeReclassifyKind upgrades inc.Kind in place when the new finding
// classifies as a stronger Kind, or when the incident's sticky
// CompoundFlags plus the new finding cover a compound pattern that the
// per-finding classifier cannot see. Compound rules at this time:
// webshell + outbound C2 connection -> PostExploitProcess. Idempotent:
// calling with weaker findings is a no-op.
//
// CompoundFlags are mutated here so callers do not need a separate
// pass; they survive timeline trimming so an early webshell still
// arms the rule when a much later C2 finding arrives.
func maybeReclassifyKind(inc *Incident, f alert.Finding) {
	if inc == nil {
		return
	}
	// Hydrate sticky flags from the current timeline so incidents
	// restored from bbolt (predating sticky flags) or built directly
	// in tests still arm the compound rule. Timeline scan is bounded
	// by maxIncidentTimeline so the cost is constant.
	hydrateCompoundFlagsFromTimeline(&inc.CompoundFlags, inc.Timeline)
	updateCompoundFlags(&inc.CompoundFlags, f.Check)
	if newKind := ClassifyKind(f); kindRank[newKind] > kindRank[inc.Kind] {
		inc.Kind = newKind
	}
	if kindRank[KindPostExploitProcess] > kindRank[inc.Kind] && inc.CompoundFlags.Webshell && inc.CompoundFlags.C2 {
		inc.Kind = KindPostExploitProcess
	}
}

// hydrateCompoundFlagsFromTimeline OR-merges timeline-derived signals
// into flags. Used as a one-shot migration for legacy/persisted
// incidents that have webshell or C2 events in their timeline but no
// CompoundFlags yet. Trimmed timelines may miss events, but anything
// still present remains a valid signal.
func hydrateCompoundFlagsFromTimeline(flags *CompoundFlags, events []IncidentEvent) {
	if flags == nil || (flags.Webshell && flags.C2) {
		return
	}
	for _, ev := range events {
		updateCompoundFlags(flags, ev.Check)
		if flags.Webshell && flags.C2 {
			return
		}
	}
}

// updateCompoundFlags sets the webshell / C2 flag based on a Finding's
// check name. Once true a flag stays true so reclassify decisions are
// not silently disarmed by later trimming.
func updateCompoundFlags(flags *CompoundFlags, check string) {
	if flags == nil {
		return
	}
	check = strings.ToLower(strings.TrimSpace(check))
	if _, ok := compoundPostExploitWebChecks[check]; ok {
		flags.Webshell = true
	}
	if _, ok := compoundPostExploitNetworkChecks[check]; ok {
		flags.C2 = true
	}
}
