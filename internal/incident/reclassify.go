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
	KindWebAttack:            0,
	KindMailboxBruteforce:    0,
	KindWebAccountCompromise: 1,
	KindMailboxTakeover:      2,
	KindPostExploitProcess:   3,
	KindHostIntegrityRisk:    4,
	KindCredentialSpray:      3,
	KindHostTakeover:         5,
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

// compoundHostPrivescUID0Checks, compoundHostPrivescSUIDChecks, and
// compoundHostPrivescBadASNChecks are the three host-takeover legs the
// takeover rule correlates: a new uid-0 account, a planted suid binary, and
// an outbound connection to a bad/unexpected ASN.
var compoundHostPrivescUID0Checks = map[string]struct{}{
	"uid0_account": {},
}

var compoundHostPrivescSUIDChecks = map[string]struct{}{
	"suid_binary": {},
}

var compoundHostPrivescBadASNChecks = map[string]struct{}{
	"bad_asn_outbound": {},
}

// allCompoundFlagsSet reports whether every compound signal is already
// recorded, so the timeline hydrate loop can stop early.
func allCompoundFlagsSet(f CompoundFlags) bool {
	return f.Webshell && f.C2 && f.UID0 && f.SUID && f.BadASNOutbound
}

// hostTakeoverLegs counts how many of the three distinct host-takeover legs
// an incident has observed. Two or more legs escalate to KindHostTakeover.
func hostTakeoverLegs(f CompoundFlags) int {
	n := 0
	if f.UID0 {
		n++
	}
	if f.SUID {
		n++
	}
	if f.BadASNOutbound {
		n++
	}
	return n
}

// maybeReclassifyKind upgrades inc.Kind in place when the new finding
// classifies as a stronger Kind, or when the incident's sticky
// CompoundFlags plus the new finding cover a compound pattern that the
// per-finding classifier cannot see. Compound rules at this time:
// webshell + outbound C2 connection -> PostExploitProcess;
// uid0_account + suid_binary -> HostTakeover. Idempotent: calling with
// weaker findings is a no-op.
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
	// Host takeover: any two of the three distinct legs (new uid-0 account,
	// planted suid binary, outbound connection to a bad ASN) on the same
	// host inside the window.
	if kindRank[KindHostTakeover] > kindRank[inc.Kind] && hostTakeoverLegs(inc.CompoundFlags) >= 2 {
		inc.Kind = KindHostTakeover
	}
}

// hydrateCompoundFlagsFromTimeline OR-merges timeline-derived signals
// into flags. Used as a one-shot migration for legacy/persisted
// incidents that have webshell or C2 events in their timeline but no
// CompoundFlags yet. Trimmed timelines may miss events, but anything
// still present remains a valid signal.
func hydrateCompoundFlagsFromTimeline(flags *CompoundFlags, events []IncidentEvent) {
	if flags == nil || allCompoundFlagsSet(*flags) {
		return
	}
	for _, ev := range events {
		updateCompoundFlags(flags, ev.Check)
		if allCompoundFlagsSet(*flags) {
			return
		}
	}
}

// updateCompoundFlags sets sticky compound flags based on a Finding's
// check name. Once true a flag stays true so reclassify decisions are not
// silently disarmed by later trimming.
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
	if _, ok := compoundHostPrivescUID0Checks[check]; ok {
		flags.UID0 = true
	}
	if _, ok := compoundHostPrivescSUIDChecks[check]; ok {
		flags.SUID = true
	}
	if _, ok := compoundHostPrivescBadASNChecks[check]; ok {
		flags.BadASNOutbound = true
	}
}
