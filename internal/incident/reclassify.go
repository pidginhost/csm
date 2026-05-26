package incident

import (
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
	KindCredentialSpray:      3, // peer of post-exploit; never reached here in practice
}

// maybeReclassifyKind upgrades inc.Kind in place when the new finding
// classifies as a stronger Kind, or when the timeline now shows a
// compound pattern that the per-finding classifier cannot see.
// Compound rules at this time: webshell + outbound C2 connection ->
// PostExploitProcess. Idempotent: calling with weaker findings is a
// no-op.
func maybeReclassifyKind(inc *Incident, f alert.Finding) {
	if inc == nil {
		return
	}
	if newKind := ClassifyKind(f); kindRank[newKind] > kindRank[inc.Kind] {
		inc.Kind = newKind
	}
	if inc.Kind != KindPostExploitProcess && hasCompoundPostExploit(inc.Timeline, f) {
		inc.Kind = KindPostExploitProcess
	}
}

// hasCompoundPostExploit reports whether the union of timeline
// events plus the new finding covers BOTH a webshell-style signal
// and an outbound-C2 / backdoor-port signal. Either appearing alone
// is not enough; the combination is the active-attack indicator.
func hasCompoundPostExploit(events []IncidentEvent, f alert.Finding) bool {
	seenWebshell := false
	seenC2 := false
	checkScan := func(check string) {
		switch check {
		case "webshell",
			"webshell_realtime",
			"webshell_content_realtime",
			"new_webshell_file",
			"obfuscated_php_realtime":
			seenWebshell = true
		case "c2_connection",
			"backdoor_port",
			"backdoor_port_outbound":
			seenC2 = true
		}
	}
	for _, ev := range events {
		checkScan(ev.Check)
	}
	checkScan(f.Check)
	return seenWebshell && seenC2
}
