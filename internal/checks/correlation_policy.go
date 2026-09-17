package checks

import (
	"fmt"
	"sort"
	"sync"
)

// CorrelationClass is a check's role in cross-account correlation. Every
// registry entry sets one; the zero value fails the completeness test.
type CorrelationClass uint8

const (
	// CorrelationUnclassified is the zero value and never valid.
	CorrelationUnclassified CorrelationClass = iota
	// CorrelationIgnored is never an input to correlation; a reason is required.
	CorrelationIgnored
	// CorrelationSecurityEvent: an attributed Critical counts toward coordinated_attack.
	CorrelationSecurityEvent
	// CorrelationMalwareArtifact is a SecurityEvent that also raises
	// cross_account_malware when the same check appears on two accounts.
	CorrelationMalwareArtifact
	// CorrelationDerived is an output of correlation and never an input.
	CorrelationDerived
)

// Ignore reasons. The value is a short token; the sentence is what the
// generated policy table prints and what a reviewer reads.
const (
	reasonPosture          = "posture"
	reasonAttackerSide     = "attacker-side"
	reasonInformational    = "informational"
	reasonSelfHealth       = "self-health"
	reasonResponse         = "response"
	reasonHostScope        = "host-scope"
	reasonAccountAggregate = "account-aggregate"
	reasonPerformance      = "performance"
)

var correlationReasonSentences = map[string]string{
	reasonPosture:          "static configuration, hardening or hygiene state; a Critical means a misconfiguration, not an attack on the account",
	reasonAttackerSide:     "attacker activity or attempted access, not evidence of compromise of the named victim",
	reasonInformational:    "audit trail or inventory event with no compromise claim",
	reasonSelfHealth:       "CSM's own health, capacity or coverage state",
	reasonResponse:         "record of an automatic action already taken; feeding it back would double count",
	reasonHostScope:        "host-wide condition with no account to attribute; a cross-account count cannot use it even when it is a real compromise",
	reasonAccountAggregate: "already summarizes several accounts without a single victim identity",
	reasonPerformance:      "resource usage",
}

// Attribution gaps documented on eligible checks. A gap never changes
// eligibility: an attributed Critical still counts.
const gapEnvelopeSender = "envelope-sender"

var correlationGapSentences = map[string]string{
	gapEnvelopeSender: "sender-domain volume aggregate is unattributed when contributing submissions are unverified or belong to different accounts",
}

// validateCorrelationPolicy returns the first policy violation in entries,
// naming the offending check.
func validateCorrelationPolicy(entries []CheckInfo) error {
	for _, c := range entries {
		switch c.Correlation {
		case CorrelationIgnored:
			if _, ok := correlationReasonSentences[c.CorrelationReason]; !ok {
				return fmt.Errorf("check %q is ignored without a known reason (%q)", c.Name, c.CorrelationReason)
			}
			if c.CorrelationGap != "" {
				return fmt.Errorf("check %q is ignored but carries gap %q", c.Name, c.CorrelationGap)
			}
		case CorrelationSecurityEvent, CorrelationMalwareArtifact:
			if c.CorrelationReason != "" {
				return fmt.Errorf("check %q is eligible but carries reason %q", c.Name, c.CorrelationReason)
			}
			if c.CorrelationGap != "" {
				if _, ok := correlationGapSentences[c.CorrelationGap]; !ok {
					return fmt.Errorf("check %q carries unknown gap %q", c.Name, c.CorrelationGap)
				}
			}
		case CorrelationDerived:
			if c.CorrelationReason != "" || c.CorrelationGap != "" {
				return fmt.Errorf("check %q is derived but carries a reason or gap", c.Name)
			}
		default:
			return fmt.Errorf("check %q has no correlation classification (class %d)", c.Name, c.Correlation)
		}
	}
	return nil
}

// correlationIndex is built once from the registry. It never reads the
// filesystem, the store or the network.
type correlationIndex struct {
	classes map[string]CorrelationClass
	derived []string
}

var (
	correlationOnce  sync.Once
	correlationTable *correlationIndex
)

func loadCorrelationIndex() *correlationIndex {
	correlationOnce.Do(func() {
		idx := &correlationIndex{classes: make(map[string]CorrelationClass, len(checkRegistry))}
		for _, c := range checkRegistry {
			idx.classes[c.Name] = c.Correlation
			if c.Correlation == CorrelationDerived {
				idx.derived = append(idx.derived, c.Name)
			}
		}
		sort.Strings(idx.derived)
		correlationTable = idx
	})
	return correlationTable
}

func correlationClassOf(name string) CorrelationClass {
	return loadCorrelationIndex().classes[name]
}

// securityEventEligible reports whether an attributed Critical finding of
// this check counts toward coordinated_attack.
func securityEventEligible(name string) bool {
	switch correlationClassOf(name) {
	case CorrelationSecurityEvent, CorrelationMalwareArtifact:
		return true
	}
	return false
}

// DerivedCorrelationChecks returns the names correlation itself emits,
// sorted. The caller owns the slice.
func DerivedCorrelationChecks() []string {
	return append([]string(nil), loadCorrelationIndex().derived...)
}

// IsDerivedCorrelationCheck reports whether name is an output of correlation.
func IsDerivedCorrelationCheck(name string) bool {
	return correlationClassOf(name) == CorrelationDerived
}
