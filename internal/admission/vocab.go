// Package admission holds the typed vocabulary automatic firewall responses
// are admitted with: canonical targets, evidence records, verified owners,
// candidate identity and priority. It imports only the standard library so
// the checks, daemon, firewall and store packages can share it without an
// import cycle.
package admission

import (
	"errors"
	"fmt"
)

// Severity is a finding severity as admission orders it. The zero value is
// invalid; the checks package converts alert severities at its boundary.
type Severity uint8

const (
	SeverityWarning Severity = iota + 1
	SeverityHigh
	SeverityCritical
)

func (s Severity) Valid() bool { return s >= SeverityWarning && s <= SeverityCritical }

func (s Severity) String() string {
	switch s {
	case SeverityWarning:
		return "warning"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	}
	return fmt.Sprintf("severity(%d)", uint8(s))
}

// Class is the priority class of a candidate; larger classes are served
// first. It is not the action risk tier of internal/privops.
type Class uint8

const (
	// ClassC1: external intel or derived history about a locally sighted
	// address.
	ClassC1 Class = iota + 1
	// ClassC2: local attack observations such as brute force, floods,
	// scanners and WAF escalations.
	ClassC2
	// ClassC3: direct compromise evidence under a reviewed check policy, or
	// C2 corroborated by an independent root.
	ClassC3
)

func (c Class) Valid() bool { return c >= ClassC1 && c <= ClassC3 }

func (c Class) String() string {
	if c.Valid() {
		return fmt.Sprintf("c%d", uint8(c))
	}
	return fmt.Sprintf("class(%d)", uint8(c))
}

// Tier is the eviction pair. Only Tier decides strictly-lower-tier
// eviction; age, account and queue position never do.
type Tier struct {
	Class    Class
	Severity Severity
}

func (t Tier) Valid() bool { return t.Class.Valid() && t.Severity.Valid() }

// Less reports whether t is strictly lower than u: class first, then
// severity.
func (t Tier) Less(u Tier) bool {
	if t.Class != u.Class {
		return t.Class < u.Class
	}
	return t.Severity < u.Severity
}

// Family is the observation channel a check's evidence comes from. Two roots
// of one family never corroborate each other, so one HTTP request seen by
// both the access log and the WAF stays one root. The zero value carries no
// admissible address evidence.
type Family uint8

const (
	FamilyNone Family = iota
	// FamilyHTTP: web server and WAF observations of HTTP requests.
	FamilyHTTP
	// FamilyPanel: cPanel, WHM, webmail and panel API authentication.
	FamilyPanel
	// FamilyMail: SMTP, IMAP and POP3 authentication and abuse.
	FamilyMail
	// FamilySSH: SSH and PAM authentication.
	FamilySSH
	// FamilyFTP: FTP authentication.
	FamilyFTP
	// FamilyNetwork: local socket observations of connections.
	FamilyNetwork
	// FamilyReputation: external intel about a locally sighted address.
	FamilyReputation
	// FamilyDerived: local history, threat database rows, central intel,
	// incident wrappers and challenge timeouts. Never an independent root.
	FamilyDerived
	familyEnd
)

var familyNames = [...]string{"none", "http", "panel", "mail", "ssh", "ftp", "network", "reputation", "derived"}

func (f Family) Valid() bool { return f < familyEnd }

func (f Family) String() string {
	if f.Valid() {
		return familyNames[f]
	}
	return fmt.Sprintf("family(%d)", uint8(f))
}

// LocalAttack reports whether evidence of f is a local observation of the
// attack itself.
func (f Family) LocalAttack() bool {
	switch f {
	case FamilyHTTP, FamilyPanel, FamilyMail, FamilySSH, FamilyFTP, FamilyNetwork:
		return true
	}
	return false
}

// Independent reports whether evidence of f can corroborate a root of a
// different family.
func (f Family) Independent() bool { return f.LocalAttack() || f == FamilyReputation }

// Basis is the class a check's own evidence supports before corroboration.
type Basis uint8

const (
	BasisNone Basis = iota
	// BasisIntel supports C1.
	BasisIntel
	// BasisLocal supports C2: a local observation of attack activity.
	BasisLocal
	// BasisCompromise supports C3: direct compromise evidence. Only checks
	// on the reviewed compromise list may carry it.
	BasisCompromise
	basisEnd
)

var basisNames = [...]string{"none", "intel", "local", "compromise"}

func (b Basis) Valid() bool { return b < basisEnd }

func (b Basis) String() string {
	if b.Valid() {
		return basisNames[b]
	}
	return fmt.Sprintf("basis(%d)", uint8(b))
}

// Class returns the class b supports; BasisNone supports none.
func (b Basis) Class() (Class, bool) {
	switch b {
	case BasisIntel:
		return ClassC1, true
	case BasisLocal:
		return ClassC2, true
	case BasisCompromise:
		return ClassC3, true
	}
	return 0, false
}

// ValidPolicy reports whether a family and basis may appear together in a
// check's policy. Intel needs a reputation or derived family; local and
// compromise evidence must be a local attack observation.
func ValidPolicy(f Family, b Basis) error {
	if !f.Valid() || !b.Valid() {
		return fmt.Errorf("unknown family %d or basis %d", uint8(f), uint8(b))
	}
	switch {
	case f == FamilyNone && b == BasisNone:
		return nil
	case f == FamilyNone || b == BasisNone:
		return fmt.Errorf("family %s and basis %s must both be none or both be set", f, b)
	case b == BasisIntel && f != FamilyReputation && f != FamilyDerived:
		return fmt.Errorf("intel basis needs a reputation or derived family, not %s", f)
	case b != BasisIntel && !f.LocalAttack():
		return fmt.Errorf("%s basis needs a local attack family, not %s", b, f)
	}
	return nil
}

// Kind is the response a candidate asks for.
type Kind uint8

const (
	KindBlockIP Kind = iota + 1
	KindBlockService
	KindBlockSubnet
	KindPromote
	KindChallenge
	kindEnd
)

var kindNames = [...]string{"", "block_ip", "block_service", "block_subnet", "promote", "challenge"}

func (k Kind) Valid() bool { return k >= KindBlockIP && k < kindEnd }

func (k Kind) String() string {
	if k.Valid() {
		return kindNames[k]
	}
	return fmt.Sprintf("kind(%d)", uint8(k))
}

// Effect is the action family a kind belongs to. Fairness scopes are
// (owner, effect).
type Effect uint8

const (
	EffectAddress Effect = iota + 1
	EffectService
	EffectPrefix
	EffectChallenge
	effectEnd
)

var effectNames = [...]string{"", "address", "service", "prefix", "challenge"}

func (e Effect) Valid() bool { return e >= EffectAddress && e < effectEnd }

func (e Effect) String() string {
	if e.Valid() {
		return effectNames[e]
	}
	return fmt.Sprintf("effect(%d)", uint8(e))
}

// Effect returns the action family of k.
func (k Kind) Effect() Effect {
	switch k {
	case KindBlockIP, KindPromote:
		return EffectAddress
	case KindBlockService:
		return EffectService
	case KindBlockSubnet:
		return EffectPrefix
	case KindChallenge:
		return EffectChallenge
	}
	return 0
}

// Entry is the automatic path a candidate arrives on. The engine binds each
// entry to its registered producers.
type Entry uint8

const (
	EntryScan Entry = iota + 1
	EntryChallengeTimeout
	EntryIncident
	EntryIncidentSpray
	EntryCentral
	EntryNetblock
	EntryASNCrawl
	EntryMailSubnet
	EntryPermblock
	entryEnd
)

var entryNames = [...]string{"", "scan", "challenge_timeout", "incident", "incident_spray", "central", "netblock", "asn_crawl", "mail_subnet", "permblock"}

func (e Entry) Valid() bool { return e >= EntryScan && e < entryEnd }

func (e Entry) String() string {
	if e.Valid() {
		return entryNames[e]
	}
	return fmt.Sprintf("entry(%d)", uint8(e))
}

// Disposition is how a candidate ended or why it waits. The first four
// group the reasons a candidate did not receive its selected response; the
// rest are attempt and preview outcomes.
type Disposition uint8

const (
	DispositionDeferred Disposition = iota + 1
	DispositionRefused
	DispositionWithheld
	DispositionDropped
	// Outcomes of an attempt or a preview. Persisted: append, never renumber.
	DispositionApplied
	DispositionNarrowed
	DispositionDryRun
	DispositionObserve
	DispositionFailed
	DispositionUnknown
	dispositionEnd
)

var dispositionNames = [...]string{"", "deferred", "refused", "withheld", "dropped", "applied", "narrowed", "dry_run", "observe", "failed", "unknown"}

func (d Disposition) Valid() bool { return d >= DispositionDeferred && d < dispositionEnd }

func (d Disposition) String() string {
	if d.Valid() {
		return dispositionNames[d]
	}
	return fmt.Sprintf("disposition(%d)", uint8(d))
}

// Reason is a fixed, bounded explanation. It never carries attacker text.
type Reason uint8

const (
	ReasonCeiling Reason = iota + 1
	ReasonSetFull
	ReasonStorageShare
	ReasonEngineUnavailable
	ReasonPendingRecovery
	ReasonProtected
	ReasonAttribution
	ReasonInvalid
	ReasonPolicy
	ReasonStaleIdentity
	ReasonExistingEffect
	ReasonCollateral
	ReasonBreaker
	ReasonEnvelopeNoAlternative
	ReasonUnsupportedContainment
	ReasonQueueOverflow
	ReasonStale
	ReasonIngressInterruption
	reasonEnd
)

var reasonNames = [...]string{
	"", "ceiling", "set_full", "storage_share", "engine_unavailable",
	"pending_recovery", "protected", "attribution", "invalid", "policy",
	"stale_identity", "existing_effect", "collateral", "breaker",
	"envelope_no_alternative", "unsupported_containment", "queue_overflow",
	"stale", "ingress_interruption",
}

func (r Reason) Valid() bool { return r >= ReasonCeiling && r < reasonEnd }

func (r Reason) String() string {
	if r.Valid() {
		return reasonNames[r]
	}
	return fmt.Sprintf("reason(%d)", uint8(r))
}

// Disposition returns the group r belongs to.
func (r Reason) Disposition() Disposition {
	switch {
	case r >= ReasonCeiling && r <= ReasonPendingRecovery:
		return DispositionDeferred
	case r >= ReasonProtected && r <= ReasonExistingEffect:
		return DispositionRefused
	case r >= ReasonCollateral && r <= ReasonUnsupportedContainment:
		return DispositionWithheld
	case r >= ReasonQueueOverflow && r <= ReasonIngressInterruption:
		return DispositionDropped
	}
	return 0
}

// Error is an admission refusal. Detail is engine-generated text; it never
// quotes the input that was refused.
type Error struct {
	Reason Reason
	Detail string
}

func (e *Error) Error() string { return e.Reason.String() + ": " + e.Detail }

func refuse(r Reason, detail string) error { return &Error{Reason: r, Detail: detail} }

// ReasonOf returns the reason carried by err, if any.
func ReasonOf(err error) (Reason, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason, true
	}
	return 0, false
}
