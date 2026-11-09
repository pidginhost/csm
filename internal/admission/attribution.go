package admission

import (
	"errors"
	"fmt"
)

// Attribution is how a parser learned the address a finding names (spec
// 5.8). The parser that read the address sets it; a response path never
// does. Parked findings keep these numbers: append, never renumber.
type Attribution uint8

const (
	// AttributionUnknown is the zero value: no parser vouched for the
	// address. A parked finding without the optional kind decodes with
	// it. It never authorizes a new mint.
	AttributionUnknown Attribution = iota
	// AttributionPeer: the transport peer of an authenticated mail, SSH,
	// FTP or panel exchange, never an address in a message, mail header,
	// URL or username.
	AttributionPeer
	// AttributionHTTPPeer: the direct socket peer of an HTTP request.
	AttributionHTTPPeer
	// AttributionTrustedHTTPChain: the client a configured trusted proxy
	// forwarded, verified hop by hop. It is not a packet source.
	AttributionTrustedHTTPChain
	// AttributionSocketDestination: the remote end of a local outbound
	// connection. It is not an inbound source.
	AttributionSocketDestination
	// AttributionDerived: intel or history resting on retained roots.
	AttributionDerived
	attributionEnd
)

var attributionNames = [...]string{"unknown", "peer", "http_peer", "trusted_http_chain", "socket_destination", "derived"}

// Valid reports a known kind other than unknown.
func (a Attribution) Valid() bool { return a > AttributionUnknown && a < attributionEnd }

func (a Attribution) String() string {
	if a < attributionEnd {
		return attributionNames[a]
	}
	return fmt.Sprintf("attribution(%d)", uint8(a))
}

// AttributionSet is a set of attribution kinds: the kinds a check accepts,
// or the kinds a producer mints.
type AttributionSet uint8

// Attributions returns the set of kinds.
func Attributions(kinds ...Attribution) AttributionSet {
	var s AttributionSet
	for _, k := range kinds {
		s |= 1 << k
	}
	return s
}

// Has reports whether s holds the valid kind k.
func (s AttributionSet) Has(k Attribution) bool { return k.Valid() && s&(1<<k) != 0 }

// Valid reports whether s holds only valid kinds.
func (s AttributionSet) Valid() bool {
	return s&1 == 0 && s>>attributionEnd == 0
}

// Within reports whether every kind of s is in t.
func (s AttributionSet) Within(t AttributionSet) bool { return s&^t == 0 }

// Attributions returns the kinds an address of family f can be learned by.
func (f Family) Attributions() AttributionSet {
	switch f {
	case FamilyHTTP:
		return Attributions(AttributionHTTPPeer, AttributionTrustedHTTPChain)
	case FamilyPanel, FamilyMail, FamilySSH, FamilyFTP:
		return Attributions(AttributionPeer)
	case FamilyNetwork:
		return Attributions(AttributionSocketDestination)
	case FamilyReputation, FamilyDerived:
		return Attributions(AttributionDerived)
	}
	return 0
}

// Cause names why an attribution refusal was refused. Persisted in refusal
// summaries: append, never renumber.
type Cause uint8

const (
	// CauseNoObservation: the finding names no observation a producer
	// stamped.
	CauseNoObservation Cause = iota + 1
	// CauseKindNotAllowed: the producer did not declare the kind, or the
	// check does not accept it; unknown is never accepted.
	CauseKindNotAllowed
	// CauseTargetMismatch: the response names a target its evidence does
	// not attribute.
	CauseTargetMismatch
	causeEnd
)

var causeNames = [...]string{"", "no_observation", "kind_not_allowed", "target_mismatch"}

func (c Cause) Valid() bool { return c > 0 && c < causeEnd }

func (c Cause) String() string {
	if c.Valid() {
		return causeNames[c]
	}
	return fmt.Sprintf("cause(%d)", uint8(c))
}

// CauseOf returns the cause of an attribution refusal in err, or zero.
func CauseOf(err error) Cause {
	var e *Error
	if errors.As(err, &e) && e.Reason == ReasonAttribution {
		return e.Cause
	}
	return 0
}

func refuseAttribution(c Cause, detail string) error {
	return &Error{Reason: ReasonAttribution, Cause: c, Detail: detail}
}
