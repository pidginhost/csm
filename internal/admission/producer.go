package admission

import (
	"fmt"
	"slices"
	"sort"
	"sync"
)

// Policy is the admission projection of a check's response policy.
type Policy struct {
	Family Family
	Basis  Basis
	// MinSeverity is the lowest finding severity that counts as evidence for
	// the check; zero accepts every severity. It carries a Critical-only
	// rule, so an advisory finding of such a check never becomes a root.
	MinSeverity Severity
}

// PolicyLookup resolves a check name, including a renamed producer's old
// name, to its canonical registered name and policy. ok is false for an
// unregistered check. Registration, minting and validation share this lookup;
// checks.AdmissionPolicy projects the production check registry. Calls from
// separate operations can overlap, so the lookup must be immutable or safe
// for concurrent use.
type PolicyLookup func(check string) (canonical string, p Policy, ok bool)

// ProducerID names a registered evidence producer.
type ProducerID string

// ValidProducerID accepts 1-48 bytes of lowercase letters, digits and
// underscores, starting with a letter.
func ValidProducerID(id ProducerID) bool {
	if len(id) == 0 || len(id) > 48 || id[0] < 'a' || id[0] > 'z' {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}

// ObservationKind is how a producer identifies an observation.
type ObservationKind uint8

const (
	// ObservationLogCursor: a position in a log file or journal.
	ObservationLogCursor ObservationKind = iota + 1
	// ObservationEventSeq: a sequence number of kernel, socket or IPC
	// events.
	ObservationEventSeq
	// ObservationScanPass: one pass of a scan over server-owned state.
	ObservationScanPass
	observationEnd
)

func (k ObservationKind) Valid() bool { return k >= ObservationLogCursor && k < observationEnd }

// maxProducerChecks bounds one producer's check list.
const maxProducerChecks = 32

// ProducerSpec is what a producer registers. Checks are exact names; a
// dynamic prefix is never a catch-all. Claims are the ownership claim kinds
// the producer's findings may carry; Mint refuses any other.
type ProducerSpec struct {
	ID          ProducerID
	Entry       Entry
	Observation ObservationKind
	Checks      []string
	Claims      []ClaimKind
}

// Registry holds the producers allowed to mint evidence. Register all
// producers, then Seal; a sealed registry accepts none.
type Registry struct {
	mu        sync.Mutex
	lookup    PolicyLookup
	producers map[ProducerID]ProducerSpec
	sealed    bool
}

func NewRegistry(lookup PolicyLookup) (*Registry, error) {
	if lookup == nil {
		return nil, fmt.Errorf("registry needs a policy lookup")
	}
	return &Registry{lookup: lookup, producers: map[ProducerID]ProducerSpec{}}, nil
}

// Producer is the capability to mint evidence as one registered producer.
// Only Register creates one.
type Producer struct {
	reg *Registry
	id  ProducerID
}

func (p *Producer) ID() ProducerID { return p.id }

// Register validates spec and returns the producer's minting capability.
// Every check must be registered with an evidence family.
func (r *Registry) Register(spec ProducerSpec) (*Producer, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch {
	case r.sealed:
		return nil, fmt.Errorf("producer registered after the registry was sealed")
	case !ValidProducerID(spec.ID):
		return nil, fmt.Errorf("invalid producer ID")
	case !spec.Entry.Valid():
		return nil, fmt.Errorf("producer has an unknown entry")
	case !spec.Observation.Valid():
		return nil, fmt.Errorf("producer has an unknown observation kind")
	case len(spec.Checks) == 0 || len(spec.Checks) > maxProducerChecks:
		return nil, fmt.Errorf("producer must publish 1-%d checks", maxProducerChecks)
	}
	if _, dup := r.producers[spec.ID]; dup {
		return nil, fmt.Errorf("producer is already registered")
	}
	checks := make([]string, 0, len(spec.Checks))
	seen := map[string]bool{}
	for _, name := range spec.Checks {
		canonical, p, ok := r.lookup(name)
		if !ok || canonical != name {
			return nil, fmt.Errorf("producer check is not a canonical registered check")
		}
		if p.Family == FamilyNone {
			return nil, fmt.Errorf("producer check carries no admissible address evidence")
		}
		if err := ValidPolicy(p.Family, p.Basis); err != nil || (p.MinSeverity != 0 && !p.MinSeverity.Valid()) {
			return nil, fmt.Errorf("producer check has an invalid evidence policy")
		}
		if seen[name] {
			return nil, fmt.Errorf("producer check is repeated")
		}
		seen[name] = true
		checks = append(checks, name)
	}
	sort.Strings(checks)
	spec.Checks = checks
	claims := make([]ClaimKind, 0, len(spec.Claims))
	for _, kind := range spec.Claims {
		if !kind.Valid() {
			return nil, fmt.Errorf("producer declares an unknown claim kind")
		}
		if slices.Contains(claims, kind) {
			return nil, fmt.Errorf("producer claim kind is repeated")
		}
		claims = append(claims, kind)
	}
	slices.Sort(claims)
	spec.Claims = claims
	r.producers[spec.ID] = spec
	return &Producer{reg: r, id: spec.ID}, nil
}

// Seal stops further registration.
func (r *Registry) Seal() {
	r.mu.Lock()
	r.sealed = true
	r.mu.Unlock()
}

// Sealed reports whether registration has ended. The ledger accepts only a
// sealed registry, so the set of producers cannot change under it.
func (r *Registry) Sealed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sealed
}

// Spec returns a copy of a registered producer's spec.
func (r *Registry) Spec(id ProducerID) (ProducerSpec, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	spec, ok := r.producers[id]
	if ok {
		spec.Checks = append([]string(nil), spec.Checks...)
		spec.Claims = append([]ClaimKind(nil), spec.Claims...)
	}
	return spec, ok
}

func (spec ProducerSpec) publishes(check string) bool {
	i := sort.SearchStrings(spec.Checks, check)
	return i < len(spec.Checks) && spec.Checks[i] == check
}

// Validate refuses evidence whose producer, entry, check or policy no
// longer matches the registry, including a severity below the check's
// current floor. Admission calls it on every use, so a policy change takes
// effect on evidence minted before it.
func (r *Registry) Validate(e Evidence) error {
	spec, ok := r.Spec(e.rec.Producer)
	if !ok {
		return refuse(ReasonPolicy, "evidence producer is not registered")
	}
	if spec.Entry != e.rec.Entry || !spec.publishes(e.rec.Check) {
		return refuse(ReasonPolicy, "evidence entry or check is not registered for its producer")
	}
	canonical, p, ok := r.lookup(e.rec.Check)
	if !ok || canonical != e.rec.Check || p.Family != e.rec.Family || p.Basis != e.rec.Basis {
		return refuse(ReasonPolicy, "check policy changed since the evidence was minted")
	}
	if e.rec.Severity < p.MinSeverity {
		return refuse(ReasonPolicy, "finding severity is below the check's evidence floor")
	}
	return nil
}
