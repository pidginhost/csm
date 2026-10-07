package checks

import (
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
)

// ResponseAdmission is the admission owner as the response funnels see it.
// Every automatic response the legacy funnels select is also handed to it,
// where it is admitted and previewed but never executed; the legacy path
// keeps every enforcement decision and never waits for admission.
type ResponseAdmission interface {
	// Mint mints the evidence f's own observation supports for target. It
	// counts nothing.
	Mint(f alert.Finding, target string) (admission.Evidence, error)
	// Refuse counts a response that could not be answered because f could
	// not be minted.
	Refuse(kind admission.Kind, f alert.Finding, via admission.Entry, err error)
	// Respond hands a response of kind to e's target to the ingress,
	// through the derived entry via when it is set.
	Respond(kind admission.Kind, e admission.Evidence, via admission.Entry, ttl ...time.Duration) error
}

type responseAdmissionSlot struct{ a ResponseAdmission }

var responseAdmissionHolder atomic.Pointer[responseAdmissionSlot]

// SetResponseAdmission wires the admission owner; nil unwires it.
func SetResponseAdmission(a ResponseAdmission) {
	responseAdmissionHolder.Store(&responseAdmissionSlot{a: a})
}

func getResponseAdmission() ResponseAdmission {
	if slot := responseAdmissionHolder.Load(); slot != nil {
		return slot.a
	}
	return nil
}

// respond asks admission for a response of kind to the address or prefix
// f names, through via when it is set, and returns the minted evidence for
// a derived response to answer later. Its outcome never changes the
// legacy response.
func respond(kind admission.Kind, f alert.Finding, target string, via admission.Entry) admission.Evidence {
	a := getResponseAdmission()
	if a == nil {
		return admission.Evidence{}
	}
	e, err := a.Mint(f, target)
	if err != nil {
		a.Refuse(kind, f, via, err)
		return admission.Evidence{}
	}
	_ = a.Respond(kind, e, via)
	return e
}

// respondSpray asks admission to block a spray's prefix through the mail
// subnet entry, with each counted address's observation as a root, newest
// first, at most as many as one candidate holds. A spray recorded without
// its constituents answers its own observation.
func respondSpray(f alert.Finding, cidr string) {
	if len(f.SprayConstituents) == 0 {
		respond(admission.KindBlockSubnet, f, cidr, admission.EntryMailSubnet)
		return
	}
	constituents := slices.Clone(f.SprayConstituents)
	slices.SortFunc(constituents, func(a, b alert.SprayConstituent) int {
		if c := b.LastSeen.Compare(a.LastSeen); c != 0 {
			return c
		}
		return strings.Compare(a.Address, b.Address)
	})
	for _, c := range constituents[:min(len(constituents), admission.MaxRoots)] {
		root := f
		root.Observation = c.Observation
		respond(admission.KindBlockSubnet, root, cidr, admission.EntryMailSubnet)
	}
}

// respondNetblock hands admission a netblock escalation. It rests on past
// blocks rather than a root admission could answer, so admission refuses
// it until range corroboration exists.
func respondNetblock() {
	if a := getResponseAdmission(); a != nil {
		_ = a.Respond(admission.KindBlockSubnet, admission.Evidence{}, admission.EntryNetblock)
	}
}
