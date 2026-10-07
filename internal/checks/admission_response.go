package checks

import (
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
