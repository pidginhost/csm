package checks

import (
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/metrics"
)

// ResponseAdmission is the admission owner as the response funnels see it.
// Every automatic response the legacy funnels select is also handed to it,
// where it is previewed, or forecast in dry run, but never executed; the
// legacy path keeps every enforcement decision and never waits for
// admission.
type ResponseAdmission interface {
	// Mint mints the evidence f's own observation supports, aimed at the
	// address its parser read. It counts nothing.
	Mint(f alert.Finding) (admission.Evidence, error)
	// Refuse counts a response that could not be answered because f could
	// not be minted.
	Refuse(kind admission.Kind, f alert.Finding, via admission.Entry, err error)
	// Respond hands the ingress a response of kind to target, the address
	// or prefix the legacy path acts on, with e as its root, through the
	// derived entry via when it is set. Admission refuses a target that is
	// not e's address and does not contain it.
	Respond(kind admission.Kind, target string, e admission.Evidence, via admission.Entry, ttl ...time.Duration) error
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

var (
	handoffSeconds     *metrics.Histogram
	handoffSecondsOnce sync.Once
)

// timeHandoff records how long a funnel waited on admission since start.
// The comparison reads the 10 ms bucket for its p99 criterion (R11).
func timeHandoff(start time.Time) {
	handoffSecondsOnce.Do(func() {
		handoffSeconds = metrics.NewHistogram("csm_admission_handoff_seconds",
			"Time a response funnel waits to hand an automatic response to admission.",
			[]float64{.001, .0025, .005, .01, .025, .1, 1})
		metrics.MustRegister("csm_admission_handoff_seconds", handoffSeconds)
	})
	handoffSeconds.Observe(time.Since(start).Seconds())
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
	defer timeHandoff(time.Now())
	e, err := a.Mint(f)
	if err != nil {
		a.Refuse(kind, f, via, err)
		return admission.Evidence{}
	}
	_ = a.Respond(kind, target, e, via)
	return e
}

// respondSpray asks admission to block a spray's prefix through the mail
// subnet entry, with each counted address as a root, read as its tracker
// recorded it, newest first, at most as many as one candidate holds. A
// spray recorded without its constituents names no address of its own.
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
		root.SourceIP = c.Address
		root.Observation, root.Attribution = c.Observation, c.Attribution
		respond(admission.KindBlockSubnet, root, cidr, admission.EntryMailSubnet)
	}
}

// respondDerived hands admission the block a derived path applies, with the
// root it carries, through its entry. A permanent block is never asked for
// implicitly (spec 5.10): it is handed over without a root, as a path that
// kept none is, and admission refuses it.
func respondDerived(req ApplyBlockRequest) {
	if req.TTL == 0 {
		AnswerRoot(admission.KindBlockIP, req.IP, admission.Evidence{}, req.Entry)
		return
	}
	AnswerPreparedRoot(admission.KindBlockIP, req.IP, req.Root, req.Entry, req.RootFinding, req.RootErr, req.TTL)
}

// AdmissionRoot keeps a root for a derived path whose retained finding
// may no longer be available when it responds. Failure leaves no root.
func AdmissionRoot(f alert.Finding) admission.Evidence {
	e, _ := PrepareAdmissionRoot(f)
	return e
}

// PrepareAdmissionRoot preserves a local finding's mint refusal so a
// selected response can count it once with its original check and reason.
func PrepareAdmissionRoot(f alert.Finding) (admission.Evidence, error) {
	a := getResponseAdmission()
	if a == nil {
		return admission.Evidence{}, nil
	}
	return a.Mint(f)
}

// AnswerPreparedRoot counts a failed mint once, without replacing its
// provenance refusal with a second rootless-response refusal.
func AnswerPreparedRoot(kind admission.Kind, target string, root admission.Evidence, via admission.Entry, f alert.Finding, err error, ttl time.Duration) {
	if err != nil {
		if a := getResponseAdmission(); a != nil {
			defer timeHandoff(time.Now())
			a.Refuse(kind, f, via, err)
		}
		return
	}
	AnswerRoot(kind, target, root, via, ttl)
}

// AnswerRoot hands admission a response of kind to target a derived path
// decided, with the root it kept, through its entry.
func AnswerRoot(kind admission.Kind, target string, root admission.Evidence, via admission.Entry, ttl ...time.Duration) {
	if a := getResponseAdmission(); a != nil {
		defer timeHandoff(time.Now())
		_ = a.Respond(kind, target, root, via, ttl...)
	}
}

// respondNetblock hands admission a netblock escalation. It rests on past
// blocks rather than a root admission could answer, so admission refuses
// it until range corroboration exists.
func respondNetblock() {
	if a := getResponseAdmission(); a != nil {
		defer timeHandoff(time.Now())
		_ = a.Respond(admission.KindBlockSubnet, "", admission.Evidence{}, admission.EntryNetblock)
	}
}
