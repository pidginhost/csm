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
	"github.com/pidginhost/csm/internal/platform"
)

// ResponseAdmission is the admission owner as the response funnels see it.
// Every automatic response the legacy funnels select is also handed to it,
// where it is previewed, forecast in dry run, or, for a block admission
// applies, executed instead of the legacy block. The funnels never wait for
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
	// ExecutesBlocks reports whether admission applies the block picks it
	// takes, so legacy must leave them alone.
	ExecutesBlocks() bool
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
// The comparison reads the 10 ms bucket for its p99 criterion.
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
// f names, through via when it is set, and returns whether legacy must
// leave the block to admission and whether admission accepted it to apply.
func respond(kind admission.Kind, f alert.Finding, target string, via admission.Entry) (bool, bool) {
	a := getResponseAdmission()
	if a == nil {
		return false, false
	}
	executes := a.ExecutesBlocks()
	// Spray lifetime and budget stay with legacy. Use the handoff's owner
	// and execution snapshot so a concurrent publication cannot take it.
	if kind == admission.KindBlockIP && f.BlockTTL > 0 && executes {
		return false, false
	}
	e, err := a.Mint(f)
	// Building evidence, including a web peer verdict's wait for the peer
	// log, takes no admission lock and is not the handoff.
	defer timeHandoff(time.Now())
	if err != nil {
		a.Refuse(kind, f, via, err)
		return taken(executes, kind, err, nil), false
	}
	err = a.Respond(kind, target, e, via)
	accepted := err == nil && executes && kind == admission.KindBlockIP
	return taken(executes, kind, nil, err), accepted
}

// taken reports whether legacy must leave a response of kind to admission.
// While admission applies block picks its answer is final: a block it
// accepted is its own to apply, and one it refused is applied by neither
// path. Two answers leave the block to legacy: an address Apache or nginx
// may have rewritten from a proxy header, which this build cannot verify
// yet, and an error that is not an admission answer or a closed ingress,
// where admission could not answer at all. A rewritten address anyone can
// choose is refused for good: see forgeableRewrite.
func taken(executes bool, kind admission.Kind, mintErr, respondErr error) bool {
	if !executes || kind != admission.KindBlockIP {
		return false
	}
	err := mintErr
	if err == nil {
		err = respondErr
	}
	if err == nil {
		return true
	}
	if admission.CauseOf(err) == admission.CauseRewrittenLog {
		return forgeableRewrite(err)
	}
	reason, answered := admission.ReasonOf(err)
	return answered && reason != admission.ReasonEngineUnavailable
}

// forgeableRewrite reports whether err refuses a rewritten address someone
// other than the sender can choose: LiteSpeed applies forwarding headers to
// requests from the host itself, so any local user chooses it, and a log
// format that writes request data where CSM reads the client lets any
// client choose it. nginx PROXY protocol also lets customer code on shared
// edges choose an address unless its configured sources were verified.
func forgeableRewrite(err error) bool {
	// Where the daemon reads and trusts the web peer log, an address it
	// cannot verify is refused for good (operator ruling 2026-11-21).
	return admission.CauseOf(err) == admission.CauseRewrittenLog && (rewrittenRefusalFinal(CurrentHTTPRewrite()) || WebPeerLogActive())
}

// rewrittenRefusalFinal reports a rewrite any local process or edge customer
// can drive, whose rewritten_log refusal the legacy path must not override.
func rewrittenRefusalFinal(r HTTPRewrite) bool {
	return r.Server == platform.WSLiteSpeed || r.Format || r.NginxProxyProtocol()
}

// writableSpray rejects summaries that depend on any writable log line,
// including a mixed-source spray whose latest observation was trusted.
func writableSpray(f alert.Finding) bool {
	if ProducerWritableLog(admission.ProducerID(f.Observation.Producer)) {
		return true
	}
	for _, c := range f.SprayConstituents {
		if ProducerWritableLog(admission.ProducerID(c.Observation.Producer)) {
			return true
		}
	}
	return false
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
// root it carries, through its entry, and reports whether legacy must leave
// it to admission. A permanent block is never asked for implicitly: it is
// handed over without a root, as a path that kept none is, and it stays
// with legacy until admission can apply one. A block asked to last longer
// than lease, which admission would cut to lease, keeps its legacy block
// while admission executes; a previewing admission still sees it. It still
// never blocks a CDN edge, an unreachable client or an address someone else
// can choose, whatever the lifetime, permanent incident escalation included.
func respondDerived(req ApplyBlockRequest, lease time.Duration) bool {
	a := getResponseAdmission()
	if a == nil {
		return false
	}
	defer timeHandoff(time.Now())
	executes := a.ExecutesBlocks()
	// Incident retries can escalate to a permanent lifetime. That must not
	// discard a refusal of an address someone else can choose.
	if c := admission.CauseOf(req.RootErr); executes && (c == admission.CauseForgedClient || c == admission.CauseWritableLog || forgeableRewrite(req.RootErr)) {
		a.Refuse(admission.KindBlockIP, req.RootFinding, req.Entry, req.RootErr)
		return true
	}
	if req.TTL == 0 {
		answerRoot(a, executes, admission.KindBlockIP, req.IP, admission.Evidence{}, req.Entry)
		return false
	}
	if executes && lease > 0 && req.TTL > lease {
		// These legacy-only lifetimes retain their safety refusals, without
		// submitting a block that admission would shorten.
		if c := admission.CauseOf(req.RootErr); c == admission.CauseProxyPeer || c == admission.CauseUnreachable {
			a.Refuse(admission.KindBlockIP, req.RootFinding, req.Entry, req.RootErr)
			return true
		}
		return false
	}
	return answerPreparedRoot(a, executes, admission.KindBlockIP, req.IP, req.Root, req.Entry, req.RootFinding, req.RootErr, req.TTL)
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
	// Derived paths must retain this refusal even while no owner is wired.
	if ProducerWritableLog(admission.ProducerID(f.Observation.Producer)) {
		_, _, err := AdmissionEvidence(f)
		return admission.Evidence{}, err
	}
	a := getResponseAdmission()
	if a == nil {
		return admission.Evidence{}, nil
	}
	return a.Mint(f)
}

// AnswerPreparedRoot counts a failed mint once, without replacing its
// provenance refusal with a second rootless-response refusal. It reports
// whether legacy must leave the response to admission.
func AnswerPreparedRoot(kind admission.Kind, target string, root admission.Evidence, via admission.Entry, f alert.Finding, err error, ttl time.Duration) bool {
	a := getResponseAdmission()
	if a == nil {
		return false
	}
	defer timeHandoff(time.Now())
	return answerPreparedRoot(a, a.ExecutesBlocks(), kind, target, root, via, f, err, ttl)
}

// AnswerRoot hands admission a response of kind to target a derived path
// decided, with the root it kept, through its entry, and reports whether
// legacy must leave it to admission.
func AnswerRoot(kind admission.Kind, target string, root admission.Evidence, via admission.Entry, ttl ...time.Duration) bool {
	a := getResponseAdmission()
	if a == nil {
		return false
	}
	defer timeHandoff(time.Now())
	return answerRoot(a, a.ExecutesBlocks(), kind, target, root, via, ttl...)
}

// answerPreparedRoot and answerRoot answer with the caller's reading of
// whether a executes blocks, so one hand-off decides on one reading.
func answerPreparedRoot(a ResponseAdmission, executes bool, kind admission.Kind, target string, root admission.Evidence, via admission.Entry, f alert.Finding, err error, ttl time.Duration) bool {
	if err != nil {
		a.Refuse(kind, f, via, err)
		return taken(executes, kind, err, nil)
	}
	return answerRoot(a, executes, kind, target, root, via, ttl)
}

func answerRoot(a ResponseAdmission, executes bool, kind admission.Kind, target string, root admission.Evidence, via admission.Entry, ttl ...time.Duration) bool {
	return taken(executes, kind, nil, a.Respond(kind, target, root, via, ttl...))
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
