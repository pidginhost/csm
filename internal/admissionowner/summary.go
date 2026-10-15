package admissionowner

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
)

// Bounds of the dry-run summary (spec 3.8).
const (
	// summaryEvery is the least time from a summary's first prediction to
	// its delivery, and between two delivery attempts.
	summaryEvery = time.Minute
	// summaryExamples bounds the distinct examples one summary names.
	summaryExamples = 20
	// Shutdown bounds the final history attempt; normal delivery is
	// cancelled through the owner's context before its sender is joined.
	summaryStopTimeout = time.Second
)

type summaryResult struct {
	summary *dryRunSummary
	err     error
}

// summaryExample is one capacity admission a summary names.
type summaryExample struct {
	candidate     admission.CandidateID
	finding       string
	target, check string
}

// dryRunSummary counts the forecast's committed predictions between two
// deliveries. It is a fixed size: counts, at most summaryExamples examples
// in committed order and a session count.
type dryRunSummary struct {
	counts   [admission.PredictionSlots]uint64
	examples []summaryExample
	// sessions counts the sessions it covers, from first to last.
	sessions        int
	first, last     string
	start, end      time.Time
	firstPrediction time.Time
	// overflowed is set once a count could not grow, counted lost once.
	overflowed bool
}

// summaryState is the owner's side of the summary: the one pending summary,
// the one in delivery, and the delivery slot that keeps summaries to one a
// minute whatever the mode. Only the owner goroutine uses it; the sender
// holds an immutable copy while it delivers.
type summaryState struct {
	pending  *dryRunSummary
	inFlight bool
	// lastAttempt is the monotonic time of the last delivery attempt, a
	// failed one included; retry backs off failures.
	lastAttempt time.Time
	retry       retryBackoff
}

// noteSummary counts p's committed prediction, and names a capacity
// admission as an example while the summary has room.
func (o *Owner) noteSummary(p execPick, pred admission.Prediction, change *shadowChange) {
	s := o.summary.pending
	if s == nil {
		s = &dryRunSummary{start: time.Now().UTC(), firstPrediction: monoNow()}
		o.summary.pending = s
	}
	s.end = time.Now().UTC()
	if s.counts[pred] == ^uint64(0) {
		o.summaryOverflow(s)
	} else {
		s.counts[pred]++
	}
	if id := o.shadow.id; id != s.last {
		if s.sessions == 0 {
			s.first = id
		}
		s.sessions++
		s.last = id
	}
	if change != nil && len(s.examples) < summaryExamples && !s.names(change.ip) {
		s.examples = append(s.examples, summaryExample{candidate: p.pick.ID, finding: p.c.FindingID, target: change.ip, check: registeredCheck(p.c.Check)})
	}
}

// summaryOverflow counts one lost summary the first time a count of s
// cannot grow.
func (o *Owner) summaryOverflow(s *dryRunSummary) {
	if !s.overflowed {
		s.overflowed = true
		saturating(&o.out.summariesLost)
	}
}

func (s *dryRunSummary) names(target string) bool {
	for _, e := range s.examples {
		if e.target == target {
			return true
		}
	}
	return false
}

// summaryDue reports whether the pending summary may be delivered now: a
// minute after its first prediction and after the last attempt, once a
// failing delivery's backoff allows, and not while another is delivered.
func (o *Owner) summaryDue() bool {
	st := &o.summary
	now := monoNow()
	return st.pending != nil && !st.inFlight && st.retry.due(now) &&
		!now.Before(st.pending.firstPrediction.Add(summaryEvery)) &&
		(st.lastAttempt.IsZero() || !now.Before(st.lastAttempt.Add(summaryEvery)))
}

// takeSummary hands the sender the due summary. The owner keeps no
// reference to it: later predictions start the next one.
func (o *Owner) takeSummary() *dryRunSummary {
	if !o.summaryDue() {
		return nil
	}
	st := &o.summary
	s := st.pending
	st.pending, st.inFlight, st.lastAttempt = nil, true, monoNow()
	return s
}

// summaryDelivered settles a delivery attempt. A failed summary goes back
// in front of what accumulated meanwhile, as one summary.
func (o *Owner) summaryDelivered(s *dryRunSummary, err error) {
	st := &o.summary
	st.inFlight = false
	if err == nil {
		st.retry = retryBackoff{}
		return
	}
	st.retry.fail(monoNow(), defaultNoticeEvery)
	if later := st.pending; later != nil {
		o.mergeSummary(s, later)
	}
	st.pending = s
}

// mergeSummary adds later, which followed s, into s.
func (o *Owner) mergeSummary(s, later *dryRunSummary) {
	for p, n := range later.counts {
		if n > ^uint64(0)-s.counts[p] {
			o.summaryOverflow(s)
		}
		s.counts[p] += min(n, ^uint64(0)-s.counts[p])
	}
	for _, e := range later.examples {
		if len(s.examples) < summaryExamples && !s.names(e.target) {
			s.examples = append(s.examples, e)
		}
	}
	s.sessions += later.sessions
	if s.last == later.first {
		s.sessions--
	}
	s.last, s.end = later.last, later.end
}

// finishSummary settles the pending summary when the owner stops: one its
// minute allows is delivered, any other is counted discarded. Stop never
// sends a summary early. The caller runs this after joining the owner and
// sender, so delivery never occupies the owner goroutine.
func (o *Owner) finishSummary() {
	if o.summary.pending == nil {
		return
	}
	if o.summaryDue() && o.opts.DeliverSummary != nil {
		ctx, cancel := context.WithTimeout(context.Background(), summaryStopTimeout)
		defer cancel()
		if o.opts.DeliverSummary(ctx, summaryFinding(o.summary.pending, time.Now())) == nil {
			o.summary.pending = nil
			return
		}
	}
	o.summary.pending = nil
	saturating(&o.out.summariesLost)
}

// summaryFinding is the history record of s: the capacity admissions in
// its message, every other prediction, its interval, its session count and
// its examples as candidate/finding/target/check.
func summaryFinding(s *dryRunSummary, now time.Time) alert.Finding {
	var b strings.Builder
	fmt.Fprintf(&b, "start=%s end=%s sessions=%d", s.start.Format(time.RFC3339), s.end.Format(time.RFC3339), s.sessions)
	for p := admission.Prediction(1); p.Valid(); p++ {
		if p != admission.PredictCapacityAdmit {
			fmt.Fprintf(&b, " %s=%d", p, s.counts[p])
		}
	}
	if len(s.examples) > 0 {
		names := make([]string, len(s.examples))
		for i, e := range s.examples {
			names[i] = string(e.candidate) + "/" + e.finding + "/" + e.target + "/" + e.check
		}
		b.WriteString(" examples=" + strings.Join(names, ","))
	}
	return alert.Finding{
		Check: "auto_block", Severity: alert.Warning, Details: b.String(), Timestamp: now,
		Message: fmt.Sprintf("Dry-run capacity forecast: %d responses passed modelled capacity checks", s.counts[admission.PredictCapacityAdmit]),
	}
}

// sendSummary delivers a due dry-run summary to history only, through the
// independent path, never to an alert channel. A summary waiting for its
// delivery counts in the notice queue, so a failing delivery shows there.
func (s *sender) sendSummary() {
	if s.o.opts.DeliverSummary == nil {
		return
	}
	var due *dryRunSummary
	if s.o.do(func() error {
		due = s.o.takeSummary()
		s.summaryWaiting = s.o.summary.pending != nil || due != nil
		return nil
	}) != nil || due == nil {
		s.observe()
		return
	}
	s.observe()
	err := s.o.opts.DeliverSummary(s.o.summaryCtx, summaryFinding(due, time.Now()))
	if err == nil {
		s.delivered++
	}
	if ackErr := s.o.do(func() error {
		s.o.summaryDelivered(due, err)
		s.summaryWaiting = s.o.summary.pending != nil
		return nil
	}); ackErr != nil {
		s.o.summaryResult <- summaryResult{summary: due, err: err}
	}
	s.observe()
}
