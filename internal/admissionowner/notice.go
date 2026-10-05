package admissionowner

import (
	"fmt"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/queuehealth"
	"github.com/pidginhost/csm/internal/store"
)

// ackNotices acknowledges delivered notices; tests make it fail.
var ackNotices = (*store.AdmissionLedger).AckNotices

// maxNoticeRetryWait caps the wait between attempts of a failing delivery.
const maxNoticeRetryWait = time.Hour

// noticeMessages name each notice kind as its notification does.
var noticeMessages = map[admission.NoticeKind]string{
	admission.NoticeWithheld:        "Critical automatic response withheld",
	admission.NoticeWithheldWarning: "Compromise response withheld",
	admission.NoticeCapacity:        "Automatic response capacity exhausted",
	admission.NoticeCriticalSummary: "Critical automatic response gaps summary",
	admission.NoticeAppliedSummary:  "Automatic responses applied summary",
}

// sender delivers the ledger's due notices, and the notice of a stopped
// ingress, through the daemon's independent health path. It runs on its
// own goroutine, since delivery may wait on mail or a webhook, and alone
// serializes reading, delivery and acknowledgement; the owner goroutine
// makes the acknowledgement (handoffs O50-O52).
type sender struct {
	o     *Owner
	queue *queuehealth.Sampled
	// unacked holds a delivery whose acknowledgement failed: it is
	// acknowledged before another ledger notice batch, never delivered
	// again. The independent stopped-ingress notice still runs.
	unacked   []admission.NoticeAck
	delivered uint64
	// announced is set once the current stop of the ingress was sent.
	announced      bool
	announcedSince time.Time
	// A failed stop notification must survive recovery until delivery.
	pendingStop   *alert.Finding
	pendingSince  time.Time
	ledgerPending int
	// failures counts consecutive failed deliveries; retryAt is when the
	// next attempt is due.
	failures int
	retryAt  time.Time
	done     chan struct{}
}

func (s *sender) run() {
	defer close(s.done)
	t := time.NewTicker(s.o.opts.NoticeEvery)
	defer t.Stop()
	for {
		select {
		case <-s.o.done:
			return
		case <-t.C:
			s.cycle()
		}
	}
}

func (s *sender) cycle() {
	if s.o.opts.Deliver == nil || s.o.stopping.Load() {
		return
	}
	s.announceStop()
	if len(s.unacked) > 0 {
		if err := s.o.do(func() error { return ackNotices(s.o.ledger, s.unacked) }); err != nil {
			return
		}
		s.unacked = nil
		s.ledgerPending = 0
		s.observe()
	}
	var l *store.AdmissionLedger
	if s.o.do(func() error { l = s.o.ledger; return nil }) != nil || l == nil {
		return
	}
	due, err := l.PendingNotices()
	if err != nil {
		return
	}
	s.ledgerPending = len(due)
	s.observe()
	if len(due) == 0 {
		return
	}
	now := time.Now()
	findings := make([]alert.Finding, len(due))
	acks := make([]admission.NoticeAck, len(due))
	for i, r := range due {
		findings[i] = noticeFinding(r, now)
		acks[i] = admission.NoticeAck{Key: r.Key, First: r.First, Count: r.Count}
	}
	if !s.deliver(findings) {
		return
	}
	s.delivered += uint64(len(due))
	s.unacked = acks
	s.observe()
	if err = s.o.do(func() error { return ackNotices(l, acks) }); err != nil {
		return
	}
	s.unacked = nil
	s.ledgerPending = 0
	s.observe()
}

func (s *sender) observe() {
	depth := s.ledgerPending
	if s.pendingStop != nil {
		depth++
	}
	s.queue.Observe(deliveryNow(), depth, s.delivered)
}

// announceStop sends one Critical notice when the ingress stops admitting,
// naming the cause the owner recorded (ruling 8, O52). The ledger may be
// the damaged part, so nothing here writes it.
func (s *sender) announceStop() bool {
	if s.pendingStop != nil && s.sendStop() {
		return true
	}
	h := admission.IngressHealth{}
	cause := "the owner has not started"
	// Read stop state and its cause together: a recovery between them
	// must not report a healthy ingress as stopped.
	if err := s.o.do(func() error {
		if s.o.ingress != nil {
			h = s.o.ingress.Health()
		}
		for _, err := range []error{s.o.startErr, s.o.tickErr, s.o.snapshotErr} {
			if err != nil {
				cause = err.Error()
				break
			}
		}
		return nil
	}); err != nil || s.o.stopping.Load() {
		return false
	}
	if h.Admitting {
		s.announced = false
		return false
	}
	if s.announced && s.announcedSince.Equal(h.StoppedSince) {
		return false
	}
	s.pendingStop = &alert.Finding{
		Check: "auto_response_withheld", Severity: alert.Critical, Message: "Automatic response admission stopped",
		Details:   fmt.Sprintf("since=%s critical_refused=%d cause=%s", h.StoppedSince.UTC().Format(time.RFC3339), h.CriticalRefused, cause),
		Timestamp: time.Now(),
	}
	s.pendingSince = h.StoppedSince
	return s.sendStop()
}

func (s *sender) sendStop() bool {
	s.observe()
	if !s.deliver([]alert.Finding{*s.pendingStop}) {
		return true
	}
	s.announced, s.announcedSince = true, s.pendingSince
	s.pendingStop = nil
	s.delivered++
	s.observe()
	return false
}

// deliver sends findings unless the retry of a failing delivery is not yet
// due. Every attempt reaches every channel and history, those that accepted
// the last attempt included, so a failing one is not retried each cycle:
// the next two cycles retry at once, then each attempt waits twice as long
// as the one before, up to an hour. A delivery restores prompt retries.
func (s *sender) deliver(findings []alert.Finding) bool {
	if s.o.stopping.Load() || deliveryNow().Before(s.retryAt) {
		return false
	}
	if err := s.o.opts.Deliver(findings); err != nil {
		s.failures++
		if s.failures > 2 {
			s.retryAt = deliveryNow().Add(min(defaultNoticeEvery<<min(s.failures-2, 20), maxNoticeRetryWait))
		}
		return false
	}
	s.failures, s.retryAt = 0, time.Time{}
	return true
}

// noticeFinding is the notification of one notice record: its registered
// check and severity, and in its details the events no delivery covered,
// their key and their example candidates.
func noticeFinding(r admission.NoticeRecord, now time.Time) alert.Finding {
	var b strings.Builder
	fmt.Fprintf(&b, "events=%d first=%s last=%s", r.Unsent(), r.First.UTC().Format(time.RFC3339), r.Last.UTC().Format(time.RFC3339))
	if r.Key.Kind.Keyed() && r.Key.Fixed() {
		b.WriteString(" overflow=true")
	}
	if r.Key.Reason != 0 {
		b.WriteString(" reason=" + r.Key.Reason.String())
	}
	if r.Key.Outcome != 0 {
		b.WriteString(" outcome=" + r.Key.Outcome.String())
	}
	if r.Key.Check != "" {
		b.WriteString(" check=" + r.Key.Check)
	}
	if r.Key.Effect != 0 {
		b.WriteString(" effect=" + r.Key.Effect.String())
	}
	if len(r.Examples) > 0 {
		ids := make([]string, len(r.Examples))
		for i, e := range r.Examples {
			ids[i] = string(e.Candidate)
		}
		b.WriteString(" examples=" + strings.Join(ids, ","))
	}
	sev := alert.Warning
	if r.Key.Kind.Severity() == admission.SeverityCritical {
		sev = alert.Critical
	}
	return alert.Finding{Check: r.Key.Kind.Check(), Severity: sev, Message: noticeMessages[r.Key.Kind], Details: b.String(), Timestamp: now}
}
