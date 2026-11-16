package admissionowner

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/queuehealth"
	"github.com/pidginhost/csm/internal/store"
)

// ackNotices acknowledges delivered notices; tests make it fail.
var ackNotices = (*store.AdmissionLedger).AckNotices

// maxRetryWait caps the wait between attempts of failing work.
const maxRetryWait = time.Hour

// noticeMessages name each notice kind as its notification does.
var noticeMessages = map[admission.NoticeKind]string{
	admission.NoticeWithheld:        "Critical automatic response withheld",
	admission.NoticeWithheldWarning: "Compromise response withheld",
	admission.NoticeCapacity:        "Automatic response capacity exhausted",
	admission.NoticeCriticalSummary: "Critical automatic response gaps summary",
	admission.NoticeAppliedSummary:  admission.AppliedSummaryMessage,
}

// sender delivers the ledger's due notices, and the notice of a stopped
// ingress, through the daemon's independent health path. It runs on its
// own goroutine, since delivery may wait on mail or a webhook, and alone
// serializes reading, delivery and acknowledgement; the owner goroutine
// makes the acknowledgement.
type sender struct {
	o     *Owner
	queue *queuehealth.Sampled
	// unacked holds a delivery whose acknowledgement failed: it is
	// acknowledged before another ledger notice batch, never delivered
	// again. The independent stopped-ingress notice still runs.
	unacked        []admission.NoticeAck
	unackedStarted bool
	// unackedRead is the admission time the unacknowledged delivery was
	// read at; ackedRead keeps it per key once acknowledged. Events after
	// that read were not delivered, though they may predate the
	// acknowledgement.
	unackedRead time.Time
	ackedRead   map[admission.NoticeKey]time.Time
	delivered   uint64
	// announced is set once the current stop of the ingress was sent.
	announced      bool
	announcedSince time.Time
	// A failed stop notification must survive recovery until delivery.
	pendingStop   *alert.Finding
	pendingSince  time.Time
	ledgerPending int
	// summaryWaiting is set while a dry-run summary waits for delivery.
	summaryWaiting bool
	// The independent stop alert must not inherit a ledger delivery's wait,
	// and its successful delivery must not reset that ledger retry.
	ledgerRetry retryBackoff
	// ledgerStarted binds the retry delay to the notice stream: clearing
	// preview records at live start also discards their delivery failures.
	ledgerStarted bool
	stopRetry     retryBackoff
	done          chan struct{}
}

// retryBackoff spaces the attempts of work that keeps failing: the next
// two attempts run at once, then each waits twice as long as the one before,
// from base up to ceiling. A success restores prompt attempts.
type retryBackoff struct {
	failures int
	at       time.Time
}

func (r *retryBackoff) due(now time.Time) bool { return !now.Before(r.at) }

func (r *retryBackoff) fail(now time.Time, base, ceiling time.Duration) {
	r.failures++
	if r.failures > 2 {
		r.at = now.Add(min(base<<min(r.failures-2, 20), ceiling))
	}
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
	if s.o.stopping.Load() {
		return
	}
	if s.o.opts.Deliver != nil {
		s.announceStop()
	}
	s.sendSummary()
	if s.o.opts.Deliver == nil {
		return
	}
	if len(s.unacked) > 0 {
		if err := s.o.do(func() error { return ackNoticeSnapshot(s.o.ledger, s.unackedStarted, s.unacked) }); err != nil {
			return
		}
		s.noteAcked()
		s.ledgerPending = 0
		s.observe()
	}
	var l *store.AdmissionLedger
	var live, started bool
	var due []admission.NoticeRecord
	var spans []liveSpan
	var read time.Time
	err := s.o.do(func() error {
		l, live, read = s.o.ledger, s.o.executing(), s.o.now
		if l == nil {
			return nil
		}
		if !liveExecution {
			return nil
		}
		s.o.noteMode()
		spans = slices.Clone(s.o.liveSpans)
		started = l.LiveStarted()
		// The payload and its mode belong to the same owner boundary.
		if live && !started {
			return nil
		}
		var readErr error
		due, readErr = l.PendingNotices()
		return readErr
	})
	if err != nil || l == nil {
		return
	}
	if !liveExecution {
		due, err = l.PendingNotices()
	}
	if err != nil {
		return
	}
	if started != s.ledgerStarted {
		s.ledgerRetry = retryBackoff{}
		s.ledgerStarted = started
	}
	s.ledgerPending = len(due)
	s.observe()
	if len(due) == 0 {
		return
	}
	// Each record goes out in the mode it was raised in: live records
	// first, then previews. A failed delivery leaves its group and those
	// after it due.
	now := time.Now()
	var acks []admission.NoticeAck
	for _, preview := range []bool{false, true} {
		var findings []alert.Finding
		var group []admission.NoticeAck
		for _, r := range due {
			if (liveExecution && raisedLive(r, spans, s.ackedRead[r.Key])) == preview {
				continue
			}
			findings = append(findings, noticeFinding(r, now, !preview))
			group = append(group, admission.NoticeAck{Key: r.Key, First: r.First, Count: r.Count})
		}
		if len(findings) == 0 {
			continue
		}
		if !s.deliver(&s.ledgerRetry, findings, preview) {
			break
		}
		acks = append(acks, group...)
	}
	if len(acks) == 0 {
		return
	}
	s.delivered += uint64(len(acks))
	s.unacked, s.unackedStarted, s.unackedRead = acks, started, read
	s.observe()
	if err = s.o.do(func() error { return ackNoticeSnapshot(l, started, acks) }); err != nil {
		return
	}
	s.noteAcked()
	s.ledgerPending = len(due) - len(acks)
	s.observe()
}

// noteAcked ends the unacknowledged delivery, keeping when each of its
// keys was read.
func (s *sender) noteAcked() {
	if s.ackedRead == nil {
		s.ackedRead = make(map[admission.NoticeKey]time.Time)
	}
	for _, a := range s.unacked {
		s.ackedRead[a.Key] = s.unackedRead
	}
	s.unacked = nil
}

func (s *sender) observe() {
	depth := s.ledgerPending
	if s.pendingStop != nil {
		depth++
	}
	if s.summaryWaiting {
		depth++
	}
	s.queue.Observe(deliveryNow(), depth, s.delivered)
}

// announceStop sends one notice when the ingress stops admitting, naming
// the cause the owner recorded. The ledger may be the
// damaged part, so nothing here writes it. It warns while legacy blocking
// enforces and admission previews; while the owner executes, a stop
// stops automatic blocking and the notice is Critical.
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
		for _, err := range []error{s.o.startErr, s.o.drainErr, s.o.tickErr, s.o.snapshotErr} {
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
		Check: "auto_response_withheld", Severity: alert.Warning, Message: "Automatic response admission preview stopped; existing blocking is unaffected",
		Details:   fmt.Sprintf("since=%s critical_refused=%d cause=%s", h.StoppedSince.UTC().Format(time.RFC3339), h.CriticalRefused, cause),
		Timestamp: time.Now(),
	}
	s.pendingSince = h.StoppedSince
	return s.sendStop()
}

func (s *sender) sendStop() bool {
	var live bool
	if err := s.o.do(func() error { live = s.o.executing(); return nil }); err != nil {
		return true
	}
	// A pending delivery can outlive a policy change. Keep its identity
	// and details, but describe the mode in which it is sent.
	s.pendingStop.Severity = alert.Warning
	s.pendingStop.Message = "Automatic response admission preview stopped; existing blocking is unaffected"
	if live {
		s.pendingStop.Severity = alert.Critical
		s.pendingStop.Message = "Automatic response admission stopped; automatic blocks are not applied"
	}
	s.observe()
	if !s.deliver(&s.stopRetry, []alert.Finding{*s.pendingStop}, false) {
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
// the last attempt included, so a failing one is backed off from the
// default notice period. A delivery restores prompt retries for its path.
func (s *sender) deliver(retry *retryBackoff, findings []alert.Finding, preview bool) bool {
	if s.o.stopping.Load() || !retry.due(deliveryNow()) {
		return false
	}
	if err := s.o.opts.Deliver(findings, preview); err != nil {
		retry.fail(deliveryNow(), defaultNoticeEvery, maxRetryWait)
		return false
	}
	*retry = retryBackoff{}
	return true
}

// liveSpan is an admission time interval in which this process executed
// block picks; a zero until is still open.
type liveSpan struct{ since, until time.Time }

// noteMode opens or closes the live span at the owner's admission time
// when executing() changed. Records older than the process take the mode
// it started in. A span boundary shares its time with the events beside
// it, so an event at a flip counts as live.
func (o *Owner) noteMode() {
	open := len(o.liveSpans) > 0 && o.liveSpans[len(o.liveSpans)-1].until.IsZero()
	switch live := o.executing(); {
	case live && !open:
		since := o.now
		if !o.modeNoted {
			since = time.Time{}
		}
		o.liveSpans = append(o.liveSpans, liveSpan{since: since})
	case !live && open:
		o.liveSpans[len(o.liveSpans)-1].until = o.now
	}
	o.modeNoted = true
}

// raisedLive reports whether r is a live notice: its key comes only from a
// real attempt (an outcome, or the applied summary), or an event it has not
// delivered may fall in one of spans. Undelivered events are no older than
// read, the admission time this process read r's last acknowledged
// delivery at, or without one than that acknowledgement (Sent).
func raisedLive(r admission.NoticeRecord, spans []liveSpan, read time.Time) bool {
	if r.Key.Outcome != 0 || r.Key.Kind == admission.NoticeAppliedSummary {
		return true
	}
	from, delivered := r.First, r.Sent
	if !read.IsZero() {
		delivered = read
	}
	if delivered.After(from) {
		from = delivered
	}
	for _, s := range spans {
		if !r.Last.Before(s.since) && (s.until.IsZero() || !from.After(s.until)) {
			return true
		}
	}
	return false
}

// noticeFinding is the record of one notice: its registered check, and in
// its details the events no delivery covered, their key and their example
// candidates. Legacy blocking enforces while admission previews, so a
// preview record warns, whatever its kind's severity. While the owner
// executes (live) a gap is an outage of automatic blocking: the record
// carries its kind's severity and no preview prefix.
func noticeFinding(r admission.NoticeRecord, now time.Time, live bool) alert.Finding {
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
	if live {
		return alert.Finding{Check: r.Key.Kind.Check(), Severity: alertSeverity(r.Key.Kind), Message: noticeMessages[r.Key.Kind], Details: b.String(), Timestamp: now}
	}
	return alert.Finding{Check: r.Key.Kind.Check(), Severity: alert.Warning, Message: "Admission preview: " + noticeMessages[r.Key.Kind], Details: b.String(), Timestamp: now}
}

// alertSeverity is the severity a notice of k alerts with.
func alertSeverity(k admission.NoticeKind) alert.Severity {
	if k.Severity() == admission.SeverityCritical {
		return alert.Critical
	}
	return alert.Warning
}

// ackNoticeSnapshot runs on the owner. Clearing preview notices at cutover
// invalidates their receipts, even if a new notice has the same first time.
func ackNoticeSnapshot(l *store.AdmissionLedger, started bool, acks []admission.NoticeAck) error {
	if liveExecution && started != l.LiveStarted() {
		return nil
	}
	return ackNotices(l, acks)
}
