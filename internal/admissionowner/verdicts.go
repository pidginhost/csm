package admissionowner

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/health"
	"github.com/pidginhost/csm/internal/verdict"
)

// Bounds of the verdict stage (spec 4.3).
const (
	verdictWorkers = 4
	// verdictPending bounds the jobs queued, running or completed and not
	// yet received; it is also the job channel's capacity.
	verdictPending = 64
	verdictResults = 64
	verdictReady   = 128
	// verdictTTL is how long a completed answer may be used.
	verdictTTL = 30 * time.Second
	// verdictTextBytes bounds the panel's tenant and note, and
	// verdictResultBytes one encoded result.
	verdictTextBytes   = 256
	verdictResultBytes = 2048
)

// answerKind is what a completed job learned.
type answerKind uint8

const (
	// answerAllow: a valid allow. The pick ends without a reservation.
	answerAllow answerKind = iota + 1
	// answerDefault: block, empty, or a failed exchange (Class set). The
	// local path continues.
	answerDefault
	// answerCancelled: the call was cancelled; nothing was learned.
	answerCancelled
	// answerSkipped: the job was cancelled before its call.
	answerSkipped
)

// jobKey is the attempt a job asks about, under one policy epoch.
type jobKey struct {
	Candidate admission.CandidateID `json:"candidate"`
	Attempt   uint32                `json:"attempt"`
	Epoch     uint64                `json:"epoch"`
}

// verdictJob is immutable once submitted; workers only read it.
type verdictJob struct {
	id         uint64
	key        jobKey
	ip, reason string
	ctx        context.Context
	cancel     context.CancelFunc
	timeout    time.Duration
	ask        Asker
}

// verdictResult is a completed job, normalized by its worker: fixed
// classes, the job's pinned identity and bounded panel text. No response
// body or error text is kept.
type verdictResult struct {
	Job    uint64             `json:"job"`
	Key    jobKey             `json:"key"`
	IP     string             `json:"ip"`
	Reason string             `json:"reason"`
	Answer answerKind         `json:"answer"`
	Class  verdict.ErrorClass `json:"class,omitempty"`
	Tenant string             `json:"tenant,omitempty"`
	Note   string             `json:"note,omitempty"`
	// completed includes time spent waiting for the owner to receive it.
	completed time.Time
}

// verdictStage is one policy epoch's workers and channels. The owner alone
// submits jobs and receives results.
type verdictStage struct {
	epoch   uint64
	jobs    chan *verdictJob
	results chan verdictResult
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	tally   *verdictTally
	// done closes once every worker has returned, after retirement began.
	done chan struct{}
}

// verdictTally holds the process counters. Workers count the calls they
// start and finish, independently of when the owner receives their results.
type verdictTally struct {
	mu                                         sync.Mutex
	asked, inFlight                            uint64
	allow, deflt, failed, cancelled, discarded uint64
	evicted, endings                           uint64
	lastErr                                    verdict.ErrorClass
	lastErrAt                                  time.Time
	recent                                     minuteTotals
}

func saturating(n *uint64) {
	if *n != ^uint64(0) {
		*n++
	}
}

func (t *verdictTally) add(n *uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	saturating(n)
}

// complete counts one call when its worker finishes, at mono and wall.
func (t *verdictTally) complete(r verdictResult, mono, wall time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if r.Answer == answerSkipped {
		return
	}
	t.inFlight--
	switch {
	case r.Answer == answerCancelled:
		saturating(&t.cancelled)
	case r.Class != "":
		saturating(&t.failed)
		t.lastErr, t.lastErrAt = r.Class, wall.UTC()
		t.recent.add(mono)
	case r.Answer == answerAllow:
		saturating(&t.allow)
	default:
		saturating(&t.deflt)
	}
}

// minuteTotals keeps sixty one-minute counts on the process's monotonic
// clock, aligned to the first count, so a wall-clock change cannot age
// them.
type minuteTotals struct {
	base    time.Time
	buckets [60]struct {
		set    bool
		minute int64
		n      uint64
	}
}

func (m *minuteTotals) minute(mono time.Time) int64 {
	return int64(max(mono.Sub(m.base), 0) / time.Minute)
}

func (m *minuteTotals) add(mono time.Time) {
	if m.base.IsZero() {
		m.base = mono
	}
	minute := m.minute(mono)
	b := &m.buckets[minute%int64(len(m.buckets))]
	if !b.set || b.minute != minute {
		b.set, b.minute, b.n = true, minute, 0
	}
	saturating(&b.n)
}

// total sums the sixty minutes up to and including mono's.
func (m *minuteTotals) total(mono time.Time) uint64 {
	if m.base.IsZero() {
		return 0
	}
	now := m.minute(mono)
	var out uint64
	for _, b := range m.buckets {
		if b.set && b.minute <= now && b.minute > now-int64(len(m.buckets)) {
			out += min(b.n, ^uint64(0)-out)
		}
	}
	return out
}

// verdicts is the owner's side of the stage, used only on its goroutine.
type verdicts struct {
	stage    *verdictStage
	retiring *verdictStage
	// pending holds each candidate's outstanding job until its completion
	// is received, cancelled or not; ready holds received answers.
	pending map[admission.CandidateID]*verdictJob
	ready   map[admission.CandidateID]verdictResult
	nextJob uint64
	// received counts the completions received: the queue's progress.
	received uint64
	tally    verdictTally
}

// observeVerdicts samples the outstanding jobs for queue health.
func (o *Owner) observeVerdicts() {
	if o.verdictQueue != nil {
		o.verdictQueue.Observe(deliveryNow(), len(o.verdicts.pending), o.verdicts.received)
	}
}

func (s *verdictStage) work() {
	defer s.wg.Done()
	for {
		select {
		case <-s.ctx.Done():
			return
		case j := <-s.jobs:
			r := s.run(j)
			// The owner keeps at most verdictPending jobs outstanding, so the
			// result channel has room; a stopping stage still delivers it.
			select {
			case s.results <- r:
			default:
				select {
				case s.results <- r:
				case <-s.ctx.Done():
					return
				}
			}
		}
	}
}

// run makes one call. Its timeout covers the exchange from the worker's
// start, not the time the job waited in the queue.
func (s *verdictStage) run(j *verdictJob) verdictResult {
	r := verdictResult{Job: j.id, Key: j.key, IP: j.ip, Reason: j.reason}
	// A stopping stage cancels its jobs one at a time after itself: check
	// both, so no call starts once the stage is cancelled.
	if s.ctx.Err() != nil || j.ctx.Err() != nil {
		s.tally.add(&s.tally.discarded)
		r.Answer = answerSkipped
		return r
	}
	s.tally.mu.Lock()
	saturating(&s.tally.asked)
	s.tally.inFlight++
	s.tally.mu.Unlock()
	ctx, cancel := context.WithTimeout(j.ctx, j.timeout)
	resp, err := j.ask(ctx, j.ip, j.reason)
	timedOut := ctx.Err() == context.DeadlineExceeded
	cancel()
	switch {
	case j.ctx.Err() != nil:
		r.Answer = answerCancelled
	case err != nil:
		r.Answer, r.Class = answerDefault, verdict.ClassOf(err)
		if timedOut {
			r.Class = verdict.ClassTimeout
		} else if r.Class == "" {
			r.Class = verdict.ClassProtocol
		}
	case resp.Verdict == "allow":
		r.Answer = answerAllow
	case resp.Verdict == "" || resp.Verdict == "block":
		r.Answer = answerDefault
	default:
		// An asker that returns a verdict the client would refuse made a
		// protocol error; it never reads as an allow.
		r.Answer, r.Class = answerDefault, verdict.ClassProtocol
	}
	if r.Class == "" && r.Answer != answerCancelled {
		r.Tenant, r.Note = boundedText(resp.TenantID), boundedText(resp.Note)
		fitResult(&r)
	}
	r.completed = monoNow()
	s.tally.complete(r, r.completed, time.Now())
	return r
}

// boundedText escapes control characters and invalid bytes, then keeps at
// most verdictTextBytes without splitting a character.
func boundedText(s string) string {
	var b strings.Builder
	for _, c := range strings.ToValidUTF8(s, "�") {
		if unicode.IsControl(c) {
			fmt.Fprintf(&b, "\\u%04x", c)
		} else {
			b.WriteRune(c)
		}
		if b.Len() > verdictTextBytes {
			break
		}
	}
	return truncateRunes(b.String(), verdictTextBytes)
}

// truncateRunes keeps at most n bytes of s, at a character boundary.
func truncateRunes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// fitResult shortens the tenant and note, longer one first, until the
// encoded result fits verdictResultBytes. The fixed fields stay whole.
func fitResult(r *verdictResult) {
	for {
		data, err := json.Marshal(r)
		if err == nil && len(data) <= verdictResultBytes {
			return
		}
		field := &r.Tenant
		if len(r.Note) > len(r.Tenant) {
			field = &r.Note
		}
		if *field == "" {
			return
		}
		_, size := utf8.DecodeLastRuneInString(*field)
		*field = (*field)[:len(*field)-size]
	}
}

// startVerdicts starts the stage for the installed policy when its callback
// is on. A stage still retiring starts its replacement once its workers
// have returned, so no more than verdictWorkers calls ever run.
func (o *Owner) startVerdicts() {
	v := &o.verdicts
	if v.stage != nil || v.retiring != nil || !o.asksVerdicts() {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &verdictStage{
		epoch: o.policy.Epoch, jobs: make(chan *verdictJob, verdictPending), results: make(chan verdictResult, verdictResults),
		ctx: ctx, cancel: cancel, tally: &v.tally, done: make(chan struct{}),
	}
	s.wg.Add(verdictWorkers)
	for range verdictWorkers {
		go s.work()
	}
	v.stage = s
}

// retireVerdicts invalidates every job and answer of the current stage and
// cancels it. Unrelated owner work goes on while its workers return; one
// joiner reports when they have.
func (o *Owner) retireVerdicts() {
	v := &o.verdicts
	for range v.ready {
		v.tally.add(&v.tally.discarded)
	}
	clear(v.ready)
	clear(v.pending)
	o.observeVerdicts()
	s := v.stage
	if s == nil {
		return
	}
	v.stage, v.retiring = nil, s
	s.cancel()
	go func() {
		s.wg.Wait()
		close(s.done)
	}()
}

// verdictsRetired takes what the retired stage left in its channels,
// counts it and starts the stage of the current policy.
func (o *Owner) verdictsRetired() {
	v := &o.verdicts
	s := v.retiring
	v.retiring = nil
	o.drainStage(s)
	o.startVerdicts()
	o.scheduleDue = true
}

// drainStage counts the jobs no worker took and the completions nobody
// received, once its workers have returned.
func (o *Owner) drainStage(s *verdictStage) {
	v := &o.verdicts
	for {
		select {
		case <-s.jobs:
			v.tally.add(&v.tally.discarded)
		case r := <-s.results:
			if r.Answer != answerSkipped && r.Answer != answerCancelled {
				v.tally.add(&v.tally.discarded)
			}
		default:
			return
		}
	}
}

// stopVerdicts cancels every call and joins the workers. A cancelled call
// is never read as an answer; its candidate stays queued.
func (o *Owner) stopVerdicts() {
	v := &o.verdicts
	for _, s := range []*verdictStage{v.stage, v.retiring} {
		if s != nil {
			s.cancel()
			s.wg.Wait()
			o.drainStage(s)
		}
	}
	v.stage, v.retiring = nil, nil
	clear(v.pending)
	for range v.ready {
		v.tally.add(&v.tally.discarded)
	}
	clear(v.ready)
	o.observeVerdicts()
}

// stageResults is the current stage's result channel, nil without one.
func (o *Owner) stageResults() <-chan verdictResult {
	if o.verdicts.stage == nil {
		return nil
	}
	return o.verdicts.stage.results
}

// stageRetired closes once a retiring stage's workers have returned.
func (o *Owner) stageRetired() <-chan struct{} {
	if o.verdicts.retiring == nil {
		return nil
	}
	return o.verdicts.retiring.done
}

// askVerdict submits one job for pick c lasting as member, unless the
// stage is retiring or full: then the candidate stays as it is.
func (o *Owner) askVerdict(id admission.CandidateID, c admission.Candidate, ip, reason string) {
	v := &o.verdicts
	s := v.stage
	if s == nil || len(v.pending) >= verdictPending || v.pending[id] != nil {
		return
	}
	ctx, cancel := context.WithCancel(s.ctx)
	j := &verdictJob{
		id: v.nextJob + 1, key: jobKey{Candidate: id, Attempt: c.Attempts + 1, Epoch: s.epoch},
		ip: ip, reason: reason, ctx: ctx, cancel: cancel, timeout: o.policy.VerdictTimeout, ask: o.policy.AskVerdict,
	}
	select {
	case s.jobs <- j:
		v.nextJob++
		if v.pending == nil {
			v.pending = map[admission.CandidateID]*verdictJob{}
		}
		v.pending[id] = j
		o.observeVerdicts()
	default:
		cancel()
	}
}

// receiveVerdict takes one completion of the current stage. Only the
// candidate's outstanding job is answered; a late, duplicate or swept
// completion is discarded. A received answer wakes the schedule.
func (o *Owner) receiveVerdict(r verdictResult) {
	v := &o.verdicts
	v.received++
	defer o.observeVerdicts()
	j := v.pending[r.Key.Candidate]
	if j == nil || j.id != r.Job || j.key != r.Key || j.ip != r.IP || j.reason != r.Reason {
		if r.Answer != answerSkipped && r.Answer != answerCancelled {
			v.tally.add(&v.tally.discarded)
		}
		return
	}
	delete(v.pending, r.Key.Candidate)
	swept := j.ctx.Err() != nil
	j.cancel()
	switch {
	case r.Answer == answerSkipped || r.Answer == answerCancelled:
		return
	case swept || !monoNow().Before(r.completed.Add(verdictTTL)):
		v.tally.add(&v.tally.discarded)
		o.scheduleDue = true
		return
	}
	if v.ready == nil {
		v.ready = map[admission.CandidateID]verdictResult{}
	}
	if _, replacing := v.ready[r.Key.Candidate]; !replacing && len(v.ready) >= verdictReady {
		o.evictReady()
	}
	v.ready[r.Key.Candidate] = r
	o.scheduleDue = true
}

// evictReady makes room for one answer: expired answers go first, then the
// oldest completed, the earlier job first. The evicted candidate asks again
// when it is next selected.
func (o *Owner) evictReady() {
	v := &o.verdicts
	if o.expireVerdicts() {
		return
	}
	oldest := slices.MinFunc(slices.Collect(maps.Values(v.ready)), func(a, b verdictResult) int {
		if c := a.completed.Compare(b.completed); c != 0 {
			return c
		}
		return cmpUint(a.Job, b.Job)
	})
	delete(v.ready, oldest.Key.Candidate)
	v.tally.add(&v.tally.evicted)
}

func cmpUint(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// expireVerdicts drops the answers whose lifetime has ended and wakes the
// schedule, so their candidates can ask again whatever the live budgets.
// It reports whether any was dropped.
func (o *Owner) expireVerdicts() bool {
	v := &o.verdicts
	now := monoNow()
	expired := false
	for id, r := range v.ready {
		if !now.Before(r.completed.Add(verdictTTL)) {
			delete(v.ready, id)
			expired = true
		}
	}
	if expired {
		o.scheduleDue = true
	}
	return expired
}

// usable reports whether key still names c's next attempt under the
// installed policy, with c still waiting for it.
func (o *Owner) usable(c admission.Candidate, key jobKey) bool {
	return c.State == admission.StateQueued && c.Attempts+1 == key.Attempt && key.Epoch == o.policy.Epoch &&
		o.now.Before(c.AgeOut) && (c.Attempts == 0 || o.now.Before(c.ExpiresAt))
}

// sweepVerdicts cancels the jobs of candidates that ceased to be eligible
// and drops their answers. A cancelled job keeps its pending slot until
// its completion is received, so cancelled work stays bounded.
func (o *Owner) sweepVerdicts() {
	v := &o.verdicts
	for id, j := range v.pending {
		if j.ctx.Err() != nil {
			continue
		}
		if c, err := o.ledger.Candidate(id); err != nil || !o.usable(c, j.key) {
			j.cancel()
		}
	}
	for id, r := range v.ready {
		if c, err := o.ledger.Candidate(id); err != nil || !o.usable(c, r.Key) {
			delete(v.ready, id)
			v.tally.add(&v.tally.discarded)
		}
	}
}

// readyVerdict is the usable answer for pick c lasting as member: same
// attempt, epoch, address and reason, completed less than verdictTTL ago.
// Any other answer for c is discarded.
func (o *Owner) readyVerdict(id admission.CandidateID, c admission.Candidate, ip, reason string) (verdictResult, bool) {
	v := &o.verdicts
	r, ok := v.ready[id]
	if !ok {
		return r, false
	}
	if !monoNow().Before(r.completed.Add(verdictTTL)) || !o.usable(c, r.Key) || r.Key.Candidate != id || r.IP != ip || r.Reason != reason {
		delete(v.ready, id)
		v.tally.add(&v.tally.discarded)
		return r, false
	}
	return r, true
}

// answers are the outside answers the schedule judges queued work by:
// outstanding jobs and the work a refused policy holds wait, and allows
// are picked uncharged.
func (o *Owner) answers() map[admission.CandidateID]admission.Answer {
	v := &o.verdicts
	if len(v.pending) == 0 && len(v.ready) == 0 && len(o.policyHeld) == 0 {
		return nil
	}
	out := make(map[admission.CandidateID]admission.Answer, len(v.pending)+len(v.ready)+len(o.policyHeld))
	now := monoNow()
	for id, r := range v.ready {
		if r.Answer == answerAllow && now.Before(r.completed.Add(verdictTTL)) {
			out[id] = admission.AnswerAllow
		}
	}
	for id := range v.pending {
		out[id] = admission.AnswerPending
	}
	for id := range o.policyHeld {
		out[id] = admission.AnswerPending
	}
	return out
}

// verdictStatus reads the stage for status.
func (o *Owner) verdictStatus() *health.AdmissionVerdict {
	v := &o.verdicts
	t := &v.tally
	t.mu.Lock()
	defer t.mu.Unlock()
	s := &health.AdmissionVerdict{
		Enabled: o.asksVerdicts(), Epoch: o.policy.Epoch,
		Pending: len(v.pending), InFlight: t.inFlight, Ready: len(v.ready), StageRetiring: v.retiring != nil,
		Asked: t.asked, ResponsesAllow: t.allow, ResponsesDefault: t.deflt, Failed: t.failed, Cancelled: t.cancelled,
		Discarded: t.discarded, ReadyEvicted: t.evicted, AllowEndings: t.endings,
		LastHourFailed: t.recent.total(monoNow()),
	}
	if t.lastErr != "" {
		class, at := string(t.lastErr), t.lastErrAt
		s.LastError, s.LastErrorAt = &class, &at
	}
	return s
}
