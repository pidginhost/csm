package admissionowner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/health"
	"github.com/pidginhost/csm/internal/store"
	"github.com/pidginhost/csm/internal/verdict"
)

// fakePanel is a verdict asker the test scripts. While hold is set, calls
// wait for it to close or for their context to end.
type fakePanel struct {
	mu        sync.Mutex
	answer    func(ip string) (verdict.Response, error)
	hold      chan struct{}
	asked     []string
	active    int
	peak      int
	cancelled int
}

func newFakePanel(v string) *fakePanel {
	return &fakePanel{answer: func(string) (verdict.Response, error) { return verdict.Response{Verdict: v}, nil }}
}

func (p *fakePanel) ask(ctx context.Context, ip, _ string) (verdict.Response, error) {
	p.mu.Lock()
	p.asked = append(p.asked, ip)
	p.active++
	p.peak = max(p.peak, p.active)
	hold, answer := p.hold, p.answer
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		p.active--
		p.mu.Unlock()
	}()
	if hold != nil {
		select {
		case <-hold:
		case <-ctx.Done():
			p.mu.Lock()
			p.cancelled++
			p.mu.Unlock()
			return verdict.Response{}, ctx.Err()
		}
	}
	return answer(ip)
}

func (p *fakePanel) state() (asked []string, active, peak, cancelled int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.asked...), p.active, p.peak, p.cancelled
}

func (p *fakePanel) set(fn func(*fakePanel)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	fn(p)
}

func verdictPolicy(epoch uint64, p *fakePanel) ExecutionPolicy {
	policy := validPolicy(epoch)
	policy.VerdictEnabled, policy.AskVerdict = true, p.ask
	return policy
}

// verdictOwner starts an executable owner whose policy asks panel.
func verdictOwner(t *testing.T, f *ownerFixture, blocks *fakeBlocks, panel *fakePanel) (*Owner, *policyReader, *fakeMono) {
	t.Helper()
	r := &policyReader{p: verdictPolicy(1, panel)}
	opts := executeOptions(f, blocks)
	opts.Policy = r.read
	o := f.start(opts)
	return o, r, heldMono(t, o)
}

func verdictState(t *testing.T, o *Owner) *health.AdmissionVerdict {
	t.Helper()
	var s *health.AdmissionVerdict
	if err := o.do(func() error { s = o.verdictStatus(); return nil }); err != nil {
		t.Fatal(err)
	}
	return s
}

func readyAnswers(t *testing.T, o *Owner, n int) {
	t.Helper()
	eventually(t, fmt.Sprintf("%d answers", n), func() bool { return verdictState(t, o).Ready == n })
}

// D5, D7: with the callback on, a pick is asked about before anything is
// reserved and stays queued meanwhile. A valid allow then ends it as one
// verdict_allow refusal with no attempt, reservation, charge or apply,
// counted and logged once after the ending commits.
func TestOwnerEndsAPanelAllowUncharged(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	panel := newFakePanel("allow")
	panel.answer = func(string) (verdict.Response, error) {
		return verdict.Response{Verdict: "allow", TenantID: "tenant-7", Note: "known crawler"}, nil
	}
	o, _, _ := verdictOwner(t, f, blocks, panel)
	var logged []verdictResult
	setOwnerHook(t, o, &logVerdictAllow, func(_ admission.CandidateID, _ string, r verdictResult) { logged = append(logged, r) })
	id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if c := candidate(t, o, id); c.State != admission.StateQueued || c.Attempts != 0 || c.Reason != 0 {
		t.Fatalf("asked pick = %+v", c)
	}
	readyAnswers(t, o, 1)
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	c := candidate(t, o, id)
	if c.State != admission.StateRefused || c.Reason != admission.ReasonVerdictAllow || c.Attempts != 0 {
		t.Fatalf("allowed pick = %+v", c)
	}
	checks, applies := blocks.calls()
	if len(checks) != 0 || len(applies) != 0 || ledgerStatus(t, o).Ceiling.General.Used != 0 {
		t.Fatalf("an allowed pick reached reservation: %d checks, %d applies", len(checks), len(applies))
	}
	if asked, _, _, _ := panel.state(); len(asked) != 1 || asked[0] != "192.0.2.10" {
		t.Fatalf("panel asked about %v", asked)
	}
	if len(logged) != 1 || logged[0].Tenant != "tenant-7" || logged[0].Note != "known crawler" || logged[0].IP != "192.0.2.10" {
		t.Fatalf("logged %+v", logged)
	}
	s := verdictState(t, o)
	if !s.Enabled || s.Epoch != 1 || s.Asked != 1 || s.ResponsesAllow != 1 || s.AllowEndings != 1 || s.Pending != 0 || s.Ready != 0 || s.InFlight != 0 || s.LastError != nil {
		t.Fatalf("verdict status = %+v", s)
	}
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if s := verdictState(t, o); s.AllowEndings != 1 || len(logged) != 1 {
		t.Fatalf("a later turn counted the allow again: %+v", s)
	}
}

// Block, an empty verdict and a failed exchange all continue the local
// path: the pick is reserved and applied with the answer for its attempt,
// which the reservation consumes. A failure keeps only its fixed class.
func TestOwnerRunsBlocksAfterADefaultAnswer(t *testing.T) {
	for name, answer := range map[string]func(string) (verdict.Response, error){
		"block": func(string) (verdict.Response, error) { return verdict.Response{Verdict: "block"}, nil },
		"empty": func(string) (verdict.Response, error) { return verdict.Response{}, nil },
		"error": func(string) (verdict.Response, error) {
			return unconfiguredClient.Ask(context.Background(), verdict.Request{})
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			panel := newFakePanel("")
			panel.answer = answer
			o, _, _ := verdictOwner(t, f, blocks, panel)
			id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
			if err := o.do(o.turn); err != nil {
				t.Fatal(err)
			}
			readyAnswers(t, o, 1)
			if err := o.do(o.turn); err != nil {
				t.Fatal(err)
			}
			if c := candidate(t, o, id); c.State != admission.StateVerified || c.Attempts != 1 {
				t.Fatalf("pick after a %s answer = %+v", name, c)
			}
			s := verdictState(t, o)
			if s.Ready != 0 || s.Asked != 1 {
				t.Fatalf("status = %+v", s)
			}
			switch name {
			case "error":
				if s.Failed != 1 || s.LastError == nil || *s.LastError != string(verdict.ClassConfiguration) || s.LastErrorAt == nil || s.LastHourFailed != 1 {
					t.Fatalf("failure status = %+v", s)
				}
			default:
				if s.ResponsesDefault != 1 || s.Failed != 0 || s.LastError != nil {
					t.Fatalf("default status = %+v", s)
				}
			}
		})
	}
}

// unconfiguredClient is the real client without a usable URL: every call
// fails as configuration.
var unconfiguredClient = verdict.New(verdict.Config{URL: "x"})

// With the callback off nothing is asked and nothing waits: the pick runs
// in its first turn.
func TestOwnerWithoutCallbackAsksNothing(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	panel := newFakePanel("allow")
	r := &policyReader{p: validPolicy(1)}
	r.p.AskVerdict = panel.ask
	opts := executeOptions(f, blocks)
	opts.Policy = r.read
	o := f.start(opts)
	id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if c := candidate(t, o, id); c.State != admission.StateVerified {
		t.Fatalf("pick = %+v", c)
	}
	if asked, _, _, _ := panel.state(); len(asked) != 0 {
		t.Fatalf("asked %v with the callback off", asked)
	}
	if s := verdictState(t, o); s.Enabled || s.Pending != 0 || s.Asked != 0 || len(blocks.snapshots) != 0 {
		t.Fatalf("status %+v, %d snapshots", s, len(blocks.snapshots))
	}
}

// Local checks come before the panel and again before any answer is
// used: a protected or already enforced target is never asked about, a
// full set waits without a call, and protection added while the call ran
// refuses the pick instead of ending it as an allow.
func TestOwnerChecksLocallyAroundTheCallback(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	blocks.refuse["192.0.2.20"] = firewall.BlockRefusedProtected
	blocks.refuse["192.0.2.21"] = firewall.BlockRefusedExisting
	panel := newFakePanel("allow")
	o, _, _ := verdictOwner(t, f, blocks, panel)
	protected, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.20")
	existing, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.21")
	later, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.22")
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if c := candidate(t, o, protected); c.State != admission.StateRefused || c.Reason != admission.ReasonProtected {
		t.Fatalf("protected pick = %+v", c)
	}
	if c := candidate(t, o, existing); c.State != admission.StateRefused || c.Reason != admission.ReasonExistingEffect {
		t.Fatalf("existing pick = %+v", c)
	}
	readyAnswers(t, o, 1)
	if asked, _, _, _ := panel.state(); len(asked) != 1 || asked[0] != "192.0.2.22" {
		t.Fatalf("asked %v", asked)
	}
	blocks.set(func(b *fakeBlocks) { b.refuse["192.0.2.22"] = firewall.BlockRefusedAllowed })
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if c := candidate(t, o, later); c.State != admission.StateRefused || c.Reason != admission.ReasonProtected {
		t.Fatalf("pick protected while asked = %+v", c)
	}
	if s := verdictState(t, o); s.AllowEndings != 0 {
		t.Fatalf("an allow ended a protected pick: %+v", s)
	}
	full, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.23")
	blocks.set(func(b *fakeBlocks) { b.temp, b.limit = 4, 4 })
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if c := candidate(t, o, full); c.State != admission.StateQueued || c.Reason != admission.ReasonSetFull {
		t.Fatalf("pick for a full set = %+v", c)
	}
	if asked, _, _, _ := panel.state(); len(asked) != 1 {
		t.Fatalf("a full set was asked about: %v", asked)
	}
}

// An allow ends its pick uncharged even with the live ceiling spent: the
// schedule picks it as uncharged work. Charged work waits.
func TestOwnerSchedulesAllowsUncharged(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	panel := newFakePanel("allow")
	o, _, _ := verdictOwner(t, f, blocks, panel)
	id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	readyAnswers(t, o, 1)
	var seen map[admission.CandidateID]admission.Answer
	schedule := scheduleLedger
	setOwnerHook(t, o, &scheduleLedger, func(l *store.AdmissionLedger, lim admission.ScheduleLimits, answers map[admission.CandidateID]admission.Answer) ([]admission.Pick, error) {
		seen = answers
		return schedule(l, lim, answers)
	})
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if seen[id] != admission.AnswerAllow {
		t.Fatalf("answers = %v", seen)
	}
	if c := candidate(t, o, id); c.State != admission.StateRefused || c.Reason != admission.ReasonVerdictAllow {
		t.Fatalf("pick = %+v", c)
	}
}

// Four workers bound the calls in flight and 64 the jobs outstanding. A
// full stage leaves further picks queued, unasked, with no goroutine of
// their own, and is not an answer. The owner keeps serving reloads and
// status meanwhile; asked jobs are passed over by the schedule.
func TestOwnerBoundsVerdictCalls(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	panel := newFakePanel("block")
	release := make(chan struct{})
	panel.hold = release
	o, _, _ := verdictOwner(t, f, blocks, panel)
	for i := range 70 {
		queuedAt(t, o, p, f.host, admission.SeverityHigh, fmt.Sprintf("2001:db8::%x", i+1))
	}
	// The history budget can hold a turn below 64 picks; the next turn
	// asks about the rest until the stage is full.
	for range 2 {
		if err := o.do(o.turn); err != nil {
			t.Fatal(err)
		}
	}
	eventually(t, "four calls", func() bool { _, active, _, _ := panel.state(); return active == verdictWorkers })
	if s := verdictState(t, o); s.Pending != verdictPending || s.InFlight != verdictWorkers {
		t.Fatalf("status = %+v", s)
	}
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if err := o.Reload(); err != nil {
		t.Fatal(err)
	}
	if s := verdictState(t, o); s.Pending != verdictPending {
		t.Fatalf("pending after a further turn = %d", s.Pending)
	}
	if asked, _, _, _ := panel.state(); len(asked) != verdictWorkers {
		t.Fatalf("%d calls started while four ran", len(asked))
	}
	for _, c := range queuedCandidates(t, o) {
		if c.State != admission.StateQueued || c.Attempts != 0 {
			t.Fatalf("a full stage changed %+v", c)
		}
	}
	if _, applies := blocks.calls(); len(applies) != 0 {
		t.Fatalf("a full stage applied %v", applies)
	}
	close(release)
	readyAnswers(t, o, verdictPending)
	if _, _, peak, _ := panel.state(); peak != verdictWorkers {
		t.Fatalf("%d calls ran at once", peak)
	}
	s := verdictState(t, o)
	if s.Asked != verdictPending || s.ResponsesDefault != verdictPending || s.InFlight != 0 || s.Pending != 0 {
		t.Fatalf("status = %+v", s)
	}
}

// A new epoch cancels the calls of the old one and drops its answers; the
// replacement stage starts once the old workers returned, so no more than
// four calls ever run. Picks ask again under the new epoch and never use
// an old epoch's answer.
func TestOwnerRetiresVerdictsOnANewEpoch(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	panel := newFakePanel("allow")
	held := make(chan struct{})
	panel.hold = held
	o, r, _ := verdictOwner(t, f, blocks, panel)
	var ids []admission.CandidateID
	for i := range 6 {
		id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, fmt.Sprintf("2001:db8::%x", i+1))
		ids = append(ids, id)
	}
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	eventually(t, "four calls", func() bool { _, active, _, _ := panel.state(); return active == verdictWorkers })
	r.publish(verdictPolicy(2, panel))
	if err := o.Reload(); err != nil {
		t.Fatal(err)
	}
	if s := verdictState(t, o); s.Pending != 0 || s.Epoch != 2 {
		t.Fatalf("status after the new epoch = %+v", s)
	}
	eventually(t, "the old stage to retire", func() bool { return !verdictState(t, o).StageRetiring })
	if _, active, _, cancelled := panel.state(); cancelled != verdictWorkers || active != 0 {
		t.Fatalf("%d calls cancelled, %d active", cancelled, active)
	}
	panel.set(func(p *fakePanel) { p.hold = nil })
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	readyAnswers(t, o, len(ids))
	if asked, _, peak, _ := panel.state(); len(asked) != verdictWorkers+len(ids) || peak != verdictWorkers {
		t.Fatalf("asked %d times, %d at once", len(asked), peak)
	}
	r.publish(verdictPolicy(3, panel))
	if err := o.Reload(); err != nil {
		t.Fatal(err)
	}
	if s := verdictState(t, o); s.Ready != 0 || s.Discarded < uint64(len(ids)) {
		t.Fatalf("an old epoch's answers survived: %+v", s)
	}
	eventually(t, "the second stage to retire", func() bool { return !verdictState(t, o).StageRetiring })
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		if c := candidate(t, o, id); c.State != admission.StateQueued {
			t.Fatalf("an old epoch's allow was used: %+v", c)
		}
	}
	readyAnswers(t, o, len(ids))
	s := verdictState(t, o)
	if s.Asked != s.ResponsesAllow+s.ResponsesDefault+s.Failed+s.Cancelled+s.InFlight || s.Cancelled != verdictWorkers {
		t.Fatalf("call accounting = %+v", s)
	}
	close(held)
}

// A pick that stops being eligible while it is asked about has its call
// cancelled; the cancelled job holds its slot until its completion
// arrives, and its answer is never used.
func TestOwnerCancelsCallsOfIneligiblePicks(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	panel := newFakePanel("allow")
	panel.hold = make(chan struct{})
	o, _, _ := verdictOwner(t, f, blocks, panel)
	id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the call", func() bool { _, active, _, _ := panel.state(); return active == 1 })
	f.host.advance(admission.QueueAgeLimit + time.Minute)
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the cancellation", func() bool { _, _, _, cancelled := panel.state(); return cancelled == 1 })
	eventually(t, "the completion", func() bool { return verdictState(t, o).Pending == 0 })
	if c := candidate(t, o, id); c.State == admission.StateRefused {
		t.Fatalf("an ineligible pick took its answer: %+v", c)
	}
	if s := verdictState(t, o); s.Cancelled != 1 || s.Ready != 0 || s.AllowEndings != 0 {
		t.Fatalf("status = %+v", s)
	}
}

// A received answer lasts thirty seconds on the monotonic clock: usable
// just before, gone at the deadline, after which the pick asks again.
func TestOwnerExpiresAnswers(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	panel := newFakePanel("allow")
	o, _, mono := verdictOwner(t, f, blocks, panel)
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	readyAnswers(t, o, 1)
	mono.advance(verdictTTL - time.Nanosecond)
	if err := o.do(func() error {
		if o.expireVerdicts() {
			return errors.New("an answer expired early")
		}
		mono.advance(time.Nanosecond)
		if !o.expireVerdicts() || len(o.verdicts.ready) != 0 || !o.scheduleDue {
			return errors.New("an answer outlived its deadline")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	eventually(t, "a second call", func() bool { a, _, _, _ := panel.state(); return len(a) == 2 })
}

// Stop cancels running and queued calls and joins the workers. A
// cancellation is never an answer: the picks stay queued.
func TestOwnerStopCancelsVerdictCalls(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	panel := newFakePanel("allow")
	panel.hold = make(chan struct{})
	o, _, _ := verdictOwner(t, f, blocks, panel)
	for i := range 8 {
		queuedAt(t, o, p, f.host, admission.SeverityHigh, fmt.Sprintf("2001:db8::%x", i+1))
	}
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	eventually(t, "four calls", func() bool { _, active, _, _ := panel.state(); return active == verdictWorkers })
	o.Stop()
	if _, active, _, cancelled := panel.state(); active != 0 || cancelled != verdictWorkers {
		t.Fatalf("after stop: %d active, %d cancelled", active, cancelled)
	}
	if _, applies := blocks.calls(); len(applies) != 0 {
		t.Fatalf("a cancelled call ran its pick: %v", applies)
	}
	s := o.Status().Owner.Verdict
	if s == nil || s.InFlight != 0 || s.Cancelled != verdictWorkers || s.ResponsesAllow != 0 {
		t.Fatalf("status after stop = %+v", s)
	}
}

// With the real client blocked at a local server, Stop returns within a
// second of cancelling the stage, whatever the configured timeout.
func TestOwnerStopJoinsTheRealClient(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	entered := make(chan struct{}, verdictWorkers)
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		select {
		case <-r.Context().Done():
		case <-done:
		}
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(done) })
	client := verdict.New(verdict.Config{URL: srv.URL, AllowUnsigned: true, Timeout: 30 * time.Second})
	policy := validPolicy(1)
	policy.VerdictEnabled, policy.VerdictTimeout = true, 30*time.Second
	policy.AskVerdict = func(ctx context.Context, ip, reason string) (verdict.Response, error) {
		return client.Ask(ctx, verdict.Request{IP: ip, Reason: reason})
	}
	r := &policyReader{p: policy}
	opts := executeOptions(f, blocks)
	opts.Policy = r.read
	o := f.start(opts)
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	<-entered
	start := time.Now()
	o.Stop()
	if took := time.Since(start); took > time.Second {
		t.Fatalf("stop took %v", took)
	}
}

// A result keeps its pinned identity whole; the panel's tenant and note
// are escaped, bounded at character boundaries and shortened further
// until the encoded result fits.
func TestVerdictResultsStayBounded(t *testing.T) {
	controls := strings.Repeat("\x01", 4*verdictTextBytes)
	wide := strings.Repeat("é", verdictTextBytes)
	if got := boundedText("a\nb\x7f"); got != `a\u000ab\u007f` {
		t.Fatalf("escaped = %q", got)
	}
	if got := boundedText(wide); len(got) > verdictTextBytes || !utf8.ValidString(got) {
		t.Fatalf("wide text = %d bytes, valid %t", len(got), utf8.ValidString(got))
	}
	if got := boundedText("ok\xff"); got != "ok�" {
		t.Fatalf("invalid bytes = %q", got)
	}
	panel := &fakePanel{answer: func(string) (verdict.Response, error) {
		return verdict.Response{Verdict: "allow", TenantID: strings.Repeat("<", 1000), Note: controls}, nil
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &verdictStage{ctx: ctx, tally: &verdictTally{}}
	id := admission.CandidateID("cand_00112233445566778899aabbccddeeff")
	r := s.run(&verdictJob{id: 7, key: jobKey{Candidate: id, Attempt: 2, Epoch: 3}, ip: "2001:db8::1", reason: "CSM auto-block: ssh_brute", ctx: ctx, cancel: cancel, timeout: time.Second, ask: panel.ask})
	data, err := json.Marshal(r)
	if err != nil || len(data) > verdictResultBytes {
		t.Fatalf("encoded result = %d bytes, %v", len(data), err)
	}
	if r.Answer != answerAllow || r.Job != 7 || r.Key.Candidate != id || r.Key.Attempt != 2 || r.Key.Epoch != 3 || r.IP != "2001:db8::1" || r.Reason != "CSM auto-block: ssh_brute" {
		t.Fatalf("identity = %+v", r)
	}
	if len(r.Tenant) > verdictTextBytes || len(r.Note) > verdictTextBytes || !utf8.ValidString(r.Tenant) || !utf8.ValidString(r.Note) || strings.ContainsRune(r.Note, '\x01') {
		t.Fatalf("text = %q / %q", r.Tenant, r.Note)
	}
}

// A completion answers only its candidate's outstanding job: a duplicate,
// a late one for a replaced job and one for an unknown candidate are
// discarded. A full ready cache evicts expired answers first, then the
// oldest received, the earlier job first.
func TestOwnerReceivesOnlyOutstandingAnswers(t *testing.T) {
	mono := &fakeMono{now: time.Unix(1000, 0)}
	previous := monoNow
	monoNow = mono.read
	t.Cleanup(func() { monoNow = previous })
	o := &Owner{}
	submit := func(n int) (admission.CandidateID, *verdictJob) {
		id := admission.CandidateID(fmt.Sprintf("cand_%032x", n))
		ctx, cancel := context.WithCancel(context.Background())
		o.verdicts.nextJob++
		j := &verdictJob{id: o.verdicts.nextJob, key: jobKey{Candidate: id, Attempt: 1, Epoch: 1}, ctx: ctx, cancel: cancel}
		if o.verdicts.pending == nil {
			o.verdicts.pending = map[admission.CandidateID]*verdictJob{}
		}
		o.verdicts.pending[id] = j
		return id, j
	}
	result := func(j *verdictJob) verdictResult {
		return verdictResult{Job: j.id, Key: j.key, Answer: answerDefault}
	}
	id, old := submit(1)
	o.verdicts.tally.inFlight = 1
	_, newer := submit(1)
	if newer.key.Candidate != id {
		t.Fatal("fixture: the replacement names another candidate")
	}
	o.receiveVerdict(result(old))
	if len(o.verdicts.ready) != 0 || o.verdicts.tally.discarded != 1 {
		t.Fatalf("a replaced job answered: ready %d, discarded %d", len(o.verdicts.ready), o.verdicts.tally.discarded)
	}
	o.verdicts.tally.inFlight = 1
	o.receiveVerdict(result(newer))
	o.verdicts.tally.inFlight = 1
	o.receiveVerdict(result(newer))
	if len(o.verdicts.ready) != 1 || o.verdicts.tally.discarded != 2 {
		t.Fatalf("duplicate: ready %d, discarded %d", len(o.verdicts.ready), o.verdicts.tally.discarded)
	}
	for n := 2; n <= verdictReady; n++ {
		mono.advance(time.Millisecond)
		_, j := submit(n)
		o.verdicts.tally.inFlight = 1
		o.receiveVerdict(result(j))
	}
	if len(o.verdicts.ready) != verdictReady || o.verdicts.tally.evicted != 0 {
		t.Fatalf("ready %d, evicted %d", len(o.verdicts.ready), o.verdicts.tally.evicted)
	}
	mono.advance(time.Millisecond)
	_, j := submit(verdictReady + 1)
	o.verdicts.tally.inFlight = 1
	o.receiveVerdict(result(j))
	if _, kept := o.verdicts.ready[id]; kept || len(o.verdicts.ready) != verdictReady || o.verdicts.tally.evicted != 1 {
		t.Fatalf("eviction kept the oldest: ready %d, evicted %d", len(o.verdicts.ready), o.verdicts.tally.evicted)
	}
	mono.advance(verdictTTL)
	_, j = submit(verdictReady + 2)
	o.verdicts.tally.inFlight = 1
	o.receiveVerdict(result(j))
	if len(o.verdicts.ready) != 1 || o.verdicts.tally.evicted != 1 {
		t.Fatalf("expired answers were not dropped first: ready %d, evicted %d", len(o.verdicts.ready), o.verdicts.tally.evicted)
	}
}

// An executing owner publishes its outstanding verdict jobs through queue
// health, bounded at 64; a comparison-only owner has no such row.
func TestOwnerPublishesTheVerdictQueue(t *testing.T) {
	g := newOwnerFixture(t)
	if _, ok := g.start(previewOptions(g)).QueueStatuses(time.Now())["verdicts"]; ok {
		t.Fatal("a comparison-only owner reports verdict jobs")
	}
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	panel := newFakePanel("block")
	release := make(chan struct{})
	panel.hold = release
	o, _, _ := verdictOwner(t, f, blocks, panel)
	if q, ok := o.QueueStatuses(time.Now())["verdicts"]; !ok || q.Depth != 0 || q.Capacity != verdictPending || q.DepthUnit != "jobs" {
		t.Fatalf("idle verdict queue = %+v, %t", q, ok)
	}
	for i := range 6 {
		queuedAt(t, o, p, f.host, admission.SeverityHigh, fmt.Sprintf("2001:db8::%x", i+1))
	}
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if q := o.QueueStatuses(time.Now())["verdicts"]; q.Depth != 6 {
		t.Fatalf("verdict queue while asking = %+v", q)
	}
	close(release)
	readyAnswers(t, o, 6)
	if q := o.QueueStatuses(time.Now())["verdicts"]; q.Depth != 0 || q.LagSeconds != 0 {
		t.Fatalf("drained verdict queue = %+v", q)
	}
}
