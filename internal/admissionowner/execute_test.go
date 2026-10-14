package admissionowner

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/store"
)

var _ BlockEngine = (*firewall.Engine)(nil)

// fakeBlocks is an engine whose answers the test scripts by address.
type fakeBlocks struct {
	mu       sync.Mutex
	refuse   map[string]firewall.BlockRefusal
	results  map[string]firewall.BlockResult
	checkErr error
	applyErr error
	// reject is how many coming batches the kernel rejects whole.
	reject       int
	markErr      error
	marks        int
	stateProbes  int
	shortResults bool
	shortChecks  bool
	checks       [][]firewall.BlockMember
	applies      [][]firewall.BlockMember
}

func newFakeBlocks() *fakeBlocks {
	return &fakeBlocks{refuse: map[string]firewall.BlockRefusal{}, results: map[string]firewall.BlockResult{}}
}

func (f *fakeBlocks) CheckBlockBatch(members []firewall.BlockMember) ([]firewall.BlockRefusal, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.checks = append(f.checks, append([]firewall.BlockMember(nil), members...))
	if f.checkErr != nil {
		return nil, f.checkErr
	}
	out := make([]firewall.BlockRefusal, len(members))
	for i, m := range members {
		out[i] = f.refuse[m.IP]
	}
	if f.shortChecks {
		return out[:len(out)-1], nil
	}
	return out, nil
}

func (f *fakeBlocks) ApplyBlockBatch(members []firewall.BlockMember) ([]firewall.BlockResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applies = append(f.applies, append([]firewall.BlockMember(nil), members...))
	if f.applyErr != nil {
		return nil, f.applyErr
	}
	out := make([]firewall.BlockResult, len(members))
	if f.reject > 0 {
		f.reject--
		for i := range out {
			out[i] = firewall.BlockResult{Effect: firewall.BlockFailed, Err: errors.Join(firewall.ErrBlockBatchRejected, errors.New("invalid argument"))}
		}
		return out, nil
	}
	for i, m := range members {
		r, ok := f.results[m.IP]
		if !ok {
			r = firewall.BlockResult{Effect: firewall.BlockApplied}
		}
		out[i] = r
		if r.Effect == firewall.BlockFailed && r.Refusal == firewall.BlockRefusedExisting {
			f.refuse[m.IP] = firewall.BlockRefusedExisting
		}
	}
	if f.shortResults {
		return out[:len(out)-1], nil
	}
	return out, nil
}

func (f *fakeBlocks) MarkBlockActionsUnverified(actions []string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.marks++
	return 0, f.markErr
}

func (f *fakeBlocks) ProbeBlockState() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stateProbes++
	return f.checkErr
}

func (f *fakeBlocks) probes() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.marks
}

func (f *fakeBlocks) set(fn func(*fakeBlocks)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

func (f *fakeBlocks) calls() (checks, applies [][]firewall.BlockMember) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.checks, f.applies
}

func executeOptions(f *ownerFixture, blocks *fakeBlocks) Options {
	opts := previewOptions(f)
	opts.Blocks = func() BlockEngine { return blocks }
	return opts
}

func candidate(t *testing.T, o *Owner, id admission.CandidateID) admission.Candidate {
	t.Helper()
	var c admission.Candidate
	if err := o.do(func() (err error) { c, err = o.ledger.Candidate(id); return err }); err != nil {
		t.Fatal(err)
	}
	return c
}

func attemptOf(t *testing.T, o *Owner, c admission.Candidate) admission.AttemptRecord {
	t.Helper()
	id, err := c.ID()
	if err != nil {
		t.Fatal(err)
	}
	next, err := admission.NewAttempt(id, c.Attempts)
	if err != nil {
		t.Fatal(err)
	}
	var a admission.AttemptRecord
	if err := o.do(func() (err error) { a, err = o.ledger.Attempt(next.ID); return err }); err != nil {
		t.Fatal(err)
	}
	return a
}

// With an engine, the turn runs its block picks as one batch: checked
// before anything is reserved, reserved and charged, recorded as running,
// applied and finished by effect. Each member names its attempt, its
// address, the check that asked for it and the expiry the configured
// response gives it.
func TestOwnerRunsBlockPicksAsOneBatch(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o := f.start(executeOptions(f, blocks))
	first, now := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	second, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.11")
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	checks, applies := blocks.calls()
	if len(checks) != 1 || len(applies) != 1 || len(applies[0]) != 2 {
		t.Fatalf("engine calls: %d checks, %d applies %v", len(checks), len(applies), applies)
	}
	for _, id := range []admission.CandidateID{first, second} {
		c := candidate(t, o, id)
		if c.State != admission.StateVerified || c.Disposition != admission.DispositionApplied || c.Attempts != 1 {
			t.Fatalf("candidate after the batch = %+v", c)
		}
		a := attemptOf(t, o, c)
		var member *firewall.BlockMember
		for i := range applies[0] {
			if applies[0][i].Action == string(a.Attempt.ID) {
				member = &applies[0][i]
			}
		}
		addr, _ := c.Key.Target.Addr()
		if member == nil || member.IP != addr.String() || member.Reason != "CSM auto-block: ssh_brute" || !member.ExpiresAt.Equal(now.Add(24*time.Hour)) {
			t.Fatalf("member for %s = %+v", addr, member)
		}
	}
	s := ledgerStatus(t, o)
	if outcomes(s, admission.DispositionApplied) != 2 || outcomes(s, admission.DispositionObserve) != 0 || s.Ceiling.General.Used != 2 {
		t.Fatalf("applied %d, observed %d, general charges %d", outcomes(s, admission.DispositionApplied), outcomes(s, admission.DispositionObserve), s.Ceiling.General.Used)
	}
}

// A member the engine refuses before reservation takes no charge: a full
// set defers it, an existing or invalid effect, an address that can never
// be blocked or a lifetime that has run out ends it. A refusal the owner
// does not know leaves it queued for a later turn.
func TestOwnerMapsEngineRefusals(t *testing.T) {
	for refusal, want := range map[firewall.BlockRefusal]struct {
		state  admission.State
		reason admission.Reason
	}{
		firewall.BlockRefusedFull:        {admission.StateQueued, admission.ReasonSetFull},
		firewall.BlockRefusedExisting:    {admission.StateRefused, admission.ReasonExistingEffect},
		firewall.BlockRefusedPending:     {admission.StateQueued, admission.ReasonPendingRecovery},
		firewall.BlockRefusedInvalid:     {admission.StateRefused, admission.ReasonInvalid},
		firewall.BlockRefusedExpired:     {admission.StateDropped, admission.ReasonStale},
		firewall.BlockRefusedUnsupported: {admission.StateWithheld, admission.ReasonUnsupportedContainment},
		firewall.BlockRefusedProtected:   {admission.StateRefused, admission.ReasonProtected},
		firewall.BlockRefusedAllowed:     {admission.StateRefused, admission.ReasonProtected},
		firewall.BlockRefusedDuplicate:   {admission.StateQueued, 0},
	} {
		t.Run(string(refusal), func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			blocks.refuse["192.0.2.10"] = refusal
			o := f.start(executeOptions(f, blocks))
			id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
			if err := o.do(o.turn); err != nil {
				t.Fatal(err)
			}
			c := candidate(t, o, id)
			if c.State != want.state || c.Reason != want.reason || c.Attempts != 0 {
				t.Fatalf("candidate = state %s reason %s attempts %d, want %s %s 0", c.State, c.Reason, c.Attempts, want.state, want.reason)
			}
			if _, applies := blocks.calls(); len(applies) != 0 {
				t.Fatalf("a refused member was applied: %v", applies)
			}
			if s := ledgerStatus(t, o); s.Ceiling.General.Used != 0 {
				t.Fatalf("a refused member was charged: %d", s.Ceiling.General.Used)
			}
		})
	}
}

// Each member ends by its own effect: applied is applied, a proven failure
// keeps its charge and retries after the backoff, and an uncertain one ends
// unknown and holds its address.
func TestOwnerFinishesEachMemberByItsEffect(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	blocks.results["192.0.2.11"] = firewall.BlockResult{Effect: firewall.BlockFailed, Refusal: firewall.BlockRefusedFull}
	blocks.results["192.0.2.12"] = firewall.BlockResult{Effect: firewall.BlockUnknown, Err: errors.New("readback lost")}
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	applied, now := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	failed, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.11")
	unknown, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.12")
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if c := candidate(t, o, applied); c.State != admission.StateVerified {
		t.Fatalf("applied member = %+v", c)
	}
	// Only a proven existing block is checked again after its finish.
	if checks, _ := blocks.calls(); len(checks) != 1 {
		t.Fatalf("an ordinary failure rechecked the engine: %d checks", len(checks))
	}
	if c := candidate(t, o, failed); c.State != admission.StateQueued || c.Attempts != 1 || !c.NotBefore.After(now) || attemptOf(t, o, c).Disposition != admission.DispositionFailed {
		t.Fatalf("failed member = %+v", c)
	}
	if c := candidate(t, o, unknown); c.State != admission.StateUnknown {
		t.Fatalf("unknown member = %+v", c)
	}
	s := ledgerStatus(t, o)
	if s.Unresolved.Unknown != 1 || s.Ceiling.General.Used != 3 {
		t.Fatalf("unresolved %+v, general charges %d", s.Unresolved, s.Ceiling.General.Used)
	}
	// A failure the kernel did not reject retries in an ordinary batch.
	mono.advance(admission.RetryBackoff(1))
	f.host.advance(admission.RetryBackoff(1))
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.13")
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if _, applies := blocks.calls(); len(applies) != 2 || len(applies[1]) != 2 {
		t.Fatalf("batches = %v", applies)
	}
}

// A batch the ledger refuses to run dispatches nothing: its reserved
// attempts fail, keeping their charges, and the engine is not asked.
func TestOwnerFailsReservedMembersTheLedgerWillNotRun(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o := f.start(executeOptions(f, blocks))
	setOwnerHook(t, o, &executeLedger, func(*store.AdmissionLedger, []admission.ActionID) ([]admission.Intent, bool, error) {
		return nil, false, &admission.Error{Reason: admission.ReasonPendingRecovery, Detail: "held"}
	})
	id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	c := candidate(t, o, id)
	if c.State != admission.StateQueued || c.Attempts != 1 || attemptOf(t, o, c).Disposition != admission.DispositionFailed {
		t.Fatalf("candidate = %+v", c)
	}
	if _, applies := blocks.calls(); len(applies) != 0 {
		t.Fatalf("the engine ran a batch the ledger refused: %v", applies)
	}
	if s := ledgerStatus(t, o); s.Ceiling.General.Used != 1 {
		t.Fatalf("general charges %d, want the reservation's", s.Ceiling.General.Used)
	}
}

// An engine that refuses the whole batch wrote and sent nothing: every
// reserved member fails, and automatic execution holds on the cause (P8)
// while the turn itself goes on.
func TestOwnerFailsTheBatchTheEngineRefuses(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	blocks.applyErr = errors.New("blocked sets unavailable")
	o := f.start(executeOptions(f, blocks))
	id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	if err := o.do(o.turn); err != nil {
		t.Fatalf("turn = %v", err)
	}
	if held := executionHeld(t, o); !strings.Contains(held, "blocked sets unavailable") {
		t.Fatalf("execution held = %q", held)
	}
	if c := candidate(t, o, id); c.State != admission.StateQueued || c.Attempts != 1 || attemptOf(t, o, c).Disposition != admission.DispositionFailed {
		t.Fatalf("candidate = %+v", c)
	}
}

// Without a running firewall engine, block picks wait, deferred as an
// unavailable engine; they are neither run nor previewed.
func TestOwnerDefersBlocksWithoutAnEngine(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	opts := previewOptions(f)
	opts.Blocks = func() BlockEngine { return nil }
	o := f.start(opts)
	id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if c := candidate(t, o, id); c.State != admission.StateQueued || c.Reason != admission.ReasonEngineUnavailable || c.Attempts != 0 {
		t.Fatalf("candidate = %+v", c)
	}
	if n := outcomes(ledgerStatus(t, o), admission.DispositionObserve); n != 0 {
		t.Fatalf("observed %d", n)
	}
}

// Only block_ip picks run; a pick of another kind beside them is still an
// observe preview.
func TestOwnerPreviewsOtherKindsBesideABatch(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o := f.start(executeOptions(f, blocks))
	block, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	challenge, _ := queuedKind(t, o, p, f.host, admission.SeverityHigh, "192.0.2.11", admission.KindChallenge)
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if c := candidate(t, o, block); c.State != admission.StateVerified {
		t.Fatalf("block = %+v", c)
	}
	if c := candidate(t, o, challenge); c.State != admission.StateObserved {
		t.Fatalf("challenge = %+v", c)
	}
	if _, applies := blocks.calls(); len(applies) != 1 || len(applies[0]) != 1 {
		t.Fatalf("applies = %v", applies)
	}
}

// A batch the kernel rejected whole fails every member, charged. Each then
// retries alone, one per turn, so a member the kernel keeps rejecting
// cannot fail healthy ones again; other work waits, untouched, until the
// rejected members are done, and then batches again (P9).
func TestOwnerRetriesRejectedMembersAlone(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	blocks.reject = 1
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	var rejected []admission.CandidateID
	for _, addr := range []string{"192.0.2.10", "192.0.2.11", "192.0.2.12"} {
		id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, addr)
		rejected = append(rejected, id)
	}
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	for _, id := range rejected {
		if c := candidate(t, o, id); c.State != admission.StateQueued || c.Attempts != 1 {
			t.Fatalf("rejected member = %+v", c)
		}
	}
	mono.advance(admission.RetryBackoff(1))
	f.host.advance(admission.RetryBackoff(1))
	waiting, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.13")
	for turn := 1; turn <= 3; turn++ {
		mono.advance(batchEvery)
		if err := o.do(o.turn); err != nil {
			t.Fatal(err)
		}
		_, applies := blocks.calls()
		if len(applies) != 1+turn || len(applies[turn]) != 1 {
			t.Fatalf("turn %d batches = %v", turn, applies)
		}
		if c := candidate(t, o, waiting); c.State != admission.StateQueued || c.Attempts != 0 || c.Reason != 0 {
			t.Fatalf("turn %d: waiting work = %+v", turn, c)
		}
	}
	for _, id := range rejected {
		if c := candidate(t, o, id); c.State != admission.StateVerified || c.Attempts != 2 {
			t.Fatalf("retried member = %+v", c)
		}
	}
	if n := isolatedCount(t, o); n != 0 {
		t.Fatalf("%d still isolated after their outcomes", n)
	}
	later, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.14")
	mono.advance(batchEvery)
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if _, applies := blocks.calls(); len(applies) != 5 || len(applies[4]) != 2 {
		t.Fatalf("batches after the retries = %v", applies)
	}
	for _, id := range []admission.CandidateID{waiting, later} {
		if c := candidate(t, o, id); c.State != admission.StateVerified {
			t.Fatalf("batched again = %+v", c)
		}
	}
}

// Isolation ends at the candidate's expiry, whether or not it ran again.
func TestOwnerForgetsIsolationAtExpiry(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	blocks.reject = 1
	o := f.start(executeOptions(f, blocks))
	queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if isolatedCount(t, o) != 1 {
		t.Fatal("a rejected member was not isolated")
	}
	f.host.advance(25 * time.Hour)
	if err := o.do(o.turn); err != nil {
		t.Fatal(err)
	}
	if n := isolatedCount(t, o); n != 0 {
		t.Fatalf("%d isolated after the expiry", n)
	}
}

func isolatedCount(t *testing.T, o *Owner) (n int) {
	t.Helper()
	if err := o.do(func() error { n = len(o.isolated); return nil }); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestOwnerDoesNotDispatchExecutionReadback(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o := f.start(executeOptions(f, blocks))
	previous := executeLedger
	setOwnerHook(t, o, &executeLedger, func(l *store.AdmissionLedger, ids []admission.ActionID) ([]admission.Intent, bool, error) {
		batch, _, err := previous(l, ids)
		return batch, false, err
	})
	id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
	if err := o.do(o.turn); !errors.Is(err, admission.ErrTransitionConflict) {
		t.Fatalf("execution readback: %v", err)
	}
	_, applies := blocks.calls()
	if c := candidate(t, o, id); len(applies) != 0 || c.State != admission.StateUnknown || c.Attempts != 1 || attemptOf(t, o, c).Disposition != admission.DispositionUnknown {
		t.Fatalf("idempotent readback dispatched: %+v applies=%d", c, len(applies))
	}
}

func TestOwnerRunsEarlierGrantsAfterReservationError(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o := f.start(executeOptions(f, blocks))
	previous := reserveLedger
	calls := 0
	failure := errors.New("reservation store unavailable")
	setOwnerHook(t, o, &reserveLedger, func(l *store.AdmissionLedger, id admission.CandidateID, lane admission.Lane, expires time.Time) (admission.Candidate, admission.AttemptRecord, bool, error) {
		calls++
		if calls == 2 {
			return admission.Candidate{}, admission.AttemptRecord{}, false, failure
		}
		return previous(l, id, lane, expires)
	})
	ids := []admission.CandidateID{}
	for _, addr := range []string{"192.0.2.10", "192.0.2.11"} {
		id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, addr)
		ids = append(ids, id)
	}
	if err := o.do(o.turn); !errors.Is(err, failure) {
		t.Fatalf("partial reservation: %v", err)
	}
	_, applies := blocks.calls()
	verified, queued := 0, 0
	for _, id := range ids {
		c := candidate(t, o, id)
		switch c.State {
		case admission.StateVerified:
			if c.Attempts != 1 || attemptOf(t, o, c).Disposition != admission.DispositionApplied {
				t.Fatalf("granted member: %+v", c)
			}
			verified++
		case admission.StateQueued:
			if c.Attempts != 0 {
				t.Fatalf("unreserved member: %+v", c)
			}
			queued++
		default:
			t.Fatalf("member after partial grant: %+v", c)
		}
	}
	if calls != 2 || len(applies) != 1 || len(applies[0]) != 1 || verified != 1 || queued != 1 {
		t.Fatalf("partial batch: reserve=%d applies=%v verified=%d queued=%d", calls, applies, verified, queued)
	}
}

func TestOwnerFinishesLaterMembersAfterOneFinishFails(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o := f.start(executeOptions(f, blocks))
	previous := finishLedger
	calls := 0
	failure := errors.New("outcome store unavailable")
	setOwnerHook(t, o, &finishLedger, func(l *store.AdmissionLedger, id admission.ActionID, d admission.Disposition) (admission.Candidate, admission.AttemptRecord, error) {
		calls++
		if calls == 1 {
			return admission.Candidate{}, admission.AttemptRecord{}, failure
		}
		return previous(l, id, d)
	})
	ids := []admission.CandidateID{}
	for _, addr := range []string{"192.0.2.10", "192.0.2.11"} {
		id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, addr)
		ids = append(ids, id)
	}
	if err := o.do(o.turn); !errors.Is(err, failure) {
		t.Fatalf("finish failure: %v", err)
	}
	running, verified := 0, 0
	for _, id := range ids {
		c := candidate(t, o, id)
		if c.Attempts != 1 {
			t.Fatalf("attempt count: %+v", c)
		}
		switch c.State {
		case admission.StateExecuting:
			running++
		case admission.StateVerified:
			verified++
		default:
			t.Fatalf("finish outcome: %+v", c)
		}
	}
	if calls != 2 || running != 1 || verified != 1 {
		t.Fatalf("finishes=%d running=%d verified=%d", calls, running, verified)
	}
}

func TestOwnerIsolationFollowsQueueLifetime(t *testing.T) {
	for _, ending := range []string{"attempt_limit", "refusal", "age_out"} {
		t.Run(ending, func(t *testing.T) {
			p := withTestRegistry(t)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			blocks.reject = int(admission.MaxAttempts)
			opts := executeOptions(f, blocks)
			opts.Expiry = func(admission.Candidate) time.Duration { return 24 * time.Hour }
			o := f.start(opts)
			mono := heldMono(t, o)
			id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
			if err := o.do(o.turn); err != nil {
				t.Fatal(err)
			}
			if isolatedCount(t, o) != 1 {
				t.Fatal("retry was not isolated")
			}
			want := admission.StateFailed
			switch ending {
			case "attempt_limit":
				for range admission.MaxAttempts - 1 {
					mono.advance(2 * time.Second)
					f.host.advance(2 * time.Second)
					if err := o.do(o.turn); err != nil {
						t.Fatal(err)
					}
				}
			case "refusal":
				if err := o.do(func() error { blocks.refuse["192.0.2.10"] = firewall.BlockRefusedProtected; return nil }); err != nil {
					t.Fatal(err)
				}
				mono.advance(time.Second)
				f.host.advance(time.Second)
				if err := o.do(o.turn); err != nil {
					t.Fatal(err)
				}
				want = admission.StateRefused
			case "age_out":
				if c := candidate(t, o, id); !c.ExpiresAt.After(c.AgeOut) {
					t.Fatalf("bad age-out fixture: %+v", c)
				}
				mono.advance(admission.QueueAgeLimit + time.Second)
				f.host.advance(admission.QueueAgeLimit + time.Second)
				if err := o.do(o.turn); err != nil {
					t.Fatal(err)
				}
				want = admission.StateDropped
			}
			if c := candidate(t, o, id); c.State != want || isolatedCount(t, o) != 0 {
				t.Fatalf("terminal candidate retained isolation: %+v", c)
			}
		})
	}
}

// An existing block the engine proves only when the batch applies ends the
// attempt failed, with its charge, and the pick refused as an existing
// effect: nothing retries against the block that holds the address. On the
// last attempt the pick has failed already and simply stays failed.
func TestOwnerEndsAnExistingEffectFoundAtApply(t *testing.T) {
	for _, wantedAttempts := range []int{1, admission.MaxAttempts - 1, admission.MaxAttempts} {
		last := wantedAttempts == admission.MaxAttempts
		p := withTestRegistry(t)
		f := newOwnerFixture(t)
		blocks := newFakeBlocks()
		o := f.start(executeOptions(f, blocks))
		mono := heldMono(t, o)
		id, _ := queuedAt(t, o, p, f.host, admission.SeverityHigh, "192.0.2.10")
		retry := func() {
			mono.advance(admission.RetryBackoff(admission.MaxAttempts))
			f.host.advance(admission.RetryBackoff(admission.MaxAttempts))
		}
		attempts := 1
		if wantedAttempts > 1 {
			blocks.results["192.0.2.10"] = firewall.BlockResult{Effect: firewall.BlockFailed}
			for ; attempts < wantedAttempts; attempts++ {
				if err := o.do(o.turn); err != nil {
					t.Fatal(err)
				}
				retry()
			}
		}
		blocks.results["192.0.2.10"] = firewall.BlockResult{Effect: firewall.BlockFailed, Refusal: firewall.BlockRefusedExisting}
		if err := o.do(o.turn); err != nil {
			t.Fatalf("last attempt %t: %v", last, err)
		}
		c := candidate(t, o, id)
		want, reason := admission.StateRefused, admission.ReasonExistingEffect
		if last {
			want, reason = admission.StateFailed, 0
		}
		if c.State != want || c.Reason != reason || c.Attempts != uint32(attempts) || attemptOf(t, o, c).Disposition != admission.DispositionFailed {
			t.Fatalf("last attempt %t: candidate %s %s after %d attempts, want %s %s", last, c.State, c.Reason, c.Attempts, want, reason)
		}
		if s := ledgerStatus(t, o); s.Ceiling.General.Used != uint32(attempts) || executionHeld(t, o) != "" {
			t.Fatalf("last attempt %t: charges %d, held %q", last, s.Ceiling.General.Used, executionHeld(t, o))
		}
		retry()
		if err := o.do(o.turn); err != nil {
			t.Fatal(err)
		}
		if _, applies := blocks.calls(); len(applies) != attempts {
			t.Fatalf("last attempt %t: the pick retried against the block that holds it: %d batches", last, len(applies))
		}
		o.Stop()
		reopened := f.start(executeOptions(f, blocks))
		if got := candidate(t, reopened, id); got.State != want || got.Reason != reason || got.Attempts != uint32(attempts) {
			t.Fatalf("persisted ending failed reopening: %+v", got)
		}
	}
}
