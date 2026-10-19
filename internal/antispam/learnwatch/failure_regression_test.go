//go:build linux

package learnwatch

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/antispam/hostfacts"
	"github.com/pidginhost/csm/internal/antispam/learn"
	"github.com/pidginhost/csm/internal/store"
)

func TestSchedulerInterruptedSubmissionKeepsReport(t *testing.T) {
	for _, outcomeError := range []bool{false, true} {
		t.Run(fmt.Sprintf("outcome=%t", outcomeError), func(t *testing.T) {
			f := newWatch(t, 1)
			f.pass()
			f.deliver(0, "new", 1, spamBody)
			for range MaxEntryErrors + 1 {
				ctx, cancel := context.WithCancel(context.Background())
				f.engine.respond = func(learn.Candidate) (learn.Outcome, error) {
					cancel()
					err := fmt.Errorf("%w: %w", learn.ErrReadFailed, context.Canceled)
					if outcomeError {
						return learn.Outcome{Deferred: true, Err: err}, nil
					}
					return learn.Outcome{Deferred: true}, err
				}
				r := f.w.Pass(ctx)
				cancel()
				if r.Pending != 1 || r.Skipped[SkipFailed] != 0 || f.pending(0) != 1 {
					t.Fatalf("interrupted work consumed the message's retry allowance: %+v", r)
				}
				f.restart()
			}
			f.engine.respond = nil
			if r := f.pass(); r.Submitted != 1 || r.Pending != 0 {
				t.Fatalf("interrupted report did not resume: %+v", r)
			}
		})
	}
}

func TestSchedulerLearningStateFailureKeepsReport(t *testing.T) {
	for _, failure := range []error{learn.ErrStateIO, learn.ErrStateMismatch, learn.ErrBodyInvalid, learn.ErrPeer, hostfacts.ErrControllerNotSent, context.Canceled} {
		t.Run(failure.Error(), func(t *testing.T) {
			f := newWatch(t, 1)
			f.pass()
			f.deliver(0, "new", 1, spamBody)
			f.engine.respond = func(learn.Candidate) (learn.Outcome, error) {
				return learn.Outcome{Deferred: true, Err: fmt.Errorf("learning unavailable: %w", failure)}, nil
			}
			for range MaxEntryErrors + 1 {
				if r := f.pass(); r.Pending != 1 || r.Skipped[SkipFailed] != 0 || f.pending(0) != 1 {
					t.Fatalf("local backend failure discarded the report: %+v", r)
				}
				f.restart()
			}
			f.engine.respond = nil
			if r := f.pass(); r.Submitted != 1 || r.Pending != 0 {
				t.Fatalf("report did not resume after backend recovery: %+v", r)
			}
		})
	}
}

func TestSchedulerUnreadableLearningBindingKeepsReport(t *testing.T) {
	f := newWatch(t, 1)
	f.pass()
	f.deliver(0, "new", 1, spamBody)
	if err := f.db.LearnUpdate(func(tx store.LearnTx) error {
		return tx.Put(store.LearnMetaBucket, []byte("binding"), []byte("invalid JSON"))
	}); err != nil {
		t.Fatal(err)
	}
	// Binding fails before any body or controller access is allowed.
	e := learn.NewEngine(learn.EngineConfig{
		Ledger: learn.Open(f.db), HashGeneration: "generation", Prefix: "prefix", TickEvery: time.Hour,
	})
	e.SetGate(antispam.LearningGate{Install: true, Publish: true})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		e.Run(ctx)
	}()
	t.Cleanup(func() { cancel(); <-done })
	f.engine.respond = func(c learn.Candidate) (learn.Outcome, error) {
		return e.SubmitReport(context.Background(), c)
	}
	for range MaxEntryErrors + 1 {
		if r := f.pass(); r.Pending != 1 || r.Skipped[SkipFailed] != 0 || f.pending(0) != 1 {
			t.Fatalf("unreadable learning binding discarded the report: %+v", r)
		}
		f.restart()
	}
	if got := len(f.engine.submitted()); got != MaxEntryErrors+1 {
		t.Fatalf("attempted %d submissions, want %d", got, MaxEntryErrors+1)
	}
	f.engine.respond = nil
	if r := f.pass(); r.Submitted != 1 || r.Pending != 0 {
		t.Fatalf("held report did not resume with an available learner: %+v", r)
	}
}

func TestSchedulerGateClosureKeepsReport(t *testing.T) {
	f := newWatch(t, 1)
	f.pass()
	f.deliver(0, "new", 1, spamBody)
	f.engine.respond = func(learn.Candidate) (learn.Outcome, error) {
		f.submit = false
		return learn.Outcome{Deferred: true, Err: fmt.Errorf("%w: %w", learn.ErrReadFailed, learn.ErrUncertain)}, nil
	}
	for range MaxEntryErrors + 1 {
		f.submit = true
		if r := f.pass(); r.Pending != 1 || r.Skipped[SkipFailed] != 0 || f.pending(0) != 1 {
			t.Fatalf("reconciliation pause discarded the report: %+v", r)
		}
		f.restart()
	}
	f.submit, f.engine.respond = true, nil
	if r := f.pass(); r.Submitted != 1 || r.Pending != 0 {
		t.Fatalf("report did not resume after reconciliation: %+v", r)
	}
}

func TestSchedulerBackendRotationWaitsForSlowerAccount(t *testing.T) {
	for _, accounts := range []int{2, 3} {
		t.Run(fmt.Sprintf("accounts=%d", accounts), func(t *testing.T) {
			f := newWatch(t, accounts)
			f.cfg.FolderOpens = 4
			f.addMailbox(1, "example.com", "user")
			f.restart()
			f.pass()
			f.deliver(0, "new", 1, spamBody)
			f.deliver(1, "new", 1, spamBody)
			f.engine.respond = func(c learn.Candidate) (learn.Outcome, error) {
				if c.UID == f.accounts[0].UID {
					return learn.Outcome{Err: fmt.Errorf("%w: %w", learn.ErrReadFailed, learn.ErrUncertain)}, nil
				}
				return learn.Outcome{Committed: []uint64{1}}, nil
			}
			if r := f.pass(); r.Pending != 2 || len(f.engine.submitted()) != 1 {
				t.Fatalf("first pass did not stop at the failing account: %+v", r)
			}
			f.restart()
			if r := f.pass(); r.Submitted != 1 || countUID(f.engine.submitted(), 1002) != 1 {
				t.Fatalf("failing account overtook slower discovery after rotation: %+v, calls %v", r, f.engine.submitted())
			}
		})
	}
}

func TestSchedulerBackendRotationSurvivesDiscoveryDeadline(t *testing.T) {
	f := newWatch(t, 3)
	f.cfg.FolderOpens = 1
	f.addMailbox(0, "example.com", "user")
	f.addMailbox(2, "example.com", "user")
	f.restart()
	f.pass()
	for i := range f.accounts {
		f.deliver(i, "new", 1, spamBody)
	}
	failed := false
	f.engine.respond = func(c learn.Candidate) (learn.Outcome, error) {
		if c.UID == f.accounts[1].UID {
			failed = true
			return learn.Outcome{Err: fmt.Errorf("%w: %w", learn.ErrReadFailed, learn.ErrUncertain)}, nil
		}
		return learn.Outcome{Committed: []uint64{1}}, nil
	}
	turnHook = func(uid int, kind string) {
		if failed && uid == f.accounts[2].UID && kind == "turn" {
			f.now = f.now.Add(PassDeadline)
		}
	}
	if r := f.pass(); !failed || !r.Unfinished {
		t.Fatalf("pass did not expire during discovery after a backend failure: %+v", r)
	}
	if err := f.cfg.State.View(func(tx StateTx) error {
		cursor, err := tx.Cursor()
		if cursor != f.accounts[2].UID {
			t.Errorf("discovery deadline overwrote backend rotation: cursor=%d", cursor)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	turnHook = func(int, string) {}
	f.restart()
	if r := f.pass(); r.Submitted != 2 || countUID(f.engine.submitted(), 1003) != 1 {
		t.Fatalf("next pass did not serve accounts skipped by the backend failure: %+v, calls %v", r, f.engine.submitted())
	}
}

// Fail closed: an error the scheduler cannot attribute to the host or the
// pass counts against the message, so no message can stop passes forever.
func TestSchedulerUnknownErrorCountsAgainstEntry(t *testing.T) {
	for _, outcomeError := range []bool{false, true} {
		t.Run(fmt.Sprintf("outcome=%t", outcomeError), func(t *testing.T) {
			f := newWatch(t, 1)
			f.pass()
			f.deliver(0, "new", 1, spamBody)
			f.engine.respond = func(learn.Candidate) (learn.Outcome, error) {
				err := errors.New("unexpected learner failure")
				if outcomeError {
					return learn.Outcome{Err: err}, nil
				}
				return learn.Outcome{}, err
			}
			for attempt := range MaxEntryErrors {
				pending, failed := 1, 0
				if attempt == MaxEntryErrors-1 {
					pending, failed = 0, 1
				}
				if r := f.pass(); r.Submitted != 0 || r.Pending != pending || r.Skipped[SkipFailed] != failed || f.pending(0) != pending {
					t.Fatalf("attempt %d: unexpected retry accounting: %+v", attempt+1, r)
				}
				f.restart()
			}
			if r := f.pass(); r.Submitted != 0 || r.Pending != 0 || r.Skipped[SkipFailed] != 0 {
				t.Fatalf("failed report was retried: %+v", r)
			}
			if got := len(f.engine.submitted()); got != MaxEntryErrors {
				t.Fatalf("submitted %d times", got)
			}
		})
	}
}
