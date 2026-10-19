//go:build linux

package learnwatch

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/pidginhost/csm/internal/antispam/hostfacts"
	"github.com/pidginhost/csm/internal/antispam/learn"
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
	for _, failure := range []error{learn.ErrStateIO, learn.ErrStateMismatch, learn.ErrBodyInvalid, learn.ErrPeer, hostfacts.ErrControllerNotSent, context.Canceled, errors.New("learning state unavailable")} {
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
