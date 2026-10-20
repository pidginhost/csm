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
			f := newWatch(t, 2)
			f.pass()
			f.deliver(1, "new", 1, spamBody)
			f.engine.respond = func(c learn.Candidate) (learn.Outcome, error) {
				if c.UID == f.accounts[0].UID {
					return learn.Outcome{Committed: []uint64{1}}, nil
				}
				return learn.Outcome{Deferred: true, Err: fmt.Errorf("learning unavailable: %w", failure)}, nil
			}
			for range MaxEntryErrors + 1 {
				f.deliver(0, "new", 1, spamBody)
				if r := f.pass(); r.Submitted != 1 || r.Pending != 1 || r.Skipped[SkipFailed] != 0 || f.pending(1) != 1 {
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

// Spec 7.5: backend failure leaves work pending. While nothing gets an
// answer, failures are not charged to the messages, however long it lasts.
func TestSchedulerBackendOutageKeepsReports(t *testing.T) {
	for _, outcomeError := range []bool{false, true} {
		t.Run(fmt.Sprintf("outcome=%t", outcomeError), func(t *testing.T) {
			f := newWatch(t, 1)
			f.pass()
			f.deliver(0, "new", 2, spamBody)
			f.engine.respond = func(learn.Candidate) (learn.Outcome, error) {
				err := fmt.Errorf("%w: %w", learn.ErrReadFailed, learn.ErrUncertain)
				if outcomeError {
					return learn.Outcome{Err: err}, nil
				}
				return learn.Outcome{}, err
			}
			for pass := range MaxEntryErrors + 2 {
				if r := f.pass(); r.Pending != 2 || r.Skipped[SkipFailed] != 0 || f.pending(0) != 2 {
					t.Fatalf("pass %d of an outage dropped a report: %+v", pass+1, r)
				}
				f.restart()
			}
			f.engine.respond = nil
			if r := f.pass(); r.Submitted != 2 || r.Pending != 0 {
				t.Fatalf("reports did not resume after the outage: %+v", r)
			}
		})
	}
}

// A controller can reject a body or find no digest without querying
// storage. Those replies must not spend other reports' error allowance.
func TestSchedulerPreQueryRepliesKeepOutageReports(t *testing.T) {
	for _, tc := range []struct {
		name  string
		reply string
	}{
		{"parse failure", `{"results":[],"errors":["cannot process message"],"complete":false,"distinct":0}`},
		{"hash failure", `{"results":[],"errors":["cannot hash message"],"complete":false,"distinct":0}`},
		{"digest limit", `{"results":[],"errors":["too many digests"],"complete":false,"distinct":65}`},
		{"no digest", `{"results":[],"errors":[],"complete":true,"distinct":0}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newWatch(t, 2)
			f.pass()
			f.deliver(1, "new", 2, spamBody)
			f.engine.respond = func(c learn.Candidate) (learn.Outcome, error) {
				if c.UID == f.accounts[1].UID {
					return learn.Outcome{Err: fmt.Errorf("%w: %w", learn.ErrReadFailed, learn.ErrUncertain)}, nil
				}
				insp, err := learn.ParseInspection([]byte(tc.reply), nil)
				if err != nil {
					if !errors.Is(err, learn.ErrMessageRejected) {
						t.Fatalf("unexpected inspection error: %v", err)
					}
					return learn.Outcome{Err: fmt.Errorf("%w: %w", learn.ErrReadFailed, err)}, nil
				}
				admission, err := learn.Assign(insp, learn.Source{UID: c.UID}, nil, nil)
				return learn.Outcome{Skips: admission.Skips, Err: err}, nil
			}
			for pass := range 2*MaxEntryErrors + 2 {
				f.now = f.now.Add(PassEvery)
				f.deliver(0, "new", 1, spamBody)
				if r := f.pass(); f.pending(1) != 2 {
					t.Fatalf("pass %d discarded reports during an outage: %+v", pass+1, r)
				}
				if got := countUID(f.engine.submitted(), f.accounts[1].UID); got != pass+1 {
					t.Fatalf("pass %d made %d total storage attempts", pass+1, got)
				}
				if err := f.cfg.State.View(func(tx StateTx) error {
					items, err := tx.Pending(FolderKey{UID: f.accounts[1].UID, Folder: ".spam"})
					for _, it := range items {
						if it.Errors != 0 {
							t.Errorf("pre-query reply charged an outage: %+v", it)
						}
					}
					return err
				}); err != nil {
					t.Fatal(err)
				}
				f.restart()
			}
			before := countUID(f.engine.submitted(), f.accounts[1].UID)
			f.engine.respond = nil
			if r := f.pass(); r.Pending != 0 || f.pending(1) != 0 ||
				countUID(f.engine.submitted(), f.accounts[1].UID) != before+2 {
				t.Fatalf("outage reports did not resume after recovery: %+v", r)
			}
		})
	}
}

// Rotation and fresh/retry alternation must let successful storage queries
// precede a poison report, even when another account's first turn defers.
func TestSchedulerMixedQueuesBoundPoisonReport(t *testing.T) {
	f := newWatch(t, 3)
	f.pass()
	const deferredBody = "Subject: waiting\r\n\r\nwaiting"
	f.deliver(1, "new", 1, deferredBody)
	healthy := 0
	f.engine.respond = func(c learn.Candidate) (learn.Outcome, error) {
		switch {
		case c.UID == f.accounts[0].UID:
			return learn.Outcome{Err: fmt.Errorf("%w: %w", learn.ErrReadFailed, learn.ErrUncertain)}, nil
		case string(c.Snapshot) == deferredBody:
			return learn.Outcome{Deferred: true}, nil
		case c.UID == f.accounts[2].UID:
			return learn.Outcome{Skips: []learn.Skip{{Reason: learn.SkipNoDigest}}}, nil
		default:
			healthy++
			return learn.Outcome{Committed: []uint64{1}}, nil
		}
	}
	if r := f.pass(); r.Pending != 1 {
		t.Fatalf("did not seed the retry queue: %+v", r)
	}
	f.deliver(0, "new", 1, spamBody)
	passes := 0
	for pass := range 2*MaxEntryErrors + 1 {
		passes++
		f.now = f.now.Add(PassEvery)
		f.deliver(1, "new", 1, spamBody)
		f.deliver(2, "new", 1, spamBody)
		r := f.pass()
		wantFailed := 0
		if healthy == MaxEntryErrors {
			wantFailed = 1
		}
		if pass < 2 && healthy != 0 || healthy > MaxEntryErrors ||
			f.pending(0) != 1-wantFailed || r.Skipped[SkipFailed] != wantFailed {
			t.Fatalf("pass %d: healthy=%d poison pending=%d report=%+v", pass+1, healthy, f.pending(0), r)
		}
		if err := f.cfg.State.View(func(tx StateTx) error {
			items, err := tx.Pending(FolderKey{UID: f.accounts[0].UID, Folder: ".spam"})
			for _, it := range items {
				if it.Errors != healthy {
					t.Errorf("pass %d: poison charged %d times after %d successful queries", pass+1, it.Errors, healthy)
				}
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		f.restart()
		if wantFailed == 1 {
			break
		}
	}
	if healthy != MaxEntryErrors || f.pending(0) != 0 {
		t.Fatalf("poison report still pending after %d passes and %d healthy queries", passes, healthy)
	}
	before := countUID(f.engine.submitted(), f.accounts[0].UID)
	if before != passes {
		t.Fatalf("poison report attempted %d times in %d passes", before, passes)
	}
	if r := f.pass(); healthy != passes || r.Skipped[SkipFailed] != 0 ||
		countUID(f.engine.submitted(), f.accounts[0].UID) != before {
		t.Fatalf("failed report retried or healthy queue did not drain: healthy=%d report=%+v", healthy, r)
	}
}

// Fail closed: an error the scheduler cannot attribute to the host or the
// pass counts against the message once the backend answers others, so no
// message can stop other accounts' passes forever.
func TestSchedulerUnknownErrorCountsAgainstEntry(t *testing.T) {
	for _, outcomeError := range []bool{false, true} {
		t.Run(fmt.Sprintf("outcome=%t", outcomeError), func(t *testing.T) {
			f := newWatch(t, 2)
			f.pass()
			f.deliver(1, "new", 1, spamBody)
			f.engine.respond = func(c learn.Candidate) (learn.Outcome, error) {
				if c.UID != f.accounts[1].UID {
					return learn.Outcome{Committed: []uint64{1}}, nil
				}
				err := errors.New("unexpected learner failure")
				if outcomeError {
					return learn.Outcome{Err: err}, nil
				}
				return learn.Outcome{}, err
			}
			for attempt := range MaxEntryErrors {
				f.deliver(0, "new", 1, spamBody)
				pending, failed := 1, 0
				if attempt == MaxEntryErrors-1 {
					pending, failed = 0, 1
				}
				if r := f.pass(); r.Submitted != 1 || r.Pending != pending || r.Skipped[SkipFailed] != failed || f.pending(1) != pending {
					t.Fatalf("attempt %d: unexpected retry accounting: %+v", attempt+1, r)
				}
				f.restart()
			}
			if r := f.pass(); r.Submitted != 0 || r.Pending != 0 || r.Skipped[SkipFailed] != 0 {
				t.Fatalf("failed report was retried: %+v", r)
			}
			if got := countUID(f.engine.submitted(), f.accounts[1].UID); got != MaxEntryErrors {
				t.Fatalf("submitted %d times", got)
			}
		})
	}
}
