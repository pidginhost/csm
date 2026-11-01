//go:build linux

package learnwatch

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/pidginhost/csm/internal/antispam/learn"
)

// A failed probe is current evidence of an outage, even if an earlier
// report got an answer. It must spare the report and stop submissions.
func TestSchedulerFailedProbeOverridesEarlierAnswer(t *testing.T) {
	for _, outcomeError := range []bool{false, true} {
		t.Run(fmt.Sprintf("outcome=%t", outcomeError), func(t *testing.T) {
			f := newWatch(t, 2)
			f.pass()
			f.deliver(1, "new", 2, poisonBody)
			f.engine.respond = func(c learn.Candidate) (learn.Outcome, error) {
				if c.UID == f.accounts[0].UID {
					return learn.Outcome{Committed: []uint64{1}}, nil
				}
				out, _ := failInspection(c)
				if outcomeError {
					return out, nil
				}
				return learn.Outcome{}, out.Err
			}
			f.engine.probe = func() error {
				if !f.w.answered {
					t.Fatal("probe did not follow a successful report")
				}
				return errors.New("storage does not answer")
			}
			for pass := range MaxEntryErrors + 1 {
				f.now = f.now.Add(PassEvery)
				f.deliver(0, "new", 1, spamBody)
				if r := f.pass(); r.Submitted != 1 || r.Pending != 2 || r.Skipped[SkipFailed] != 0 {
					t.Fatalf("pass %d: outage discarded a report: %+v", pass+1, r)
				}
				if got := countUID(f.engine.submitted(), f.accounts[1].UID); got != pass+1 {
					t.Fatalf("pass %d: outage did not stop submissions: %d attempts", pass+1, got)
				}
				if got := f.engine.probed(); got != pass+1 {
					t.Fatalf("pass %d: got %d probes", pass+1, got)
				}
				if err := f.cfg.State.View(func(tx StateTx) error {
					items, err := tx.Pending(FolderKey{UID: f.accounts[1].UID, Folder: ".spam"})
					for _, it := range items {
						if it.Errors != 0 {
							t.Errorf("failed probe charged the report %d times", it.Errors)
						}
					}
					return err
				}); err != nil {
					t.Fatal(err)
				}
				f.restart()
			}
			f.engine.respond, f.engine.probe = nil, nil
			if r := f.pass(); r.Submitted != 2 || r.Pending != 0 {
				t.Fatalf("reports did not resume after recovery: %+v", r)
			}
		})
	}
}

// The probe is another blocking call. Its success must not spend a
// report's allowance if the pass or either gate stopped in the meantime.
func TestSchedulerProbeInterruptionKeepsReport(t *testing.T) {
	for _, stop := range []string{"submit gate", "discover gate", "deadline", "context"} {
		t.Run(stop, func(t *testing.T) {
			f := newWatch(t, 1)
			discover := true
			f.cfg.CanDiscover = func() bool { return discover }
			f.restart()
			f.pass()
			f.deliver(0, "new", 1, poisonBody)
			f.engine.respond = failInspection
			for pass := range MaxEntryErrors + 1 {
				f.submit, discover = true, true
				f.now = f.now.Add(PassEvery)
				ctx, cancel := context.WithCancel(context.Background())
				f.engine.probe = func() error {
					switch stop {
					case "submit gate":
						f.submit = false
					case "discover gate":
						discover = false
					case "deadline":
						f.now = f.now.Add(PassDeadline)
					case "context":
						cancel()
					}
					return nil
				}
				r := f.w.Pass(ctx)
				cancel()
				if r.Pending != 1 || r.Skipped[SkipFailed] != 0 || poisonErrors(t, f) != 0 {
					t.Fatalf("pass %d: interrupted probe charged the report: %+v", pass+1, r)
				}
				if got := f.engine.probed(); got != pass+1 {
					t.Fatalf("pass %d: got %d probes", pass+1, got)
				}
				f.restart()
			}
			f.submit, discover = true, true
			f.engine.respond, f.engine.probe = nil, nil
			if r := f.pass(); r.Submitted != 1 || r.Pending != 0 {
				t.Fatalf("report did not resume after interruption: %+v", r)
			}
		})
	}
}
