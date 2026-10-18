package admissionowner

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
)

// Opting out while work waits must not turn its expiry into a withheld
// response notice at startup or reload.
func TestOwnerDisabledWorkPrecedesBoundaryRevalidation(t *testing.T) {
	for _, boundary := range []string{"restart", "reload", "turn"} {
		for _, dry := range []bool{false, true} {
			t.Run(boundary+"/"+map[bool]string{false: "preview", true: "forecast"}[dry], func(t *testing.T) {
				withLiveExecution(t, false)
				p := withTestRegistry(t)
				f := newOwnerFixture(t)
				blocks := newFakeBlocks()
				o, reader, _ := policyOwner(t, f, blocks, validPolicy(1))
				id, _ := queuedAt(t, o, p, f.host, admission.SeverityCritical, "192.0.2.10")
				if boundary == "restart" {
					o.Stop()
				}
				f.host.advance(3 * time.Hour)
				next := validPolicy(2)
				next.DryRun = dry
				next.CeilingLimit--
				next.Allows = func(admission.Candidate) bool { return false }
				if boundary == "restart" {
					next.Epoch = 1
					o, _, _ = policyOwner(t, f, blocks, next)
				} else {
					reader.publish(next)
					if boundary == "reload" {
						if err := o.Reload(); err != nil {
							t.Fatal(err)
						}
					}
				}
				turn(t, o)
				if c := candidate(t, o, id); c.State != admission.StateRefused || c.Reason != admission.ReasonDisabled || c.Attempts != 0 {
					t.Errorf("disabled candidate = %s/%s, attempts %d", c.State, c.Reason, c.Attempts)
				}
				var notices []admission.NoticeRecord
				if err := o.do(func() (err error) { notices, err = o.ledger.PendingNotices(); return err }); err != nil || len(notices) != 0 {
					t.Fatalf("disabled work raised notices: %+v, %v", notices, err)
				}
				checks, applies := blocks.calls()
				if len(checks) != 0 || len(applies) != 0 || len(blocks.snapshots) != 0 || liveUsed(t, o) != 0 || f.db.DryRunBlocksCount() != 0 {
					t.Fatal("disabled work reached the engine or consumed capacity")
				}
			})
		}
	}
}
