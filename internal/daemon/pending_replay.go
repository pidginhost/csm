package daemon

import (
	"fmt"
	"os"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
)

// replayPendingFindings runs the batch parked by the previous shutdown
// through the normal dispatch pipeline: auto-response, history, correlation
// and alerting. Called once the dispatcher has been released, so the replay
// sees the same ordering as any live batch.
func (d *Daemon) replayPendingFindings() {
	if d.store == nil {
		return
	}
	err := d.store.ReplayPendingFindings(func(pending []alert.Finding) {
		active := make([]alert.Finding, 0, len(pending))
		for _, f := range pending {
			if !checks.IsRetiredThreatScoreFinding(f) {
				active = append(active, f)
			}
		}
		if len(active) == 0 {
			return
		}
		fmt.Fprintf(os.Stderr, "[%s] Replaying %d finding(s) left queued by the previous shutdown\n", ts(), len(active))
		d.dispatchBatch(active)
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] Cannot replay pending findings: %v\n", ts(), err)
	}
}
