package daemon

import (
	"fmt"
	"os"

	"github.com/pidginhost/csm/internal/alert"
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
		fmt.Fprintf(os.Stderr, "[%s] Replaying %d finding(s) left queued by the previous shutdown\n", ts(), len(pending))
		d.dispatchBatch(pending)
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] Cannot replay pending findings: %v\n", ts(), err)
	}
}
