package daemon

import (
	"fmt"
	"os"
)

// replayPendingFindings runs the batch parked by the previous shutdown
// through the normal dispatch pipeline: auto-response, history, correlation
// and alerting. Called once the dispatcher has been released, so the replay
// sees the same ordering as any live batch.
func (d *Daemon) replayPendingFindings() {
	if d.store == nil {
		return
	}
	pending, err := d.store.TakePendingFindings()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] Cannot replay pending findings: %v\n", ts(), err)
		return
	}
	if len(pending) == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "[%s] Replaying %d finding(s) left queued by the previous shutdown\n", ts(), len(pending))
	d.dispatchBatch(pending)
}
