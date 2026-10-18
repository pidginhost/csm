package store

import (
	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// RefuseDisabled ends queued responses the current policy forbids before
// capacity scheduling. Like queue revalidation, it visits at most the
// durable queue bound. It cannot touch in-flight attempts or let disabled
// work consume the turns or capacity of allowed work. All endings commit
// together, including their counters and schema marker.
func (l *AdmissionLedger) RefuseDisabled(allows func(admission.Candidate) bool) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	now, err := l.clock()
	if err != nil {
		return err
	}
	return l.update("disabled", func(tx *bolt.Tx) error {
		q, err := l.openQueue(tx, now)
		if err != nil {
			return err
		}
		live, err := q.live()
		if err != nil {
			return err
		}
		for _, lc := range live {
			if lc.c.State == admission.StateQueued && !allows(lc.c) {
				if err = q.end(lc, admission.ReasonDisabled); err != nil {
					return err
				}
			}
		}
		return q.flush()
	})
}
