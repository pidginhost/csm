package checks

import (
	"context"
	"sync"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

type ftpScanObservationKey struct{}

// A check can finish before the tier is cancelled by another check. Keep its
// cursor and findings together until the runner accepts the whole scan.
type ftpScanObservation struct {
	mu         sync.Mutex
	initialRaw string
	tracker    *ftpFailTracker
	findings   []alert.Finding
}

func (o *ftpScanObservation) prepare(initialRaw string, tracker *ftpFailTracker, findings []alert.Finding) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.initialRaw, o.tracker, o.findings = initialRaw, tracker, findings
}

func (o *ftpScanObservation) complete(ctx context.Context, cfg *config.Config, store *state.Store) []alert.Finding {
	o.mu.Lock()
	initialRaw, tracker, findings := o.initialRaw, o.tracker, o.findings
	o.tracker, o.findings = nil, nil
	o.mu.Unlock()
	if tracker == nil {
		return nil
	}

	ftpTrackerMu.Lock()
	currentRaw, _ := store.GetRaw(ftpTrackerKey)
	if currentRaw == initialRaw {
		defer ftpTrackerMu.Unlock()
		if ctx.Err() != nil {
			return nil
		}
		tracker.save(store)
		return findings
	}
	ftpTrackerMu.Unlock()

	// Another accepted scan advanced the cursor while this tier was running.
	// Re-read from its position so we neither restore stale counters nor
	// dispatch an already consumed burst. The retry commits directly.
	ctx = context.WithValue(ctx, ftpScanObservationKey{}, (*ftpScanObservation)(nil))
	return CheckFTPLogins(ctx, cfg, store)
}
