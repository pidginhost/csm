package daemon

import (
	"encoding/json"
	"fmt"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/integrity"
	"github.com/pidginhost/csm/internal/store"
)

// handleBaseline clears existing state and captures the current host as
// the new known-good reference. Mirrors the old `csm baseline` flow but
// runs inside the daemon so no external lock coordination is needed.
//
// Concurrency: a sync.Mutex on the daemon serialises baselines against
// each other. Race with the periodic critical/deep scanners through the
// checks.ForceAll / checks.DryRun globals is a pre-existing quirk
// documented in the phase 2 plan; not addressed here.
func (c *ControlListener) handleBaseline(argsRaw json.RawMessage) (any, error) {
	var args control.BaselineArgs
	if len(argsRaw) > 0 {
		if err := json.Unmarshal(argsRaw, &args); err != nil {
			return nil, fmt.Errorf("parsing args: %w", err)
		}
	}

	c.d.baselineMu.Lock()
	defer c.d.baselineMu.Unlock()

	histCount := 0
	if sdb := store.Global(); sdb != nil {
		histCount = sdb.HistoryCount()
	}

	if histCount > 0 && !args.Confirm {
		return control.BaselineResult{
			HistoryCleared: histCount,
			NeedsConfirm:   true,
		}, nil
	}

	// Scoped toggle of the globals so a panic in checks.RunAll still
	// restores them. These are read by the periodic scanners too; the
	// window is narrow but real. Out of scope for this change.
	prevForceAll, prevDryRun := checks.ForceAll, checks.DryRun
	checks.ForceAll, checks.DryRun = true, true
	defer func() {
		checks.ForceAll, checks.DryRun = prevForceAll, prevDryRun
	}()

	cfg := c.d.currentCfg()
	findings := checks.RunAll(cfg, c.d.store)
	c.d.store.SetBaseline(findings)

	binaryHash, err := integrity.HashFile(c.d.binaryPath)
	if err != nil {
		return nil, fmt.Errorf("hashing binary: %w", err)
	}
	if err := integrity.SignAndSaveAtomic(cfg, binaryHash); err != nil {
		return nil, fmt.Errorf("saving integrity: %w", err)
	}

	return control.BaselineResult{
		Findings:       len(findings),
		HistoryCleared: histCount,
		BinaryHash:     binaryHash,
		ConfigHash:     cfg.Integrity.ConfigHash,
	}, nil
}
