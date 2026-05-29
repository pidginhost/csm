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
// each other. The baseline sweep still uses checks.ForceAll to bypass
// throttles; dry-run state is scoped to RunAllDryRun.
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

	// Force-all bypasses throttles for the baseline sweep. Dry-run threads
	// through RunAllDryRun so a concurrent periodic scanner running in live
	// mode is never silenced by this caller.
	prevForceAll := checks.ForceAll
	checks.ForceAll = true
	defer func() { checks.ForceAll = prevForceAll }()

	cfg := c.d.currentCfg()
	findings, _ := checks.RunAllDryRun(cfg, c.d.store)
	c.d.store.SetBaseline(findings)

	binaryHash, err := integrity.HashFile(c.d.binaryPath)
	if err != nil {
		return nil, fmt.Errorf("hashing binary: %w", err)
	}
	configHash, confdHash, err := integrity.SignConfigFilePreserving(cfg.ConfigFile, cfg.ConfigDir, binaryHash)
	if err != nil {
		return nil, fmt.Errorf("saving integrity: %w", err)
	}
	cfg.Integrity.BinaryHash = binaryHash
	cfg.Integrity.ConfigHash = configHash
	cfg.Integrity.ConfdHash = confdHash

	return control.BaselineResult{
		Findings:       len(findings),
		HistoryCleared: histCount,
		BinaryHash:     binaryHash,
		ConfigHash:     cfg.Integrity.ConfigHash,
	}, nil
}
