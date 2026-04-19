package daemon

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/integrity"
	"github.com/pidginhost/csm/internal/store"
)

// dispatch parses a raw request line, routes to the right handler, and
// wraps the handler's (result, error) pair in the response envelope.
// Unknown commands fail cleanly rather than crash the listener.
func (c *ControlListener) dispatch(line []byte) control.Response {
	var req control.Request
	if err := json.Unmarshal(line, &req); err != nil {
		return control.Response{OK: false, Error: fmt.Sprintf("bad request: %v", err)}
	}

	var (
		result any
		err    error
	)
	switch req.Cmd {
	case control.CmdTierRun:
		result, err = c.handleTierRun(req.Args)
	case control.CmdStatus:
		result, err = c.handleStatus(req.Args)
	case control.CmdHistoryRead:
		result, err = c.handleHistoryRead(req.Args)
	case control.CmdRulesReload:
		result, err = c.handleRulesReload(req.Args)
	case control.CmdGeoIPReload:
		result, err = c.handleGeoIPReload(req.Args)
	default:
		return control.Response{OK: false, Error: fmt.Sprintf("unknown command: %q", req.Cmd)}
	}

	if err != nil {
		return control.Response{OK: false, Error: err.Error()}
	}
	payload, mErr := json.Marshal(result)
	if mErr != nil {
		return control.Response{OK: false, Error: "result marshal: " + mErr.Error()}
	}
	return control.Response{OK: true, Result: payload}
}

// parseTier maps the wire string onto the checks.Tier constants. Kept
// local to the listener so the protocol package does not depend on the
// checks package.
func parseTier(s string) (checks.Tier, error) {
	switch s {
	case "critical":
		return checks.TierCritical, nil
	case "deep":
		return checks.TierDeep, nil
	case "all", "":
		return checks.TierAll, nil
	}
	return "", fmt.Errorf("unknown tier: %q", s)
}

// handleTierRun runs a tier synchronously and reports the result. The
// flow mirrors Daemon.runPeriodicChecks: integrity verify, RunTier,
// purge-and-merge, then hand findings to the alert pipeline. The only
// deviation is that we return counts to the caller instead of nothing.
func (c *ControlListener) handleTierRun(argsRaw json.RawMessage) (any, error) {
	var args control.TierRunArgs
	if len(argsRaw) > 0 {
		if err := json.Unmarshal(argsRaw, &args); err != nil {
			return nil, fmt.Errorf("parsing args: %w", err)
		}
	}
	tier, err := parseTier(args.Tier)
	if err != nil {
		return nil, err
	}

	if vErr := integrity.Verify(c.d.binaryPath, c.d.cfg); vErr != nil {
		// Integrity failures are escalated through the normal alert
		// pipeline so the on-call path sees them regardless of who
		// kicked the tier run. The client also gets an error so the
		// systemd timer unit fails loudly.
		if args.Alerts {
			select {
			case c.d.alertCh <- alert.Finding{
				Severity:  alert.Critical,
				Check:     "integrity",
				Message:   fmt.Sprintf("BINARY/CONFIG TAMPER DETECTED: %v", vErr),
				Timestamp: time.Now(),
			}:
			default:
				atomic.AddInt64(&c.d.droppedAlerts, 1)
			}
		}
		return nil, fmt.Errorf("integrity verify failed: %w", vErr)
	}

	start := time.Now()
	findings := checks.RunTier(c.d.currentCfg(), c.d.store, tier)

	if len(findings) > 0 {
		c.d.store.PurgeAndMergeFindings(checks.PerfCheckNamesForTier(tier), findings)
		if args.Alerts {
			for _, f := range findings {
				if strings.HasPrefix(f.Check, "perf_") && f.Severity == alert.Warning {
					continue
				}
				select {
				case c.d.alertCh <- f:
				default:
					atomic.AddInt64(&c.d.droppedAlerts, 1)
				}
			}
		}
	}

	// FilterNew takes a snapshot under the state mutex; racing with the
	// dispatcher that will later process the same findings is fine —
	// both observe consistent state, we just report our view.
	newCount := len(c.d.store.FilterNew(findings))
	return control.TierRunResult{
		Findings:    len(findings),
		NewFindings: newCount,
		ElapsedMs:   time.Since(start).Milliseconds(),
	}, nil
}

// handleStatus reports what `csm status` historically printed from
// disk, sourced from the live daemon instead of re-opening the store.
func (c *ControlListener) handleStatus(_ json.RawMessage) (any, error) {
	latest := c.d.store.LatestFindings()
	latestTime := c.d.store.LatestScanTime()
	var latestStr string
	if !latestTime.IsZero() {
		latestStr = latestTime.UTC().Format(time.RFC3339)
	}

	var historyCount int
	if sdb := store.Global(); sdb != nil {
		historyCount = sdb.HistoryCount()
	}

	uptime := int64(0)
	if !c.d.startTime.IsZero() {
		uptime = int64(time.Since(c.d.startTime).Seconds())
	}

	return control.StatusResult{
		Version:        c.d.version,
		UptimeSec:      uptime,
		LatestScanTime: latestStr,
		LatestFindings: len(latest),
		HistoryCount:   historyCount,
		DroppedAlerts:  c.d.DroppedAlerts(),
	}, nil
}

// handleHistoryRead paginates bbolt history. Clamps Limit so a buggy
// client cannot ask for everything at once; 1000 is well above the
// dashboard page size.
func (c *ControlListener) handleHistoryRead(argsRaw json.RawMessage) (any, error) {
	var args control.HistoryReadArgs
	if len(argsRaw) > 0 {
		if err := json.Unmarshal(argsRaw, &args); err != nil {
			return nil, fmt.Errorf("parsing args: %w", err)
		}
	}
	if args.Limit <= 0 || args.Limit > 1000 {
		args.Limit = 100
	}
	if args.Offset < 0 {
		args.Offset = 0
	}
	findings, total := c.d.store.ReadHistory(args.Limit, args.Offset)
	return control.HistoryReadResult{Findings: findings, Total: total}, nil
}

// handleRulesReload replaces `kill -HUP $(pidof csm)`. Returns after
// the reload completes so the client can confirm it happened.
func (c *ControlListener) handleRulesReload(_ json.RawMessage) (any, error) {
	c.d.reloadSignatures()
	return map[string]string{"status": "reloaded"}, nil
}

// handleGeoIPReload is the GeoIP equivalent of rules.reload.
func (c *ControlListener) handleGeoIPReload(_ json.RawMessage) (any, error) {
	c.d.publishGeoIP()
	return map[string]string{"status": "reloaded"}, nil
}
