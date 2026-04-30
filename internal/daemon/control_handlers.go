package daemon

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/integrity"
	"github.com/pidginhost/csm/internal/platform"
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
	case control.CmdBaseline:
		result, err = c.handleBaseline(req.Args)
	case control.CmdFirewallStatus:
		result, err = c.handleFirewallStatus(req.Args)
	case control.CmdFirewallPorts:
		result, err = c.handleFirewallPorts(req.Args)
	case control.CmdFirewallGrep:
		result, err = c.handleFirewallGrep(req.Args)
	case control.CmdFirewallAudit:
		result, err = c.handleFirewallAudit(req.Args)
	case control.CmdFirewallBlock:
		result, err = c.handleFirewallBlock(req.Args)
	case control.CmdFirewallUnblock:
		result, err = c.handleFirewallUnblock(req.Args)
	case control.CmdFirewallAllow:
		result, err = c.handleFirewallAllow(req.Args)
	case control.CmdFirewallRemoveAllow:
		result, err = c.handleFirewallRemoveAllow(req.Args)
	case control.CmdFirewallAllowPort:
		result, err = c.handleFirewallAllowPort(req.Args)
	case control.CmdFirewallRemovePort:
		result, err = c.handleFirewallRemovePort(req.Args)
	case control.CmdFirewallTempBan:
		result, err = c.handleFirewallTempBan(req.Args)
	case control.CmdFirewallTempAllow:
		result, err = c.handleFirewallTempAllow(req.Args)
	case control.CmdFirewallDenySubnet:
		result, err = c.handleFirewallDenySubnet(req.Args)
	case control.CmdFirewallRemoveSubnet:
		result, err = c.handleFirewallRemoveSubnet(req.Args)
	case control.CmdFirewallDenyFile:
		result, err = c.handleFirewallDenyFile(req.Args)
	case control.CmdFirewallAllowFile:
		result, err = c.handleFirewallAllowFile(req.Args)
	case control.CmdFirewallFlush:
		result, err = c.handleFirewallFlush(req.Args)
	case control.CmdFirewallRestart:
		result, err = c.handleFirewallRestart(req.Args)
	case control.CmdFirewallApplyConfirmed:
		result, err = c.handleFirewallApplyConfirmed(req.Args)
	case control.CmdFirewallConfirm:
		result, err = c.handleFirewallConfirm(req.Args)
	case control.CmdStoreExport:
		result, err = c.handleStoreExport(req.Args)
	case control.CmdHistorySince:
		result, err = c.handleHistorySince(req.Args)
	case control.CmdPHPRelayStatus:
		result, err = c.handlePHPRelayStatus(req.Args)
	case control.CmdPHPRelayIgnoreScript:
		result, err = c.handlePHPRelayIgnoreScript(req.Args)
	case control.CmdPHPRelayUnignore:
		result, err = c.handlePHPRelayUnignore(req.Args)
	case control.CmdPHPRelayIgnoreList:
		result, err = c.handlePHPRelayIgnoreList(req.Args)
	case control.CmdPHPRelayDryRun:
		result, err = c.handlePHPRelayDryRun(req.Args)
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
// purge-and-merge, then hand findings to the alert pipeline. When
// Alerts=false the handler absorbs the old `csm check*` behaviour:
// flip checks.DryRun to suppress auto-response for the duration of the
// run, append the raw findings to history, and return them in the
// response body so the CLI can render them verbatim.
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

	// dryRun ties together the three Alerts=false side effects: the
	// checks.DryRun toggle, the post-run history append, and the
	// FindingList in the response. Hoisting it makes the invariant
	// "these three happen together" visually obvious.
	dryRun := !args.Alerts

	if vErr := c.verifyTierRunIntegrity(); vErr != nil {
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

	// Dry-run mode: suppress auto-response globally for the duration
	// of this call. Mirrors the pre-phase-2 behaviour of `csm check*`
	// which set checks.DryRun=true before running. The toggle races
	// with the daemon's periodic scanners; during a long `csm check-deep`
	// a concurrent critical tick briefly sees DryRun=true and may
	// suppress auto-response for that tick.
	// TODO(phase-3): thread dry-run through checks.RunTier as a
	// parameter so concurrent scans don't clobber each other.
	if dryRun {
		prev := checks.DryRun
		checks.DryRun = true
		defer func() { checks.DryRun = prev }()
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

	// Dry-run history + FindingList: the live path writes history via
	// Daemon.runPeriodicChecks when the internal scanners fire; the
	// pre-phase-2 `csm check*` wrote it via store.AppendHistory in
	// cmd/csm/main.go. Preserve that quirk on the socket path.
	if dryRun {
		c.d.store.AppendHistory(findings)
	}

	newCount := len(c.d.store.FilterNew(findings))
	result := control.TierRunResult{
		Findings:    len(findings),
		NewFindings: newCount,
		ElapsedMs:   time.Since(start).Milliseconds(),
	}
	if dryRun {
		if findings == nil {
			result.FindingList = []alert.Finding{}
		} else {
			result.FindingList = findings
		}
	}
	return result, nil
}

func (c *ControlListener) verifyTierRunIntegrity() error {
	return integrity.Verify(c.d.binaryPath, c.d.currentCfg())
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

// handleHistorySince streams every history-bucket finding newer than
// the supplied cutoff. Used by `csm export --since` for SIEM backfill;
// the daemon-side bbolt cursor seek is materially faster than
// pagination + client-side filtering for hosts with large histories.
func (c *ControlListener) handleHistorySince(argsRaw json.RawMessage) (any, error) {
	var args control.HistorySinceArgs
	if len(argsRaw) > 0 {
		if err := json.Unmarshal(argsRaw, &args); err != nil {
			return nil, fmt.Errorf("parsing args: %w", err)
		}
	}
	if args.Since == "" {
		return nil, fmt.Errorf("since is required (RFC 3339)")
	}
	since, err := time.Parse(time.RFC3339, args.Since)
	if err != nil {
		return nil, fmt.Errorf("parsing since: %w", err)
	}
	sdb := store.Global()
	if sdb == nil {
		return nil, fmt.Errorf("bbolt store not available")
	}
	findings := sdb.ReadHistorySince(since)
	// ReadHistorySince returns newest-first; reverse for chronological
	// output so JSONL consumers see the same order they would from a
	// live tail.
	for i, j := 0, len(findings)-1; i < j; i, j = i+1, j-1 {
		findings[i], findings[j] = findings[j], findings[i]
	}
	return control.HistorySinceResult{Findings: findings}, nil
}

// handleStoreExport writes a tar+zstd backup containing the live bbolt
// snapshot, the state directory, and the signature-rules cache. The
// daemon is the single source of truth for paths; the CLI only supplies
// where to write the archive. Import deliberately does NOT route through
// the socket -- it requires a stopped daemon.
func (c *ControlListener) handleStoreExport(argsRaw json.RawMessage) (any, error) {
	var args control.StoreExportArgs
	if len(argsRaw) > 0 {
		if err := json.Unmarshal(argsRaw, &args); err != nil {
			return nil, fmt.Errorf("parsing args: %w", err)
		}
	}
	if args.DstPath == "" {
		return nil, fmt.Errorf("dst_path is required")
	}
	sdb := store.Global()
	if sdb == nil {
		return nil, fmt.Errorf("bbolt store not available")
	}
	cfg := c.d.currentCfg()
	hostname, _ := os.Hostname()
	pi := platform.Detect()

	res, err := sdb.Export(store.ExportOptions{
		StatePath: cfg.StatePath,
		RulesPath: cfg.Signatures.RulesDir,
		DstPath:   args.DstPath,
		Manifest: store.Manifest{
			CSMVersion:     c.d.version,
			SourceHostname: hostname,
			SourcePlatform: map[string]string{
				"os":         string(pi.OS),
				"os_version": pi.OSVersion,
				"panel":      string(pi.Panel),
				"webserver":  string(pi.WebServer),
			},
		},
	})
	if err != nil {
		return nil, err
	}
	return control.StoreExportResult{
		Path:          res.Path,
		Bytes:         res.Bytes,
		ArchiveSHA256: res.ArchiveSHA256,
		BboltSHA256:   res.BboltSHA256,
	}, nil
}
