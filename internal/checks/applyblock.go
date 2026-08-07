package checks

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
)

// Block sources label who asked for an auto-response block. They feed the
// outcome metric and let evidence rows say which pipeline produced them.
const (
	BlockSourceScan      = "scan"
	BlockSourceChallenge = "challenge"
	BlockSourceIncident  = "incident"
	BlockSourceCentral   = "central_intel"
)

// ApplyBlockRequest describes one auto-response IP block. EngineReason is
// handed to the firewall engine (its provenance inference keys on it);
// Reason is the human evidence recorded in the threat DB, the tracker, and
// findings.
type ApplyBlockRequest struct {
	IP           string
	EngineReason string
	Reason       string
	TTL          time.Duration
	Source       string
}

// ApplyBlockResult carries the engine outcome plus the auto_block findings
// the caller must route into its alert pipeline (scan batch or the daemon's
// async block recorder) so digests and alerting see every block source.
type ApplyBlockResult struct {
	Outcome  firewall.BlockOutcome
	Findings []alert.Finding
}

// ErrNoIPBlocker is returned when no firewall engine is wired. Callers must
// treat it as "the block did not happen", never as success.
var ErrNoIPBlocker = errors.New("firewall engine not available")

// ApplyBlock is the single chokepoint for auto-response IP blocks issued
// outside the scan loop (challenge escalation, central intel, incident
// spray). It performs the block and the same evidence bookkeeping a scan
// auto-block gets: threat-DB row, blocked-IPs tracker entry, auto_block
// finding with the Cloudflare coverage warning, and permanent-block
// escalation counting. The scan loop shares the inner implementation and
// keeps its own batch semantics (rate limit, pending queue) around it.
//
// Non-scan sources deliberately neither consume nor enforce
// auto_response.max_blocks_per_hour: challenge escalation and central intel
// are already gated upstream, and letting them starve or be starved by the
// scan budget would change containment behavior.
func ApplyBlock(cfg *config.Config, req ApplyBlockRequest) (ApplyBlockResult, error) {
	blocker := getIPBlocker()
	if blocker == nil {
		return ApplyBlockResult{}, ErrNoIPBlocker
	}
	blockStateMu.Lock()
	defer blockStateMu.Unlock()
	state := loadBlockState(cfg.StatePath)
	res, err := applyBlockLocked(cfg, blocker, state, req)
	saveBlockState(cfg.StatePath, state)
	return res, err
}

// applyBlockLocked performs one block attempt plus the evidence bookkeeping
// a live outcome requires. The caller holds blockStateMu and owns loading
// and saving state. It writes no stderr lines for live blocks - callers
// keep their own operational logging - and emits findings instead of
// dispatching them.
func applyBlockLocked(cfg *config.Config, blocker IPBlocker, state *blockState, req ApplyBlockRequest) (ApplyBlockResult, error) {
	outcome, err := callBlockIP(blocker, req.IP, req.EngineReason, req.TTL)
	observeBlockOutcome(outcome, err, req.Source)
	res := ApplyBlockResult{Outcome: outcome}
	if err != nil {
		return res, err
	}

	switch outcome {
	case firewall.BlockOutcomeLive:
		// nft was mutated; record the block below.
	case firewall.BlockOutcomeDryRun:
		// dry-run intercepted: nft was NOT mutated. Do not record a real
		// block locally or in the permanent threat DB; emit a Warning
		// notice instead so operators see what would have been blocked.
		res.Findings = append(res.Findings, alert.Finding{
			Severity:  alert.Warning,
			Check:     "auto_block",
			Message:   fmt.Sprintf("AUTO-BLOCK [dry-run]: %s would be blocked (expires in %s)", req.IP, req.TTL),
			Details:   fmt.Sprintf("Reason: %s", req.Reason),
			Timestamp: time.Now(),
			SourceIP:  req.IP,
		})
		return res, nil
	case firewall.BlockOutcomeAllowed, firewall.BlockOutcomeAllowlisted, firewall.BlockOutcomeNoop:
		// Allowed: the verdict callback deliberately declined. Allowlisted:
		// operator allow or verified bot. Noop: already blocked or guard
		// rejected. Nothing to record for any of them.
		return res, nil
	default:
		fmt.Fprintf(os.Stderr, "auto-block: unknown block outcome %q for %s, skipping local state\n", outcome, req.IP)
		return res, nil
	}

	// Record in the local threat DB with the same lifetime as the firewall
	// block. A permanent record here would re-flag the IP via ip_reputation
	// after the temp block lapses and re-block it forever (permablock loop).
	if db := GetThreatDB(); db != nil {
		db.AddTemporary(req.IP, req.Reason, req.TTL)
	}

	state.IPs = append(state.IPs, blockedIP{
		IP:        req.IP,
		Reason:    req.Reason,
		BlockedAt: time.Now(),
		ExpiresAt: time.Now().Add(req.TTL),
	})

	details := fmt.Sprintf("Reason: %s", req.Reason)
	if cc, ok := blocker.(cloudflareCoverChecker); ok && cc.CloudflareCovers(req.IP) {
		details += " (warning: " + firewall.CloudflareCoverageWarning + ")"
	}
	res.Findings = append(res.Findings, alert.Finding{
		Severity:  alert.Critical,
		Check:     "auto_block",
		Message:   fmt.Sprintf("AUTO-BLOCK: %s blocked (expires in %s)", req.IP, req.TTL),
		Details:   details,
		Timestamp: time.Now(),
		SourceIP:  req.IP,
	})

	// Permanent block escalation: promote after N temp blocks within the
	// interval. Every source counts - a challenge-timeout or central-intel
	// block is the same repeat-offender evidence as a scan block.
	if cfg.AutoResponse.PermBlock {
		count := cfg.AutoResponse.PermBlockCount
		if count < 2 {
			count = 4
		}
		interval := parseExpiry(cfg.AutoResponse.PermBlockInterval)
		if interval == 0 {
			interval = 24 * time.Hour
		}
		if checkPermBlockEscalation(cfg.StatePath, req.IP, count, interval) {
			permReason := fmt.Sprintf("PERMBLOCK: %d temp blocks within %s", count, interval)
			if promoteToPermanentBlock(blocker, req.IP, permReason) {
				res.Findings = append(res.Findings, alert.Finding{
					Severity:  alert.Critical,
					Check:     "auto_block",
					Message:   fmt.Sprintf("AUTO-PERMBLOCK: %s promoted to permanent block (%d temp blocks)", req.IP, count),
					Timestamp: time.Now(),
					SourceIP:  req.IP,
				})
			}
		}
	}

	return res, nil
}
