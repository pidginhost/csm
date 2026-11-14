package checks

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"time"

	"github.com/pidginhost/csm/internal/admission"
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
	// ActionID preserves one admission identity across retries.
	ActionID string
	// FindingID is the original audit identity, captured before display truncation.
	// Empty means this decision has no originating finding.
	FindingID    string
	IP           string
	EngineReason string
	Reason       string
	TTL          time.Duration
	Source       string
	// LoginSpray marks a mail spray scan block. It does not charge the
	// durable scan budget; the scan loop counts it on its own budget.
	LoginSpray bool
	// Root is the admission evidence the block answers again, carried by
	// the derived path that applies it; Entry is that path's entry. The
	// zero root means the path kept none.
	Root  admission.Evidence
	Entry admission.Entry
	// RootFinding and RootErr preserve a planned local mint refusal.
	RootFinding alert.Finding
	RootErr     error
	// Check names the check behind the block for a path that kept neither
	// a root nor its finding, as a challenge routed without admission.
	Check string
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

// ErrAutoBlockDisabled is returned when auto_response.enabled or block_ips is
// off, or the originating detector is in observe mode.
// Like ErrNoIPBlocker it means the block did not happen.
var ErrAutoBlockDisabled = errors.New("automatic IP blocking is disabled")

// ErrBlockTakenByAdmission reports that legacy must not apply this block.
// It does not promise that admission applied or will apply it.
var ErrBlockTakenByAdmission = errors.New("block left to admission")

// ApplyBlock is the single chokepoint for auto-response IP blocks issued
// outside the scan loop (challenge escalation, central intel, incident
// spray). It performs the block and the same evidence bookkeeping a scan
// auto-block gets: threat-DB row, blocked-IPs tracker entry, auto_block
// finding with the Cloudflare coverage warning, and permanent-block
// escalation counting. The scan loop shares the inner implementation and
// keeps its own batch semantics (rate limit, pending queue) around it.
//
// auto_response.enabled and block_ips gate every source; with either off
// ApplyBlock refuses with ErrAutoBlockDisabled before reaching the engine.
//
// Non-scan sources deliberately neither consume nor enforce
// auto_response.max_blocks_per_hour: challenge escalation and central intel
// are already gated upstream, and letting them starve or be starved by the
// scan budget would change containment behavior.
func ApplyBlock(cfg *config.Config, req ApplyBlockRequest) (ApplyBlockResult, error) {
	check := req.Root.Check()
	if check == "" {
		check = req.RootFinding.Check
	}
	if check == "" {
		check = req.Check
	}
	// The switches gate every automatic block, not only scan blocks. The
	// engine's dry-run gate still applies below them.
	if !cfg.AutoResponse.Enabled || !cfg.AutoResponse.BlockIPs || !CheckResponseEnabled(cfg, check) {
		return ApplyBlockResult{Outcome: firewall.BlockOutcomeNoop}, ErrAutoBlockDisabled
	}
	// A trusted proxy carries every visitor behind it: refuse it as the
	// engine refuses infra, before admission is asked.
	if IsTrustedProxy(req.IP, cfg) {
		return ApplyBlockResult{Outcome: firewall.BlockOutcomeNoop}, fmt.Errorf("%w: %s is a trusted proxy", firewall.ErrIPProtected, req.IP)
	}
	if respondDerived(req, parseExpiry(cfg.AutoResponse.BlockExpiry)) {
		return ApplyBlockResult{Outcome: firewall.BlockOutcomeNoop}, ErrBlockTakenByAdmission
	}
	blocker := getIPBlocker()
	if blocker == nil {
		res := ApplyBlockResult{Outcome: firewall.BlockOutcomeNoop}
		observeBlockOutcome(res.Outcome, ErrNoIPBlocker, req.Source)
		return res, ErrNoIPBlocker
	}
	work := autoBlockQueues.acquire()
	defer work.finish()
	state := work.loadState(cfg.StatePath)
	attemptAt := autoBlockNow()
	res, err := applyBlockLocked(cfg, blocker, state, req, work.progress, func(err error) { work.directOutcome(req.IP, attemptAt, err) })
	// Derived paths retain the admitted root, the source finding or at least
	// its check. Keep that attribution on their notices as the scan path does.
	cause := alert.Cause{FindingID: req.Root.FindingID(), Check: req.Root.Check()}
	if cause.Check == "" && req.RootFinding.Check != "" {
		cause = alert.CauseOf(req.RootFinding)
	}
	if cause.Check == "" {
		cause.Check = req.Check
	}
	if req.FindingID != "" {
		cause.FindingID = req.FindingID
	}
	if cause != (alert.Cause{}) {
		for i := range res.Findings {
			res.Findings[i].Cause = &cause
		}
	}
	if !errors.Is(err, firewall.ErrIPProtected) {
		work.observe(err)
	}
	work.progress()
	work.saveState(cfg.StatePath, state)
	work.complete()
	return res, err
}

// AdmissionBlock is a block the admission owner applied, as its verified
// firewall row records it.
type AdmissionBlock struct {
	IP, Reason, Check, FindingID string
	BlockedAt, ExpiresAt         time.Time
}

// RecordAdmissionBlocks records blocks the admission owner applied where a
// legacy block is recorded: a tracker row, which netblock escalation
// counts, a permanent-block strike, and the Critical auto_block finding it
// returns for the caller's alert pipeline. A block already tracked at its
// expiry is skipped, so a repeated delivery changes nothing. It promotes
// nothing: a permanent block is not an admission response.
func RecordAdmissionBlocks(cfg *config.Config, blocks []AdmissionBlock) []alert.Finding {
	work := autoBlockQueues.acquire()
	defer work.finish()
	state, err := work.readState(cfg.StatePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "autoblock: %v; skipping admission bookkeeping\n", err)
		return nil
	}
	var fresh []AdmissionBlock
	for _, b := range blocks {
		work.progress()
		if slices.ContainsFunc(state.IPs, func(r blockedIP) bool { return r.IP == b.IP && r.ExpiresAt.Equal(b.ExpiresAt) }) {
			continue
		}
		state.IPs = append(state.IPs, blockedIP{IP: b.IP, FindingID: b.FindingID, Reason: b.Reason, BlockedAt: b.BlockedAt, ExpiresAt: b.ExpiresAt})
		fresh = append(fresh, b)
	}
	if len(fresh) == 0 {
		work.complete()
		return nil
	}
	// Commit duplicate markers before any best-effort side effects. A crash
	// may lose a strike or notice, but replay must never count it twice.
	work.progress()
	if err := work.writeState(cfg.StatePath, state); err != nil {
		logBlockStateFailure(cfg.StatePath, err)
		return nil
	}
	blocker := getIPBlocker()
	var findings []alert.Finding
	for _, b := range fresh {
		work.progress()
		details := fmt.Sprintf("Reason: %s", b.Reason)
		if cc, ok := blocker.(cloudflareCoverChecker); ok && cc.CloudflareCovers(b.IP) {
			details += " (warning: " + firewall.CloudflareCoverageWarning + ")"
		}
		findings = append(findings, alert.Finding{
			Severity:  alert.Critical,
			Check:     "auto_block",
			Message:   fmt.Sprintf("AUTO-BLOCK: %s blocked (expires in %s)", b.IP, b.ExpiresAt.Sub(b.BlockedAt)),
			Details:   details,
			Timestamp: time.Now(),
			SourceIP:  b.IP,
			Cause:     &alert.Cause{FindingID: b.FindingID, Check: b.Check},
		})
		permBlockStrike(cfg, b.IP, work.progress)
	}
	work.complete()
	return findings
}

// permBlockStrike counts a temporary block of ip toward permanent-block
// escalation and reports whether ip reached the configured count. A listed
// C2 server is no offender.
func permBlockStrike(cfg *config.Config, ip string, progress func()) bool {
	if !cfg.AutoResponse.PermBlock || c2Listed(cfg, ip) {
		return false
	}
	count, interval := permBlockLimits(cfg)
	progress()
	return checkPermBlockEscalation(cfg.StatePath, ip, count, interval)
}

// permBlockLimits is the configured permanent-block count and interval.
func permBlockLimits(cfg *config.Config) (int, time.Duration) {
	// Load fills the default and validation rejects anything lower, so
	// this only catches a Config assembled in code.
	count := cfg.AutoResponse.PermBlockCount
	if count < config.MinBlockEscalationCount {
		count = config.DefaultPermBlockCount
	}
	return count, parseExpiryWithDefault(cfg.AutoResponse.PermBlockInterval, config.DefaultPermBlockInterval)
}

// requestBlocker takes a full firewall request.
type requestBlocker interface {
	BlockIPRequest(firewall.ActionRequest, *firewall.ScanAdmission) (firewall.BlockOutcome, error)
}

// durableActionBlocker supplies atomic admission when the engine owns durable
// action state. The existing scan policy is passed to that transaction.
type durableActionBlocker interface {
	DurableActionsEnabled() bool
	requestBlocker
}

// applyBlockLocked performs one block attempt plus the evidence bookkeeping
// a live outcome requires. The caller holds blockStateMu and owns loading
// and saving state. It writes no stderr lines for live blocks - callers
// keep their own operational logging - and emits findings instead of
// dispatching them.
func applyBlockLocked(cfg *config.Config, blocker IPBlocker, state *blockState, req ApplyBlockRequest, progress func(), observe func(error)) (ApplyBlockResult, error) {
	progress()
	var outcome firewall.BlockOutcome
	var err error
	durableOutcome := false
	if durable, ok := blocker.(durableActionBlocker); ok && durable.DurableActionsEnabled() {
		durableOutcome = true
		var admission *firewall.ScanAdmission
		if req.Source == BlockSourceScan && !req.LoginSpray {
			limit := cfg.AutoResponse.MaxBlocksPerHour
			if limit <= 0 {
				limit = config.DefaultMaxBlocksPerHour
			}
			admission = &firewall.ScanAdmission{Window: autoBlockNow().Format("2006-01-02T15"), Limit: limit}
		}
		outcome, err = durable.BlockIPRequest(firewall.ActionRequest{
			ID: req.ActionID, Operation: "block", Target: req.IP, Reason: req.EngineReason,
			Source: req.Source, FindingID: req.FindingID, TTL: req.TTL, Actor: "daemon", Automatic: true,
			LoginSpray: req.LoginSpray,
		}, admission)
	} else if rb, ok := blocker.(requestBlocker); ok && req.LoginSpray {
		// The request BlockIPOutcomeWithFindingID sends, plus the flag the
		// engine needs to tag the row.
		outcome, err = rb.BlockIPRequest(firewall.ActionRequest{
			Operation: "block", Target: req.IP, Reason: req.EngineReason, TTL: req.TTL,
			FindingID: req.FindingID, Automatic: true, Actor: "daemon", LoginSpray: true,
		}, nil)
	} else {
		outcome, err = callBlockIP(blocker, req.IP, req.EngineReason, req.TTL, req.FindingID)
	}
	observe(err)
	observeBlockOutcome(outcome, err, req.Source)
	res := ApplyBlockResult{Outcome: outcome}
	verifiedAuditPending := durableOutcome && outcome == firewall.BlockOutcomeLive && errors.Is(err, firewall.ErrActionAuditPending)
	if err != nil && !verifiedAuditPending {
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
	progress()
	if db := GetThreatDB(); db != nil {
		db.AddTemporary(req.IP, req.Reason, req.TTL)
	}

	state.IPs = append(state.IPs, blockedIP{
		IP:         req.IP,
		FindingID:  req.FindingID,
		Reason:     req.Reason,
		BlockedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(req.TTL),
		LoginSpray: req.LoginSpray,
	})

	details := fmt.Sprintf("Reason: %s", req.Reason)
	progress()
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
	if permBlockStrike(cfg, req.IP, progress) {
		count, interval := permBlockLimits(cfg)
		permReason := fmt.Sprintf("PERMBLOCK: %d temp blocks within %s", count, interval)
		progress()
		if promoteToPermanentBlock(blocker, req.IP, permReason, req.FindingID) {
			res.Findings = append(res.Findings, alert.Finding{
				Severity:  alert.Critical,
				Check:     "auto_block",
				Message:   fmt.Sprintf("AUTO-PERMBLOCK: %s promoted to permanent block (%d temp blocks)", req.IP, count),
				Timestamp: time.Now(),
				SourceIP:  req.IP,
			})
		}
	}

	return res, err
}
