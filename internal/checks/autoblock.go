package checks

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/atomicio"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/mailranges"
	"github.com/pidginhost/csm/internal/store"
)

const (
	defaultBlockExpiry = "24h"
	blockStateFile     = "blocked_ips.json"

	// maxPendingBlocks bounds the retry queue. Under a sustained flood or
	// firewall outage the daemon can accumulate more distinct attacker IPs
	// than it can block; without a bound the queue grows without limit and
	// bloats blocked_ips.json. Overflow is named in stderr and surfaced as
	// a warning so the resulting loss is visible to operators.
	maxPendingBlocks = 1000

	// maxPendingAge drops queued entries whose evidence has gone stale: a
	// pending IP survives requeue cycles (rate limit, engine down, block
	// errors), and blocking hours after the triggering findings is worse
	// than not blocking. Two hours covers one full rate-limit window plus
	// slack for the queue to drain.
	maxPendingAge = 2 * time.Hour
)

// IPBlocker abstracts the firewall engine for auto-blocking.
// When set, blocks go through nftables firewall engine.
type IPBlocker interface {
	BlockIP(ip string, reason string, timeout time.Duration) error
	UnblockIP(ip string) error
	IsBlocked(ip string) bool
}

// outcomeBlocker is satisfied by engines that report what they actually
// did. When the wired IPBlocker supports it, the auto-block path uses the
// outcome to decide whether to apply local side effects: a dry-run or
// verdict-allowed call must not mutate blocked_ips.json, must not bump the
// hourly counter, and must not emit the operator-facing "AUTO-BLOCK"
// finding (which would falsely claim a real block landed). The plain
// IPBlocker interface stays as a back-compat fallback for tests and any
// legacy implementation.
type outcomeBlocker interface {
	BlockIPOutcome(ip, reason string, timeout time.Duration) (firewall.BlockOutcome, error)
}

// liveBlocker is satisfied by engines that can query the live kernel firewall
// state, not just an in-memory cache built from state.json. The tracker
// reconcile loop prefers this because the cache can drift when nft
// auto-expires entries faster than CSM rewrites state.json, or when an
// out-of-band flush dropped entries the cache still claims are live. Falls
// back to IPBlocker.IsBlocked when the live query is unavailable.
type liveBlocker interface {
	IsBlockedLive(ip string) (bool, error)
}

// liveBlockedLister is satisfied by engines that can dump their live blocked
// sets once per cycle. The reconcile pass prefers it over liveBlocker: the
// per-IP query dumps an entire family set on every call, so pruning N tracked
// IPs cost N full dumps of the same data.
type liveBlockedLister interface {
	LiveBlockedSet() (firewall.LiveBlockedSnapshot, error)
}

type subnetBlocker interface {
	BlockSubnet(cidr string, reason string, timeout time.Duration) error
}

// subnetBlockValidator is satisfied by firewall engines that can run their
// subnet safety and capability checks without changing firewall state. Dry-run
// notices use it so they only describe blocks the live path could attempt.
type subnetBlockValidator interface {
	ValidateSubnetBlock(cidr string) error
}

// cloudflareCoverChecker is satisfied by engines that can report whether an
// IP falls inside the Cloudflare allow ranges. The input chain accepts
// Cloudflare edges on TCP 80/443 before the blocked drop, so a block of a
// covered IP does not stop its web traffic; findings carry that caveat.
type cloudflareCoverChecker interface {
	CloudflareCovers(ip string) bool
}

// allowChecker is satisfied by engines that can report whether an IP is
// firewall-allowed (whitelisted). http_asn_crawl uses it at emit time to drop
// any candidate subnet that contains an observed source IP which is already
// allowed, so a surgical subnet tempban can never include a whitelisted host.
// Optional: blockers that do not implement it leave all candidate CIDRs intact.
type allowChecker interface {
	IsAllowed(ip string) bool
}

// permanentPromoter is satisfied by engines that can upgrade an existing
// temporary block to a permanent one. PermBlock escalation runs in the same
// scan cycle as the temp block that triggered it, so the ordinary block path
// (which skips an already-blocked IP and returns BlockOutcomeNoop) would never
// clear the kernel timeout and the "permanent" block would silently expire.
type permanentPromoter interface {
	PromoteToPermanentBlock(ip, reason string) error
}

type subnetBlockStatus interface {
	IsSubnetBlocked(cidr string) bool
}

// subnetManager is satisfied by firewall engines that expose their blocked
// subnet state and support targeted unblock calls. Used by
// PruneExemptAutoSubnets to enumerate and remove stale subnet blocks whose
// CIDR has become DoS-exempt.
type subnetManager interface {
	BlockedSubnets() []firewall.SubnetEntry
	UnblockSubnet(cidr string) error
}

// fwBlockerSlot wraps an IPBlocker so atomic.Pointer can store it. The
// extra struct layer is required because atomic.Pointer needs a
// concrete type and interfaces cannot be stored directly.
type fwBlockerSlot struct{ b IPBlocker }

var fwBlockerHolder atomic.Pointer[fwBlockerSlot]
var blockStateMu sync.Mutex
var autoBlockNow = time.Now

// SetIPBlocker installs the firewall engine for auto-blocking. Safe to
// call concurrently with AutoBlockIPs: each call publishes the new
// blocker atomically and any in-flight scan keeps the snapshot it
// already loaded.
func SetIPBlocker(b IPBlocker) {
	fwBlockerHolder.Store(&fwBlockerSlot{b: b})
}

// getIPBlocker returns the current blocker via a single atomic load.
// Callers should capture the result into a local variable and reuse it
// for the duration of one operation so a concurrent SetIPBlocker
// cannot split a single scan across two different engines.
func getIPBlocker() IPBlocker {
	slot := fwBlockerHolder.Load()
	if slot == nil {
		return nil
	}
	return slot.b
}

type blockedIP struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	BlockedAt time.Time `json:"blocked_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type pendingIP struct {
	IP     string `json:"ip"`
	Reason string `json:"reason"`
	// QueuedAt is when the IP first entered the queue; it survives
	// requeue cycles so age accumulates instead of resetting. Zero on
	// entries written by older builds (treated as fresh once, then
	// stamped on the first requeue).
	QueuedAt time.Time `json:"queued_at,omitempty"`
}

type blockState struct {
	IPs            []blockedIP `json:"ips"`
	Pending        []pendingIP `json:"pending,omitempty"` // IPs waiting for another block attempt
	CleanupPending []string    `json:"cleanup_pending,omitempty"`
	BlocksThisHour int         `json:"blocks_this_hour"`
	HourKey        string      `json:"hour_key"`
	// RateLimitWarnedHour is the HourKey for which the rate-limit warning
	// was already emitted. The warning reflects a steady-state condition,
	// not a per-IP event, so it fires once per hour window instead of on
	// every scan tick -- the per-tick emission flooded the audit log with
	// one identical finding every few seconds during a sustained attack.
	RateLimitWarnedHour string `json:"rate_limit_warned_hour,omitempty"`
	// PendingDropWarnedHour throttles queue-overflow findings independently
	// from rate-limit warnings. Engine-down and block-error retries can fill
	// the queue without reaching the hourly block limit.
	PendingDropWarnedHour string `json:"pending_drop_warned_hour,omitempty"`
}

// AutoBlockIPs processes findings and blocks attacker IPs via the firewall engine.
// Note: this should be called with ALL findings (not just new ones)
// for reputation-based blocking to work on repeat offenders.
func AutoBlockIPs(cfg *config.Config, findings []alert.Finding) []alert.Finding {
	if !cfg.AutoResponse.Enabled || !cfg.AutoResponse.BlockIPs {
		return nil
	}
	blockStateMu.Lock()
	defer blockStateMu.Unlock()

	// Snapshot the wired firewall engine ONCE per call. A concurrent
	// SetIPBlocker (SIGHUP re-wire, test cleanup) can swap the global
	// mid-scan; reading the atomic pointer once and reusing the
	// returned value keeps every block decision in this batch routed
	// to the same engine. The previous unsynchronized read of the
	// global also tripped the race detector.
	blocker := getIPBlocker()

	// One bulk dump of the kernel's blocked sets answers every membership
	// question this cycle asks. The per-IP live query dumps the whole set, so
	// the reconcile pass below cost one full dump per tracked IP.
	var liveBlocked firewall.LiveBlockedSnapshot
	var useLiveBlocked bool
	if blocker != nil {
		liveBlocked, useLiveBlocked = liveBlockedSnapshot(blocker)
	}

	// exemptLogged deduplicates per-cycle log lines for DoS-exempt CIDR skips
	// so each suppressed subnet is logged once per AutoBlockIPs call, not once
	// per finding or per IP in the netblock counting sweep.
	exemptLogged := make(map[string]struct{})

	var actions []alert.Finding

	// Load block state
	state := loadBlockState(cfg.StatePath)

	// Prune IPs that the firewall engine no longer has blocked.
	// The engine handles expiry natively via nftables timeouts -
	// we just sync our state to match. Use the live nftables query
	// when the engine supports it so the tracker stays in lock-step
	// with the kernel; the in-memory cache (IsBlocked) can lag when
	// the kernel expires entries before state.json is rewritten.
	var stillBlocked []blockedIP
	for _, b := range state.IPs {
		if blocker != nil {
			if !blockedLiveOrCached(blocker, liveBlocked, useLiveBlocked, b.IP) {
				// Engine expired this block - clean up our state
				fmt.Fprintf(os.Stderr, "[%s] AUTO-UNBLOCK: %s removed (engine expired)\n", time.Now().Format("2006-01-02 15:04:05"), b.IP)
				continue
			}
		}
		stillBlocked = append(stillBlocked, b)
	}
	state.IPs = stillBlocked

	// Prune auto-response subnet blocks that now intersect the DoS-exempt set
	// before making new subnet decisions this cycle. Never in dry-run:
	// dry-run promises a read-only firewall and pruning is a kernel mutation.
	if blocker != nil && isAutoResponseActive(cfg) {
		PruneExemptAutoSubnets(cfg, blocker)
	}

	// Check rate limit
	currentHour := autoBlockNow().Format("2006-01-02T15")
	if state.HourKey != currentHour {
		state.HourKey = currentHour
		state.BlocksThisHour = 0
	}

	// Collect IPs to block from findings
	ipsToBlock := make(map[string]pendingIP)

	// Always blockable findings carry a confirmed attacker IP: thresholded
	// brute force, confirmed compromise, C2/reputation, or escalation.
	// Raw mailbox auth failures and account-only mail findings feed incident
	// grouping and thresholded trackers, but one row is not enough evidence
	// for a firewall block.
	alwaysBlock := map[string]bool{
		"wp_login_bruteforce":         true,
		"xmlrpc_abuse":                true,
		"http_request_flood":          true,
		"http_scanner_profile":        true,
		"http_claimed_bot_unverified": true,
		"http_ua_spoof":               true,
		"ftp_bruteforce":              true,
		"smtp_bruteforce":             true,
		"smtp_probe_abuse":            true,
		"mail_bruteforce":             true,
		"mail_account_compromised":    true,
		"admin_panel_bruteforce":      true,
		"ssh_login_unknown_ip":        true,
		"ssh_login_realtime":          true,
		"c2_connection":               true,
		"ip_reputation":               true,
		"local_threat_score":          true,
		"modsec_block_escalation":     true,
		"modsec_csm_block_escalation": true,
		"email_compromised_account":   true,
		"email_cloud_relay_abuse":     true,
		"waf_attack_blocked":          true,
	}

	// Only blockable when block_cpanel_logins is enabled (disabled by default).
	// cpanel_login / cpanel_login_realtime are deliberately absent: those
	// fire as Warning-level audit on every direct form login from a non-
	// infra IP and a single event is not brute-force evidence. Blocking on
	// one Warning turns a legitimate customer logging in from a new country
	// into a 24h lockout. Thresholded brute checks below stay blockable.
	cpanelWebmailChecks := map[string]bool{
		"cpanel_multi_ip_login":       true,
		"cpanel_file_upload_realtime": true,
		"api_auth_failure":            true,
		"api_auth_failure_realtime":   true,
		"webmail_bruteforce":          true,
		"webmail_login_realtime":      true,
		"ftp_login_realtime":          true,
		"ftp_auth_failure_realtime":   true,
	}

	// Drain pending queue first (IPs from prior rate-limited or failed
	// cycles). Stale entries are dropped by name so the audit trail shows
	// exactly which attackers aged out instead of being blocked.
	for _, p := range state.Pending {
		ip := normalizeBlockIP(p.IP)
		if ip == "" {
			fmt.Fprintf(os.Stderr, "auto-block: dropping invalid pending IP %q\n", p.IP)
			continue
		}
		p.IP = ip
		if !p.QueuedAt.IsZero() && autoBlockNow().Sub(p.QueuedAt) > maxPendingAge {
			fmt.Fprintf(os.Stderr, "auto-block: dropping stale pending %s (queued %s)\n",
				p.IP, p.QueuedAt.Format(time.RFC3339))
			continue
		}
		if !isAlreadyBlocked(state, p.IP) {
			ipsToBlock[p.IP] = p
		}
	}
	state.Pending = nil

	// Subnet fast-path: checks that represent a subnet directly.
	// Independent of the per-IP rate limit, because a single subnet block
	// replaces what would otherwise be hundreds of per-IP blocks.
	for _, f := range findings {
		if f.Check != "smtp_subnet_spray" && f.Check != "mail_subnet_spray" {
			continue
		}
		cidr := extractCIDRFromFinding(f)
		if cidr == "" {
			continue
		}
		if isSubnetAlreadyBlocked(blocker, cidr) {
			continue
		}
		if cidrIntersectsInfra(cfg, cidr) {
			continue
		}
		if shouldSkipAutoSubnet(cfg, cidr, exemptLogged) {
			continue
		}
		if !isAutoResponseActive(cfg) {
			if !canDryRunBlockSubnet(blocker, cidr) {
				continue
			}
			// Dry-run: same visibility contract as per-IP blocks - emit a
			// Warning notice instead of skipping silently.
			actions = append(actions, dryRunSubnetNotice(cidr, "", f.Message))
			continue
		}
		if blocker == nil {
			fmt.Fprintf(os.Stderr, "auto-block: firewall engine not available, skipping subnet %s\n", cidr)
			continue
		}
		sb, ok := blocker.(subnetBlocker)
		if !ok {
			fmt.Fprintf(os.Stderr, "auto-block: firewall engine does not support subnet blocking, skipping %s\n", cidr)
			continue
		}
		reason := fmt.Sprintf("CSM auto-block (subnet): %s", truncate(f.Message, 100))
		if err := sb.BlockSubnet(cidr, reason, parseExpiry(cfg.AutoResponse.BlockExpiry)); err != nil {
			fmt.Fprintf(os.Stderr, "auto-block: error blocking subnet %s: %v\n", cidr, err)
			continue
		}
		fmt.Fprintf(os.Stderr, "[%s] AUTO-BLOCK-SUBNET: %s blocked\n", time.Now().Format("2006-01-02 15:04:05"), cidr)
		actions = append(actions, alert.Finding{
			Severity:  alert.Critical,
			Check:     "auto_block",
			Message:   fmt.Sprintf("AUTO-BLOCK-SUBNET: %s blocked", cidr),
			Details:   fmt.Sprintf("Reason: %s", f.Message),
			Timestamp: time.Now(),
		})
	}

	// blockOnlyAtCritical marks checks whose sub-critical findings are
	// advisory annotations (e.g. an established multi-mailbox office source)
	// rather than confirmed-attacker evidence; those must never firewall.
	blockOnlyAtCritical := map[string]bool{
		"mail_account_compromised": true,
	}

	for _, f := range findings {
		isBlockable := alwaysBlock[f.Check]
		if !isBlockable && cfg.AutoResponse.BlockCpanelLogins && cpanelWebmailChecks[f.Check] {
			isBlockable = true
		}
		if !isBlockable {
			continue
		}
		if blockOnlyAtCritical[f.Check] && f.Severity != alert.Critical {
			continue
		}

		ip := extractIPFromFinding(f)
		if ip == "" {
			continue
		}

		// Never block infra IPs
		if isInfraIP(ip, cfg.InfraIPs) || ip == "127.0.0.1" {
			continue
		}

		// Don't re-block already blocked IPs.
		if isAlreadyBlocked(state, ip) || (blocker != nil && blockedLiveOrCached(blocker, liveBlocked, useLiveBlocked, ip)) {
			continue
		}

		// Skip IPs that are already being challenged, but do not let a
		// prior challenge suppress a later hard-block-only finding.
		if cl := GetChallengeIPList(); cl != nil && cl.Contains(ip) && shouldSkipAutoBlockForChallenge(cfg, f) {
			continue
		}

		// A drained pending entry keeps its QueuedAt when the same IP
		// recurs in fresh findings; only the reason is refreshed.
		if existing, ok := ipsToBlock[ip]; ok {
			existing.Reason = f.Message
			ipsToBlock[ip] = existing
		} else {
			ipsToBlock[ip] = pendingIP{IP: ip, Reason: f.Message}
		}
	}

	// Block IPs and queue candidates that cannot be attempted or completed.
	expiry := parseExpiry(cfg.AutoResponse.BlockExpiry)
	maxPerHour := cfg.AutoResponse.MaxBlocksPerHour
	if maxPerHour <= 0 {
		maxPerHour = config.DefaultMaxBlocksPerHour
	}
	// http_asn_crawl: surgical subnet tempban for confirmed Critical findings.
	// Each CIDR consumes one MaxBlocksPerHour slot. Independent of the per-IP
	// list but shares its hourly budget. Skips infra intersections and
	// already-blocked subnets; dry-run emits notices instead of blocking and
	// consumes no budget.
	if sb, ok := blocker.(subnetBlocker); ok {
		tempban := parseExpiry(cfg.AutoResponse.HTTPASNCrawlTempban)
		for _, f := range findings {
			if f.Check != "http_asn_crawl" || f.Severity != alert.Critical || len(f.CIDRs) == 0 {
				continue
			}
			for _, cidr := range f.CIDRs {
				if isSubnetAlreadyBlocked(blocker, cidr) || cidrIntersectsInfra(cfg, cidr) {
					continue
				}
				if shouldSkipAutoSubnet(cfg, cidr, exemptLogged) {
					continue
				}
				if !isAutoResponseActive(cfg) {
					if !canDryRunBlockSubnet(blocker, cidr) {
						continue
					}
					actions = append(actions, dryRunSubnetNotice(cidr, " (asn-crawl)", f.Message))
					continue
				}
				if state.BlocksThisHour >= maxPerHour {
					break
				}
				reason := fmt.Sprintf("CSM auto-block (asn-crawl): %s", truncate(f.Message, 100))
				if err := sb.BlockSubnet(cidr, reason, tempban); err != nil {
					fmt.Fprintf(os.Stderr, "auto-block: asn-crawl subnet %s: %v\n", cidr, err)
					continue
				}
				state.BlocksThisHour++
				actions = append(actions, alert.Finding{
					Severity:  alert.Critical,
					Check:     "auto_block",
					Message:   fmt.Sprintf("AUTO-BLOCK-SUBNET: %s blocked (asn-crawl)", cidr),
					Details:   fmt.Sprintf("Reason: %s", f.Message),
					Timestamp: time.Now(),
				})
			}
		}
	}

	rateLimited := false
	droppedPending := 0
	engineUnavailableRequeued := 0
	// requeue preserves an IP that could not be blocked this cycle (rate
	// limit, engine unavailable, transient block error). QueuedAt is
	// stamped on first entry so the drain's age check can retire it; the
	// bound keeps a sustained flood from growing the queue without limit,
	// and overflow drops are named so they remain identifiable in logs.
	requeue := func(p pendingIP) bool {
		if p.QueuedAt.IsZero() {
			p.QueuedAt = autoBlockNow()
		}
		if len(state.Pending) < maxPendingBlocks {
			state.Pending = append(state.Pending, p)
			return true
		}
		fmt.Fprintf(os.Stderr, "auto-block: pending queue full, dropping %s\n", p.IP)
		droppedPending++
		return false
	}
	for ip, cand := range ipsToBlock {
		if state.BlocksThisHour >= maxPerHour {
			requeue(cand)
			rateLimited = true
			continue
		}

		// Block via firewall engine (nftables)
		blockReason := fmt.Sprintf("CSM auto-block: %s", truncate(cand.Reason, 100))
		if blocker == nil {
			observeBlockOutcome(firewall.BlockOutcomeNoop, ErrNoIPBlocker, BlockSourceScan)
			if requeue(cand) {
				engineUnavailableRequeued++
			}
			continue
		}
		res, err := applyBlockLocked(cfg, blocker, state, ApplyBlockRequest{
			IP:           ip,
			EngineReason: blockReason,
			Reason:       cand.Reason,
			TTL:          expiry,
			Source:       BlockSourceScan,
		})
		if err != nil {
			// Protected IPs (the server's own interface or infra_ips) are
			// intentionally never blocked -- an expected no-op, not a failure.
			// The triggering finding still stands, so suspicious activity from a
			// protected address is still surfaced. Any other error is treated
			// as transient and the IP is requeued when capacity permits; the
			// age cap retires it if the failure persists.
			if !errors.Is(err, firewall.ErrIPProtected) {
				if requeue(cand) {
					fmt.Fprintf(os.Stderr, "auto-block: error blocking %s: %v (requeued)\n", ip, err)
				} else {
					fmt.Fprintf(os.Stderr, "auto-block: error blocking %s: %v (retry dropped)\n", ip, err)
				}
			}
			continue
		}
		actions = append(actions, res.Findings...)
		if res.Outcome != firewall.BlockOutcomeLive {
			continue
		}
		if blocker.IsBlocked(ip) {
			fmt.Fprintf(os.Stderr, "[%s] AUTO-BLOCK: %s blocked (expires in %s)\n", time.Now().Format("2006-01-02 15:04:05"), ip, expiry)
		}
		state.BlocksThisHour++
	}
	if engineUnavailableRequeued > 0 {
		fmt.Fprintf(os.Stderr, "auto-block: firewall engine not available, requeued %d IPs\n", engineUnavailableRequeued)
	}

	warnRateLimit := rateLimited && state.RateLimitWarnedHour != currentHour
	warnPendingDrop := droppedPending > 0 && state.PendingDropWarnedHour != currentHour
	if warnRateLimit || warnPendingDrop {
		var msg string
		if rateLimited {
			msg = fmt.Sprintf("Auto-block rate limit reached (%d/hour), %d IPs queued for next cycle", maxPerHour, len(state.Pending))
			if droppedPending > 0 {
				msg += fmt.Sprintf(", %d dropped (queue full)", droppedPending)
			}
		} else {
			msg = fmt.Sprintf("Auto-block pending queue full, %d IPs queued for retry, %d dropped", len(state.Pending), droppedPending)
		}
		actions = append(actions, alert.Finding{
			Severity:  alert.Warning,
			Check:     "auto_block",
			Message:   msg,
			Timestamp: time.Now(),
		})
		if rateLimited {
			state.RateLimitWarnedHour = currentHour
		}
		if droppedPending > 0 {
			state.PendingDropWarnedHour = currentHour
		}
	}

	// Subnet auto-blocking: detect per-family subnet patterns. Runs in
	// dry-run too so escalations that would fire (from live blocks recorded
	// before dry-run was enabled) surface as notices.
	if cfg.AutoResponse.NetBlock && blocker != nil {
		// Load fills the default and validation rejects anything lower, so
		// this only catches a Config assembled in code.
		threshold := cfg.AutoResponse.NetBlockThreshold
		if threshold < config.MinBlockEscalationCount {
			threshold = config.DefaultNetBlockThreshold
		}
		subnetExpiry := parseExpiry(cfg.AutoResponse.BlockExpiry)
		// Count blocked IPs per subnet (IPv4 /24, IPv6 /64).
		subnetCounts := make(map[string]int)
		subnetBlocked := make(map[string]bool)
		for _, b := range state.IPs {
			cidr := subnetEscalationCIDR(b.IP)
			// Exempt IPs do not contribute toward the netblock threshold so that
			// a cluster of blocked addresses inside an operator-declared DoS-exempt
			// range cannot inadvertently auto-block that range as a subnet.
			if cidr != "" && !cidrIntersectsDOSExempt(cfg, cidr) {
				subnetCounts[cidr]++
			}
		}
		for cidr, count := range subnetCounts {
			if count >= threshold && !subnetBlocked[cidr] {
				if sb, ok := blocker.(subnetBlocker); ok {
					if isSubnetAlreadyBlocked(blocker, cidr) {
						continue
					}
					if cidrIntersectsInfra(cfg, cidr) {
						continue
					}
					if shouldSkipAutoSubnet(cfg, cidr, exemptLogged) {
						continue
					}
					if !isAutoResponseActive(cfg) {
						if !canDryRunBlockSubnet(blocker, cidr) {
							continue
						}
						subnetBlocked[cidr] = true
						actions = append(actions, alert.Finding{
							Severity:  alert.Warning,
							Check:     "auto_block",
							Message:   fmt.Sprintf("AUTO-NETBLOCK [dry-run]: %s would be blocked (%d IPs from same subnet)", cidr, count),
							Timestamp: time.Now(),
						})
						continue
					}
					reason := fmt.Sprintf("Auto-netblock: %d IPs from %s", count, cidr)
					if err := sb.BlockSubnet(cidr, reason, subnetExpiry); err == nil {
						subnetBlocked[cidr] = true
						fmt.Fprintf(os.Stderr, "[%s] AUTO-NETBLOCK: %s blocked (%d IPs from same subnet)\n", time.Now().Format("2006-01-02 15:04:05"), cidr, count)
						actions = append(actions, alert.Finding{
							Severity:  alert.Critical,
							Check:     "auto_block",
							Message:   fmt.Sprintf("AUTO-NETBLOCK: %s blocked (%d IPs from same subnet)", cidr, count),
							Timestamp: time.Now(),
						})
					}
				}
			}
		}
	}

	// Save state (expired IPs were already pruned at the top of this function)
	saveBlockState(cfg.StatePath, state)

	return actions
}

// isBlockedLiveOrCached returns the live nftables status when the
// blocker supports it, otherwise falls back to the cached IsBlocked
// view. The reconcile loop relies on this to prune blocked_ips.json
// entries the kernel has already expired even when state.json has not
// caught up yet. Live lookup errors keep the cached answer so transient
// netlink failures do not erase the local tracker.
func isBlockedLiveOrCached(b IPBlocker, ip string) bool {
	if lb, ok := b.(liveBlocker); ok {
		blocked, err := lb.IsBlockedLive(ip)
		if err == nil {
			return blocked
		}
	}
	return b.IsBlocked(ip)
}

// liveBlockedSnapshot takes one bulk membership snapshot for the cycle. A
// blocker that cannot produce one leaves callers on the legacy per-IP path.
// A failed bulk dump returns an uncovered snapshot so valid IPs use cached
// status without issuing the same failing dump once per tracked address.
func liveBlockedSnapshot(b IPBlocker) (firewall.LiveBlockedSnapshot, bool) {
	lister, ok := b.(liveBlockedLister)
	if !ok {
		return firewall.LiveBlockedSnapshot{}, false
	}
	snap, err := lister.LiveBlockedSet()
	if err != nil {
		// The snapshot still describes whichever families answered, so keep
		// it: discarding it would drop a healthy family to cached status
		// because the other one failed.
		fmt.Fprintf(os.Stderr, "auto-block: live blocked-set dump incomplete, using cached status for uncovered families: %v\n", err)
	}
	return snap, true
}

// blockedLiveOrCached answers from the cycle's bulk snapshot when it covers
// the IP's address family. An uncovered family uses cached status; retrying a
// live query would repeat the same set dump and could turn an unknown result
// into a false absence. Blockers without snapshot support retain the legacy
// per-IP live lookup.
func blockedLiveOrCached(b IPBlocker, snap firewall.LiveBlockedSnapshot, useSnap bool, ip string) bool {
	if useSnap {
		if blocked, known := snap.Contains(ip); known {
			return blocked
		}
		return b.IsBlocked(ip)
	}
	return isBlockedLiveOrCached(b, ip)
}

// callBlockIP dispatches to the outcome-reporting interface when the
// underlying blocker implements it, otherwise falls back to the legacy
// IPBlocker interface and assumes the call landed live (the behaviour
// every IPBlocker had before BlockIPOutcome existed). This keeps tests
// and any third-party implementations of IPBlocker working unchanged.
func callBlockIP(b IPBlocker, ip, reason string, timeout time.Duration) (firewall.BlockOutcome, error) {
	if ob, ok := b.(outcomeBlocker); ok {
		return ob.BlockIPOutcome(ip, reason, timeout)
	}
	if err := b.BlockIP(ip, reason, timeout); err != nil {
		return firewall.BlockOutcomeNoop, err
	}
	return firewall.BlockOutcomeLive, nil
}

// shouldSkipAutoBlockForChallenge reports whether an IP carrying this finding
// should be left for the challenge gate instead of hard-blocked. It is the
// exact inverse of responseActionForFinding resolving to a block, so the two
// auto-response paths share one decision.
func shouldSkipAutoBlockForChallenge(cfg *config.Config, f alert.Finding) bool {
	return responseActionForFinding(cfg, f) == responseChallenge
}

// promoteToPermanentBlock upgrades an existing temp block to permanent. The
// real engine implements permanentPromoter and clears the kernel timeout in
// place. Legacy blockers that only implement BlockIP have not marked the IP
// blocked in a way that trips skipExisting, so a fresh zero-timeout block on
// them lands live; that fallback preserves pre-existing behaviour for tests
// and third-party implementations.
func promoteToPermanentBlock(b IPBlocker, ip, reason string) bool {
	if pp, ok := b.(permanentPromoter); ok {
		if err := pp.PromoteToPermanentBlock(ip, reason); err != nil {
			fmt.Fprintf(os.Stderr, "auto-block: permblock promotion of %s failed: %v\n", ip, err)
			return false
		}
		return true
	}
	outcome, err := callBlockIP(b, ip, reason, 0)
	return err == nil && outcome == firewall.BlockOutcomeLive
}

func isSubnetAlreadyBlocked(b IPBlocker, cidr string) bool {
	sb, ok := b.(subnetBlockStatus)
	return ok && sb.IsSubnetBlocked(cidr)
}

// ExtractIPFromFinding extracts an IP address from a finding.
func ExtractIPFromFinding(f alert.Finding) string {
	return extractIPFromFinding(f)
}

func extractIPFromFinding(f alert.Finding) string {
	if strings.TrimSpace(f.SourceIP) != "" {
		return normalizeBlockIP(f.SourceIP)
	}

	msg := f.Message

	// Fallback for detectors that have not yet adopted the structured SourceIP
	// field. Only findings whose Check is auto-block-eligible reach this path,
	// and those detectors format their own messages with a CSM-parsed IP at the
	// tail. Use LastIndex so the rightmost (CSM-appended) IP wins over any
	// log-injected content earlier in the message.
	for _, sep := range []string{" from ", ": "} {
		if idx := strings.LastIndex(msg, sep); idx >= 0 {
			rest := msg[idx+len(sep):]
			fields := strings.Fields(rest)
			if len(fields) > 0 {
				candidate := strings.TrimRight(fields[0], ",:;)([]")
				if ip := normalizeBlockIP(candidate); ip != "" {
					return ip
				}
			}
		}
	}
	return ""
}

func normalizeBlockIP(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	}
	raw = strings.Trim(raw, "[]")
	ip := net.ParseIP(raw)
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
		return ""
	}
	return ip.String()
}

func isAlreadyBlocked(state *blockState, ip string) bool {
	for _, b := range state.IPs {
		if b.IP == ip {
			return true
		}
	}
	return false
}

func parseExpiry(s string) time.Duration {
	if s == "" {
		s = defaultBlockExpiry
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 24 * time.Hour
	}
	return d
}

func loadBlockState(statePath string) *blockState {
	state, err := readBlockState(statePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "autoblock: %v; ignoring queued blocks\n", err)
		return &blockState{}
	}
	return state
}

func readBlockState(statePath string) (*blockState, error) {
	path := filepath.Join(statePath, blockStateFile)
	data, err := osFS.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &blockState{}, nil
		}
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	state := &blockState{}
	if err := json.Unmarshal(data, state); err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return state, nil
}

func saveBlockState(statePath string, s *blockState) {
	_ = writeBlockState(statePath, s)
}

func writeBlockState(statePath string, s *blockState) error {
	path := filepath.Join(statePath, blockStateFile)
	if err := atomicio.AtomicWriteJSON(path, 0o600, s); err != nil {
		fmt.Fprintf(os.Stderr, "autoblock: persist %s failed: %v\n", path, err)
		return err
	}
	return nil
}

// subnetEscalationCIDR returns the canonical CIDR used by the
// auto-netblock escalation path for the given IP. IPv4 collapses to
// /24 (the historical block size); IPv6 collapses to /64 because most
// providers hand out /64 prefixes to end users -- /128 would let
// attackers rotate addresses inside the same /64 and never escalate,
// while a wider prefix would risk taking down legitimate neighbours.
// Returns "" for unparseable input.
func subnetEscalationCIDR(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	if ip4 := parsed.To4(); ip4 != nil {
		return fmt.Sprintf("%d.%d.%d.0/24", ip4[0], ip4[1], ip4[2])
	}
	ip16 := parsed.To16()
	if ip16 == nil {
		return ""
	}
	mask := net.CIDRMask(64, 128)
	network := ip16.Mask(mask)
	return (&net.IPNet{IP: network, Mask: mask}).String()
}

// --- Permanent block escalation (LF_PERMBLOCK) ---

type permBlockTracker struct {
	IPs map[string][]time.Time `json:"ips"` // IP -> list of block timestamps
}

// checkPermBlockEscalation records a new block and returns true if the IP
// has been temp-blocked count times within interval.
func checkPermBlockEscalation(statePath, ip string, count int, interval time.Duration) bool {
	tracker := loadPermBlockTracker(statePath)
	now := time.Now()
	cutoff := now.Add(-interval)

	// Add current block timestamp
	tracker.IPs[ip] = append(tracker.IPs[ip], now)

	// Clean old entries for this IP
	var recent []time.Time
	for _, t := range tracker.IPs[ip] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	tracker.IPs[ip] = recent

	// Clean old IPs entirely (haven't been seen in 2x the interval)
	for k, times := range tracker.IPs {
		if len(times) == 0 {
			delete(tracker.IPs, k)
			continue
		}
		latest := times[len(times)-1]
		if now.Sub(latest) > interval*2 {
			delete(tracker.IPs, k)
		}
	}

	savePermBlockTracker(statePath, tracker)

	return len(recent) >= count
}

func loadPermBlockTracker(statePath string) *permBlockTracker {
	tracker := &permBlockTracker{IPs: make(map[string][]time.Time)}
	path := filepath.Join(statePath, "permblock_tracker.json")
	data, err := osFS.ReadFile(path)
	if err == nil {
		if uerr := json.Unmarshal(data, tracker); uerr != nil {
			fmt.Fprintf(os.Stderr, "autoblock: %s is corrupt, ignoring escalation history: %v\n", path, uerr)
		}
		if tracker.IPs == nil {
			tracker.IPs = make(map[string][]time.Time)
		}
	}
	return tracker
}

func savePermBlockTracker(statePath string, tracker *permBlockTracker) {
	path := filepath.Join(statePath, "permblock_tracker.json")
	if err := atomicio.AtomicWriteJSON(path, 0o600, tracker); err != nil {
		fmt.Fprintf(os.Stderr, "autoblock: persist %s failed: %v\n", path, err)
	}
}

// AutoBlockFlushResult reports which phases of a coordinated firewall flush
// completed and whether its best-effort persisted-state snapshot was readable.
type AutoBlockFlushResult struct {
	Flushed      bool
	BlockedCount int
	SnapshotErr  error
}

// FlushAutoBlockState snapshots the engine's pre-flush IPs, runs an operator
// firewall flush, and clears the auto-block bookkeeping in one critical
// section. Without this the flush was self-reverting: surviving ThreatDB temp
// rows re-flagged every flushed IP through ip_reputation on the next scan and
// re-blocked it, and stale tracker entries suppressed re-block accounting.
// Tracker entries the engine never held are cleaned up too. Pending entries
// are kept - they are queued candidates, not blocks.
//
// The firewall mutation and cleanup stay serialized with AutoBlockIPs so a
// concurrent scan either finishes before the snapshot or starts after cleanup
// with fresh evidence. Result.Flushed is true with a non-nil error when the
// firewall was flushed but bookkeeping cleanup was only partial. SnapshotErr
// is advisory because the tracker-side union still covers tracked auto-blocks.
func FlushAutoBlockState(statePath string, flush func() error) (AutoBlockFlushResult, error) {
	blockStateMu.Lock()
	defer blockStateMu.Unlock()

	var result AutoBlockFlushResult
	engineState, snapshotErr := firewall.LoadState(statePath)
	result.SnapshotErr = snapshotErr
	var ips []string
	if snapshotErr == nil {
		result.BlockedCount = len(engineState.Blocked)
		ips = make([]string, 0, result.BlockedCount)
		for _, b := range engineState.Blocked {
			ips = append(ips, b.IP)
		}
	}
	if err := flush(); err != nil {
		return result, fmt.Errorf("flushing blocked IPs: %w", err)
	}
	result.Flushed = true

	var cleanupErr error
	state, err := readBlockState(statePath)
	seenCapacity := len(ips)
	if state != nil {
		seenCapacity += len(state.IPs) + len(state.CleanupPending)
	}
	seen := make(map[string]bool, seenCapacity)
	cleanupIPs := make([]string, 0, seenCapacity)
	addCleanupIP := func(ip string) {
		if !seen[ip] {
			seen[ip] = true
			cleanupIPs = append(cleanupIPs, ip)
		}
	}
	for _, ip := range ips {
		addCleanupIP(ip)
	}
	if err != nil {
		cleanupErr = errors.Join(cleanupErr, fmt.Errorf("reading auto-block state: %w", err))
	} else {
		for _, b := range state.IPs {
			addCleanupIP(b.IP)
		}
		for _, ip := range state.CleanupPending {
			addCleanupIP(ip)
		}
	}

	sdb := store.Global()
	tdb := GetThreatDB()
	failed := make([]string, 0)
	for _, ip := range cleanupIPs {
		if sdb != nil {
			if _, err := sdb.RemoveAutoBlock(ip); err != nil {
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("removing auto-block store row for %s: %w", ip, err))
				failed = append(failed, ip)
			}
		}
		if tdb != nil {
			tdb.RemoveTemporary(ip)
		}
	}
	if state != nil {
		state.IPs = nil
		// A failed bbolt cleanup must survive in the tracker after the
		// firewall state is empty, or a retry has no way to identify the
		// stale row that can recreate the block after restart.
		state.CleanupPending = failed
		if err := writeBlockState(statePath, state); err != nil {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("clearing auto-block state: %w", err))
		}
	}
	return result, cleanupErr
}

// dryRunSubnetNotice mirrors the per-IP dry-run notice for the subnet block
// paths so operators evaluating dry-run see subnet decisions instead of
// silence. The message deliberately differs from the live
// "AUTO-BLOCK-SUBNET:" token so alert-filter suppression never treats a
// notice as a real block.
func dryRunSubnetNotice(cidr, kind, reason string) alert.Finding {
	return alert.Finding{
		Severity:  alert.Warning,
		Check:     "auto_block",
		Message:   fmt.Sprintf("AUTO-BLOCK-SUBNET [dry-run]: %s would be blocked%s", cidr, kind),
		Details:   fmt.Sprintf("Reason: %s", reason),
		Timestamp: time.Now(),
	}
}

// canDryRunBlockSubnet applies the firewall engine's read-only preflight when
// available. A missing or incapable engine cannot make the claimed live block,
// so it must not produce a "would be blocked" notice.
func canDryRunBlockSubnet(blocker IPBlocker, cidr string) bool {
	if blocker == nil {
		fmt.Fprintf(os.Stderr, "auto-block: firewall engine not available, skipping dry-run subnet %s\n", cidr)
		return false
	}
	if _, ok := blocker.(subnetBlocker); !ok {
		fmt.Fprintf(os.Stderr, "auto-block: firewall engine does not support subnet blocking, skipping dry-run subnet %s\n", cidr)
		return false
	}
	if validator, ok := blocker.(subnetBlockValidator); ok {
		if err := validator.ValidateSubnetBlock(cidr); err != nil {
			fmt.Fprintf(os.Stderr, "auto-block: dry-run subnet %s rejected: %v\n", cidr, err)
			return false
		}
	}
	return true
}

// isAutoResponseActive reports whether real blocking should happen now:
// auto-response enabled, IP blocking on, and not in dry-run.
// DryRun defaults to true (safe) when nil — operators must explicitly set
// dry_run: false to enable live nftables blocking.
func isAutoResponseActive(cfg *config.Config) bool {
	return cfg.AutoResponse.Enabled && cfg.AutoResponse.BlockIPs && !cfg.AutoResponseDryRunEnabled()
}

// cidrIntersectsInfra reports whether the CIDR contains an operator infra
// IP/range (or loopback), so the subnet tempban never blackholes protected
// addresses. An unparseable CIDR fails safe (treated as intersecting and
// skipped). The firewall engine's dynamic per-IP allowlist is not
// enumerable across a subnet, so infra_ips is the operator's mechanism to
// exempt a specific address from subnet tempban.
func cidrIntersectsInfra(cfg *config.Config, cidr string) bool {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return true
	}
	if ipnet.IP.IsLoopback() {
		return true
	}
	candidates := append([]string{"127.0.0.1", "::1"}, cfg.InfraIPs...)
	for _, raw := range candidates {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if p := net.ParseIP(raw); p != nil && ipnet.Contains(p) {
			return true
		}
		if _, infraNet, err := net.ParseCIDR(raw); err == nil &&
			(ipnet.Contains(infraNet.IP) || infraNet.Contains(ipnet.IP)) {
			return true
		}
	}
	return false
}

// dosExemptNets returns the effective DoS-exempt networks (operator ranges
// union-ed with the current mail-provider overlay) split into IPv4 and IPv6
// slices. Delegates to firewall.EffectiveDOSExemptNets so the same logic
// governs both nftables sets and auto-block guards.
func dosExemptNets(cfg *config.Config) (v4, v6 []*net.IPNet) {
	var fc *firewall.FirewallConfig
	if cfg != nil {
		fc = cfg.Firewall
	}
	return firewall.EffectiveDOSExemptNets(fc, mailranges.ProviderNets())
}

// cidrIntersectsDOSExempt reports whether the CIDR overlaps any DoS-exempt
// network, so the subnet tempban never blocks exempt sources (e.g., operator-
// designated ranges or known mail-provider egress). An unparseable CIDR fails
// safe (treated as intersecting, block skipped).
func cidrIntersectsDOSExempt(cfg *config.Config, cidr string) bool {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return true // fail-safe: skip block when CIDR is unreadable
	}
	v4, v6 := dosExemptNets(cfg)
	for _, exempt := range append(v4, v6...) { //nolint:gocritic // intentional inline join
		if ipnet.Contains(exempt.IP) || exempt.Contains(ipnet.IP) {
			return true
		}
	}
	return false
}

// shouldSkipAutoSubnet reports whether the auto-block path must suppress a
// BlockSubnet call for cidr because it intersects a DoS-exempt operator range.
// Logs once per CIDR per cycle (via the logged dedupe map) at stderr info level
// with reason dos_exempt_range. Returns true when the block must be suppressed.
// Manual operator subnet denies bypass this function entirely.
func shouldSkipAutoSubnet(cfg *config.Config, cidr string, logged map[string]struct{}) bool {
	if !cidrIntersectsDOSExempt(cfg, cidr) {
		return false
	}
	if _, already := logged[cidr]; !already {
		logged[cidr] = struct{}{}
		fmt.Fprintf(os.Stderr, "auto-block: skipping subnet %s (dos_exempt_range)\n", cidr)
	}
	return true
}

// PruneExemptAutoSubnets removes auto-response subnet blocks whose CIDR now
// intersects the DoS-exempt set (operator ranges or mail-provider overlay).
// Only entries with Source == firewall.SourceAutoResponse are touched; manual,
// CLI, web-UI, challenge, whitelist, dyndns, system, and unknown-source blocks
// are left untouched. If b does not implement subnetManager, returns 0.
// UnblockSubnet errors are logged and the entry is not counted as pruned.
func PruneExemptAutoSubnets(cfg *config.Config, b IPBlocker) int {
	sm, ok := b.(subnetManager)
	if !ok {
		return 0
	}
	pruned := 0
	for _, entry := range sm.BlockedSubnets() {
		if entry.Source != firewall.SourceAutoResponse {
			continue
		}
		if !cidrIntersectsDOSExempt(cfg, entry.CIDR) {
			continue
		}
		if err := sm.UnblockSubnet(entry.CIDR); err != nil {
			fmt.Fprintf(os.Stderr, "auto-block: prune exempt subnet %s: %v\n", entry.CIDR, err)
			continue
		}
		pruned++
	}
	return pruned
}

// extractCIDRFromFinding returns the CIDR appearing in the message after
// the canonical " from " separator. Returns "" if the value does not parse
// as a CIDR.
func extractCIDRFromFinding(f alert.Finding) string {
	msg := f.Message
	idx := strings.LastIndex(msg, " from ")
	if idx < 0 {
		return ""
	}
	rest := msg[idx+len(" from "):]
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return ""
	}
	candidate := strings.TrimRight(fields[0], ",:;)([]")
	_, ipnet, err := net.ParseCIDR(candidate)
	if err != nil {
		return ""
	}
	return ipnet.String()
}
