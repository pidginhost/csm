package checks

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
)

const (
	maxBlocksPerHour   = 50
	defaultBlockExpiry = "24h"
	blockStateFile     = "blocked_ips.json"
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

// liveBlocker is satisfied by engines that can query the live kernel
// firewall state, not just an in-memory cache built from state.json.
// The tracker reconcile loop prefers this because the cache can drift
// when nft auto-expires entries faster than CSM rewrites state.json,
// or when an out-of-band flush dropped entries the cache still claims
// are live. Falls back to IPBlocker.IsBlocked when the engine cannot
// query the kernel.
type liveBlocker interface {
	IsBlockedLive(ip string) bool
}

type subnetBlocker interface {
	BlockSubnet(cidr string, reason string, timeout time.Duration) error
}

type subnetBlockStatus interface {
	IsSubnetBlocked(cidr string) bool
}

var fwBlocker IPBlocker
var blockStateMu sync.Mutex

// SetIPBlocker sets the firewall engine for auto-blocking.
func SetIPBlocker(b IPBlocker) {
	fwBlocker = b
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
}

type blockState struct {
	IPs            []blockedIP `json:"ips"`
	Pending        []pendingIP `json:"pending,omitempty"` // IPs waiting for rate-limit reset
	BlocksThisHour int         `json:"blocks_this_hour"`
	HourKey        string      `json:"hour_key"`
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
		if fwBlocker != nil {
			if !isBlockedLiveOrCached(fwBlocker, b.IP) {
				// Engine expired this block - clean up our state
				fmt.Fprintf(os.Stderr, "[%s] AUTO-UNBLOCK: %s removed (engine expired)\n", time.Now().Format("2006-01-02 15:04:05"), b.IP)
				continue
			}
		}
		stillBlocked = append(stillBlocked, b)
	}
	state.IPs = stillBlocked

	// Check rate limit
	currentHour := time.Now().Format("2006-01-02T15")
	if state.HourKey != currentHour {
		state.HourKey = currentHour
		state.BlocksThisHour = 0
	}

	// Collect IPs to block from findings
	ipsToBlock := make(map[string]string) // ip -> reason

	// Always blockable findings carry a confirmed attacker IP: thresholded
	// brute force, confirmed compromise, C2/reputation, or escalation.
	// Raw mailbox auth failures and account-only mail findings feed incident
	// grouping and thresholded trackers, but one row is not enough evidence
	// for a firewall block.
	alwaysBlock := map[string]bool{
		"wp_login_bruteforce":         true,
		"xmlrpc_abuse":                true,
		"http_request_flood":          true,
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

	// Drain pending queue first (IPs from prior rate-limited cycles)
	for _, p := range state.Pending {
		if !isAlreadyBlocked(state, p.IP) {
			ipsToBlock[p.IP] = p.Reason
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
		if fwBlocker == nil {
			fmt.Fprintf(os.Stderr, "auto-block: firewall engine not available, skipping subnet %s\n", cidr)
			continue
		}
		sb, ok := fwBlocker.(subnetBlocker)
		if !ok {
			fmt.Fprintf(os.Stderr, "auto-block: firewall engine does not support subnet blocking, skipping %s\n", cidr)
			continue
		}
		if isSubnetAlreadyBlocked(cidr) {
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

	for _, f := range findings {
		isBlockable := alwaysBlock[f.Check]
		if !isBlockable && cfg.AutoResponse.BlockCpanelLogins && cpanelWebmailChecks[f.Check] {
			isBlockable = true
		}
		if !isBlockable {
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

		// Don't re-block already blocked IPs
		if isAlreadyBlocked(state, ip) || (fwBlocker != nil && fwBlocker.IsBlocked(ip)) {
			continue
		}

		// Skip IPs on the challenge list (they'll be challenged, not blocked)
		if cl := GetChallengeIPList(); cl != nil && cl.Contains(ip) {
			continue
		}

		ipsToBlock[ip] = f.Message
	}

	// Block IPs - queue any that can't be blocked due to rate limit
	expiry := parseExpiry(cfg.AutoResponse.BlockExpiry)
	rateLimited := false
	for ip, reason := range ipsToBlock {
		if state.BlocksThisHour >= maxBlocksPerHour {
			// Queue for next cycle instead of dropping
			state.Pending = append(state.Pending, pendingIP{IP: ip, Reason: reason})
			rateLimited = true
			continue
		}

		// Block via firewall engine (nftables)
		blockReason := fmt.Sprintf("CSM auto-block: %s", truncate(reason, 100))
		if fwBlocker == nil {
			fmt.Fprintf(os.Stderr, "auto-block: firewall engine not available, skipping %s\n", ip)
			continue
		}
		outcome, err := callBlockIP(fwBlocker, ip, blockReason, expiry)
		if err != nil {
			fmt.Fprintf(os.Stderr, "auto-block: error blocking %s: %v\n", ip, err)
			continue
		}

		switch outcome {
		case firewall.BlockOutcomeLive:
			// nft was mutated. Record the real block below.
		case firewall.BlockOutcomeDryRun:
			// dry-run intercepted: nft was NOT mutated. Do not record a real
			// block locally or in the permanent threat DB; emit a Warning
			// notice instead so operators see what would have been blocked.
			actions = append(actions, alert.Finding{
				Severity:  alert.Warning,
				Check:     "auto_block",
				Message:   fmt.Sprintf("AUTO-BLOCK [dry-run]: %s would be blocked (expires in %s)", ip, expiry),
				Details:   fmt.Sprintf("Reason: %s", reason),
				Timestamp: time.Now(),
			})
			continue
		case firewall.BlockOutcomeAllowed:
			// Verdict callback returned "allow": CSM intentionally did not
			// block. Stay silent at finding level - the panel already knows
			// it downgraded the decision and the engine logged it to stderr.
			continue
		case firewall.BlockOutcomeNoop:
			// Already-blocked, deny-limit, or other guard rejected the call.
			// No local state to record.
			continue
		default:
			fmt.Fprintf(os.Stderr, "auto-block: unknown block outcome %q for %s, skipping local state\n", outcome, ip)
			continue
		}
		if fwBlocker.IsBlocked(ip) {
			fmt.Fprintf(os.Stderr, "[%s] AUTO-BLOCK: %s blocked (expires in %s)\n", time.Now().Format("2006-01-02 15:04:05"), ip, expiry)
		}

		state.BlocksThisHour++

		// Add to permanent local threat database
		if db := GetThreatDB(); db != nil {
			db.AddPermanent(ip, reason)
		}

		state.IPs = append(state.IPs, blockedIP{
			IP:        ip,
			Reason:    reason,
			BlockedAt: time.Now(),
			ExpiresAt: time.Now().Add(expiry),
		})

		actions = append(actions, alert.Finding{
			Severity:  alert.Critical,
			Check:     "auto_block",
			Message:   fmt.Sprintf("AUTO-BLOCK: %s blocked (expires in %s)", ip, expiry),
			Details:   fmt.Sprintf("Reason: %s", reason),
			Timestamp: time.Now(),
		})

		// Permanent block escalation: promote to permanent after N temp blocks
		if cfg.AutoResponse.PermBlock && fwBlocker != nil {
			count := cfg.AutoResponse.PermBlockCount
			if count < 2 {
				count = 4
			}
			interval := parseExpiry(cfg.AutoResponse.PermBlockInterval)
			if interval == 0 {
				interval = 24 * time.Hour
			}
			if checkPermBlockEscalation(cfg.StatePath, ip, count, interval) {
				permReason := fmt.Sprintf("PERMBLOCK: %d temp blocks within %s", count, interval)
				if permOutcome, err := callBlockIP(fwBlocker, ip, permReason, 0); err == nil && permOutcome == firewall.BlockOutcomeLive {
					actions = append(actions, alert.Finding{
						Severity:  alert.Critical,
						Check:     "auto_block",
						Message:   fmt.Sprintf("AUTO-PERMBLOCK: %s promoted to permanent block (%d temp blocks)", ip, count),
						Timestamp: time.Now(),
					})
				}
			}
		}
	}

	if rateLimited {
		actions = append(actions, alert.Finding{
			Severity:  alert.Warning,
			Check:     "auto_block",
			Message:   fmt.Sprintf("Auto-block rate limit reached (%d/hour), %d IPs queued for next cycle", maxBlocksPerHour, len(state.Pending)),
			Timestamp: time.Now(),
		})
	}

	// Subnet auto-blocking: detect /24 patterns
	if cfg.AutoResponse.NetBlock && fwBlocker != nil {
		threshold := cfg.AutoResponse.NetBlockThreshold
		if threshold < 2 {
			threshold = 3
		}
		// Count blocked IPs per /24
		subnetCounts := make(map[string]int)
		subnetBlocked := make(map[string]bool)
		for _, b := range state.IPs {
			prefix := extractPrefix24(b.IP)
			if prefix != "" {
				subnetCounts[prefix]++
			}
		}
		for prefix, count := range subnetCounts {
			if count >= threshold && !subnetBlocked[prefix] {
				cidr := prefix + ".0/24"
				if sb, ok := fwBlocker.(subnetBlocker); ok {
					if isSubnetAlreadyBlocked(cidr) {
						continue
					}
					reason := fmt.Sprintf("Auto-netblock: %d IPs from %s", count, cidr)
					if err := sb.BlockSubnet(cidr, reason, 0); err == nil {
						subnetBlocked[prefix] = true
						fmt.Fprintf(os.Stderr, "[%s] AUTO-NETBLOCK: %s blocked (%d IPs from same /24)\n", time.Now().Format("2006-01-02 15:04:05"), cidr, count)
						actions = append(actions, alert.Finding{
							Severity:  alert.Critical,
							Check:     "auto_block",
							Message:   fmt.Sprintf("AUTO-NETBLOCK: %s blocked (%d IPs from same /24)", cidr, count),
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
// caught up yet.
func isBlockedLiveOrCached(b IPBlocker, ip string) bool {
	if lb, ok := b.(liveBlocker); ok {
		return lb.IsBlockedLive(ip)
	}
	return b.IsBlocked(ip)
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

func isSubnetAlreadyBlocked(cidr string) bool {
	sb, ok := fwBlocker.(subnetBlockStatus)
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

	// Use LastIndex to find the rightmost separator - log-injected content
	// tends to appear earlier in the message, while the structurally-parsed
	// IP from the log parser appears at the end.
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
	state := &blockState{}
	data, err := osFS.ReadFile(filepath.Join(statePath, blockStateFile))
	if err == nil {
		_ = json.Unmarshal(data, state)
	}
	return state
}

func saveBlockState(statePath string, state *blockState) {
	data, _ := json.MarshalIndent(state, "", "  ")
	tmpPath := filepath.Join(statePath, blockStateFile+".tmp")
	_ = os.WriteFile(tmpPath, data, 0600)
	_ = os.Rename(tmpPath, filepath.Join(statePath, blockStateFile))
}

// PendingBlockIPs returns IPs queued for blocking (rate-limited).
// Used by alert.FilterBlockedAlerts to suppress reputation alerts for these IPs.
func PendingBlockIPs(statePath string) map[string]bool {
	state := loadBlockState(statePath)
	ips := make(map[string]bool, len(state.Pending))
	for _, p := range state.Pending {
		ips[p.IP] = true
	}
	return ips
}

// extractPrefix24 returns the first 3 octets of an IPv4 address (e.g. "1.2.3").
func extractPrefix24(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ""
	}
	return parts[0] + "." + parts[1] + "." + parts[2]
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
	data, err := osFS.ReadFile(filepath.Join(statePath, "permblock_tracker.json"))
	if err == nil {
		_ = json.Unmarshal(data, tracker)
		if tracker.IPs == nil {
			tracker.IPs = make(map[string][]time.Time)
		}
	}
	return tracker
}

func savePermBlockTracker(statePath string, tracker *permBlockTracker) {
	data, _ := json.MarshalIndent(tracker, "", "  ")
	tmpPath := filepath.Join(statePath, "permblock_tracker.json.tmp")
	_ = os.WriteFile(tmpPath, data, 0600)
	_ = os.Rename(tmpPath, filepath.Join(statePath, "permblock_tracker.json"))
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
