package alert

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
	csmlog "github.com/pidginhost/csm/internal/log"
)

// State files tell SplitByClass which sources CSM already blocked. Parse
// failures must degrade open so corrupt state never moves an operator-facing
// finding to the summary; warning logs keep the corruption visible. Missing
// state files stay silent because they are normal before the first block.

// SplitByClass separates the findings an operator must see now from the
// ones that report an attack CSM already handled, which belong in the daily
// summary. A finding is summary class when the summary-notice policy names
// it (an applied response or an observation that never acts), or when a
// block or challenge on its source address answers it. A block counts only
// once it is in effect: blocked state on disk, or an applied block notice in
// the same batch. Pending, unverified and dry-run blocks keep the finding
// immediate. Both halves keep their input order.
func SplitByClass(cfg *config.Config, findings []Finding) (immediate, summary []Finding) {
	return splitByClass(cfg, findings, findings)
}

// splitByClass classifies each of findings on its own fields, while every
// observation in evidence may prove a block or challenge applied. Dispatch
// passes its audit sources as evidence only: a suppressed block notice still
// blocked its address, but it is not delivered to the summary itself.
func splitByClass(cfg *config.Config, findings, evidence []Finding) (immediate, summary []Finding) {
	if len(findings) == 0 {
		return nil, nil
	}
	notice := currentSummaryNoticePolicy()
	policy := currentIPResponsePolicy()
	web := currentWebTrafficPolicy()
	// The split runs on every dispatch: block state is read once, and only
	// for a batch where a block could answer a finding.
	var handled *handledSet
	for _, f := range findings {
		answered := notice != nil && notice(f)
		if !answered {
			if ip := ClassSourceIP(f); ip != nil {
				if handled == nil {
					handled = handledSources(cfg.StatePath, evidence)
				}
				answered = handled.answers(policy, web, cfg, f, ip)
			}
		}
		if answered {
			summary = append(summary, f)
		} else {
			immediate = append(immediate, f)
		}
	}
	return immediate, summary
}

// handledSet holds the canonical addresses and subnets CSM blocked, and the
// addresses it routed to the challenge.
type handledSet struct {
	blocked    map[string]bool
	subnets    []*net.IPNet
	challenged map[string]bool
	// The Cloudflare ranges the firewall accepts on its web ports, read at
	// the first blocked web finding.
	statePath  string
	cfLoaded   bool
	cfV4, cfV6 []string
}

// loadCloudflareRanges reads the firewall's cached Cloudflare ranges.
var loadCloudflareRanges = firewall.LoadCFState

func handledSources(statePath string, findings []Finding) *handledSet {
	// Load only IPs with actual block state. Pending entries have not reached
	// the firewall and must remain visible to the operator.
	blockedIPs := loadBlockedIPs(statePath)

	// Also collect IPs and subnets blocked in this batch, and IPs routed
	// to the challenge in this batch. A challenge-routed IP is handled
	// automatically the same way a blocked one is: it either solves the
	// PoW (legitimate) or gets escalated to a block by the port gate, so
	// the operator needs no notification either way. Dry-run notices put
	// "[dry-run]" after the action word, so they never match these tokens.
	var blockedSubnets []*net.IPNet
	challengedIPs := make(map[string]bool)
	for _, f := range findings {
		switch f.Check {
		case "auto_block":
			parts := strings.Fields(f.Message)
			for i, p := range parts {
				if p == "AUTO-BLOCK:" && i+1 < len(parts) {
					blockedIPs[parts[i+1]] = true
					break
				}
				if (p == "AUTO-BLOCK-SUBNET:" || p == "AUTO-NETBLOCK:") && i+1 < len(parts) {
					if _, ipnet, err := net.ParseCIDR(parts[i+1]); err == nil {
						blockedSubnets = append(blockedSubnets, ipnet)
					}
					break
				}
			}
		case "challenge_route":
			parts := strings.Fields(f.Message)
			for i, p := range parts {
				if p == "CHALLENGE:" && i+1 < len(parts) {
					challengedIPs[parts[i+1]] = true
					break
				}
			}
		}
	}

	// Canonicalize blocked-IP keys via net.ParseIP so equality survives
	// notation differences (2001:db8::1 vs 2001:db8:0:0:0:0:0:1,
	// IPv4-mapped IPv6). Keys that do not parse as an IP cannot
	// exact-match a finding's IP and are dropped.
	h := &handledSet{
		blocked:    make(map[string]bool, len(blockedIPs)),
		subnets:    blockedSubnets,
		challenged: make(map[string]bool, len(challengedIPs)),
		statePath:  statePath,
	}
	for ip := range blockedIPs {
		if parsed := net.ParseIP(ip); parsed != nil {
			h.blocked[parsed.String()] = true
		}
	}
	for ip := range challengedIPs {
		if parsed := net.ParseIP(ip); parsed != nil {
			h.challenged[parsed.String()] = true
		}
	}
	return h
}

// answers reports whether a block or challenge on ip, f's source, answers f.
func (h *handledSet) answers(policy IPResponsePolicy, web func(Finding) bool, cfg *config.Config, f Finding, ip net.IP) bool {
	// The class keys on the actual block state, never on auto-response
	// intent: an enabled block_ips used to hide every reputation finding,
	// including the IPs auto-block did NOT handle (dry-run, rate-limited
	// queue drops, verdict-allowed). Structured SourceIP wins when present;
	// older findings fall back to the message token. The address is
	// compared canonically: substring matching used to let a blocked
	// 192.0.2.1 answer a finding about the unrelated 192.0.2.10. A finding
	// with no parseable IP is never handled (fail open to alerting).
	// The Cloudflare accept on TCP 80/443 precedes the blocked drop, so a
	// block of a covered address leaves its web traffic flowing.
	if ipBlocked(ip, h.blocked, h.subnets) && ipResponseAnswers(policy, cfg, f, true) &&
		(web == nil || !web(f) || !h.cloudflareCovers(ip)) {
		return true
	}
	// A challenge counts only for findings a challenge answers. Critical
	// ip_reputation is a browserless mail/SSH/FTP sighting and must stay
	// immediate until a hard block lands; otherwise an old challenge entry
	// hides the exact finding that is supposed to escalate it.
	return ipResponseAnswers(policy, cfg, f, false) && ipChallenged(ip, h.challenged)
}

func (h *handledSet) cloudflareCovers(ip net.IP) bool {
	if !h.cfLoaded {
		h.cfV4, h.cfV6 = loadCloudflareRanges(h.statePath)
		h.cfLoaded = true
	}
	return firewall.CloudflareRangesCover(h.cfV4, h.cfV6, ip.String())
}

func ipBlocked(ip net.IP, blocked map[string]bool, subnets []*net.IPNet) bool {
	if blocked[ip.String()] {
		return true
	}
	// Same-batch subnet and netblock blocks answer per-IP findings for
	// addresses inside them.
	for _, subnet := range subnets {
		if subnet.Contains(ip) {
			return true
		}
	}
	return false
}

func ipChallenged(ip net.IP, challenged map[string]bool) bool {
	if challenged[ip.String()] {
		return true
	}
	return ChallengedIPFunc != nil && ChallengedIPFunc(ip.String())
}

// ipResponseAnswers reports whether a block (blocked) or a challenge answers
// the finding. With no policy wired it keeps the reputation-only rule.
func ipResponseAnswers(policy IPResponsePolicy, cfg *config.Config, f Finding, blocked bool) bool {
	if policy != nil {
		return policy(cfg, f, blocked)
	}
	if f.Check != "ip_reputation" {
		return false
	}
	return blocked || challengeHandlesFinding(f)
}

// challengeHandlesFinding mirrors the only finding-level exception to the
// challenge response policy. ip_reputation has one production grading source:
// High is browser-facing HTTP/cPanel traffic, while Critical is a browserless
// vector that resolves to a hard block.
func challengeHandlesFinding(f Finding) bool {
	return f.Check == "ip_reputation" && f.Severity != Critical
}

// ClassSourceIP is the address SplitByClass checks against block and
// challenge state: the structured SourceIP, or for an older finding the
// first address in its message. nil means the finding has none.
func ClassSourceIP(f Finding) net.IP {
	if strings.TrimSpace(f.SourceIP) != "" {
		if normalized := normalizeFindingIP(f.SourceIP); normalized != "" {
			return net.ParseIP(normalized)
		}
		return nil
	}
	return extractIPFromFindingMessage(f.Message)
}

// extractIPFromFindingMessage scans a finding message for the first token
// that parses as a valid IP address and returns it. Returns nil if no IP
// is found. Used to match reputation findings against blocked IPs and
// blocked-subnet CIDRs.
func extractIPFromFindingMessage(msg string) net.IP {
	for _, field := range strings.Fields(msg) {
		if ip := parseIPMessageField(field); ip != nil {
			return ip
		}
	}
	return nil
}

func parseIPMessageField(field string) net.IP {
	if ip := parseIPMessageToken(field); ip != nil {
		return ip
	}
	// Accept key=value tokens such as "ip=5.5.5.5". IP literals never
	// contain '=', so taking the value side cannot mangle a real IP.
	if idx := strings.LastIndexByte(field, '='); idx >= 0 {
		return parseIPMessageToken(field[idx+1:])
	}
	return nil
}

func parseIPMessageToken(token string) net.IP {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil
	}

	if ip := parseNormalizedIP(token); ip != nil {
		return ip
	}

	unquoted := strings.Trim(token, "\"'`")
	if ip := parseNormalizedIP(unquoted); ip != nil {
		return ip
	}

	withoutTrailing := strings.TrimRight(unquoted, ",;")
	if ip := parseNormalizedIP(withoutTrailing); ip != nil {
		return ip
	}

	unwrapped := strings.Trim(withoutTrailing, "()[]{}<>")
	if ip := parseNormalizedIP(unwrapped); ip != nil {
		return ip
	}

	if strings.HasSuffix(unwrapped, ":") {
		withoutColon := strings.TrimSuffix(unwrapped, ":")
		if ip := parseNormalizedIP(withoutColon); ip != nil {
			return ip
		}
		if ip := parseNormalizedIP(strings.Trim(withoutColon, "()[]{}<>")); ip != nil {
			return ip
		}
	}

	return nil
}

func parseNormalizedIP(raw string) net.IP {
	if normalized := normalizeFindingIP(raw); normalized != "" {
		return net.ParseIP(normalized)
	}
	return nil
}

func loadBlockedIPSource(statePath string, now time.Time, ips map[string]bool) {
	// Use injected loader (bbolt-backed) when available.
	loadVerified := BlockedIPsFunc == nil
	if !loadVerified {
		for ip, v := range BlockedIPsFunc() {
			ips[ip] = v
		}
	}

	// Unverified state overrides legacy tracker rows even with an injected
	// loader, which only returns the addresses it considers blocked.
	loadFirewallStateFile(statePath, now, ips, loadVerified)
}

// BlockedIPsFunc is an optional callback that returns currently blocked IPs.
// Set by the daemon (or tests) to provide blocked IPs from bbolt store,
// avoiding a circular import between alert and store packages.
// When nil, loadBlockedIPs falls back to reading flat files.
var BlockedIPsFunc func() map[string]bool

// ChallengedIPFunc reports whether an IP is currently on the challenge
// list. Set by the daemon from the live challenge IP list, mirroring
// BlockedIPsFunc; nil means challenge membership is unknown and no listed
// challenge makes a finding summary class (fail open to alerting).
var ChallengedIPFunc func(ip string) bool

// loadBlockedIPs reads blocked IPs from both the firewall engine state
// and the legacy blocked_ips.json file.
func loadBlockedIPs(statePath string) map[string]bool {
	ips := make(map[string]bool)
	now := time.Now()
	loadBlockFileEntries(statePath, now, ips, nil, blockFileIPsSection)
	loadBlockedIPSource(statePath, now, ips)
	return ips
}

func loadFirewallStateFile(statePath string, now time.Time, ips map[string]bool, loadVerified bool) {
	fwPath := filepath.Join(statePath, "firewall", "state.json")
	fwData, err := os.ReadFile(fwPath) // #nosec G304 -- filepath.Join under operator-configured statePath.
	if err != nil {
		return
	}

	var fwState struct {
		Blocked []struct {
			IP         string    `json:"ip"`
			ExpiresAt  time.Time `json:"expires_at"`
			Unverified bool      `json:"unverified"`
		} `json:"blocked"`
	}
	if err := json.Unmarshal(fwData, &fwState); err != nil {
		csmlog.Warn("alert class split: firewall state.json unparseable, its blocks count as unhandled",
			"path", fwPath, "err", err)
		return
	}

	unverified := make(map[string]bool)
	for _, entry := range fwState.Blocked {
		if entry.Unverified {
			if ip := net.ParseIP(entry.IP); ip != nil {
				unverified[ip.String()] = true
			}
		} else if loadVerified && (entry.ExpiresAt.IsZero() || now.Before(entry.ExpiresAt)) {
			ips[entry.IP] = true
		}
	}
	for ip := range ips {
		if parsed := net.ParseIP(ip); parsed != nil && unverified[parsed.String()] {
			delete(ips, ip)
		}
	}
}

type blockFile struct {
	IPs     []blockFileIP
	Pending []blockFilePendingIP
}

type blockFileIP struct {
	IP        string    `json:"ip"`
	ExpiresAt time.Time `json:"expires_at"`
}

type blockFilePendingIP struct {
	IP string `json:"ip"`
}

type blockFileSection uint8

const (
	blockFileIPsSection blockFileSection = 1 << iota
	blockFilePendingSection
)

func loadBlockFileEntries(statePath string, now time.Time, ips map[string]bool, pending map[string]bool, sections blockFileSection) {
	bf, ok := loadBlockFile(statePath, sections)
	if !ok {
		return
	}

	for _, entry := range bf.IPs {
		if ips != nil && (entry.ExpiresAt.IsZero() || now.Before(entry.ExpiresAt)) {
			ips[entry.IP] = true
		}
	}
	for _, entry := range bf.Pending {
		if pending != nil {
			pending[entry.IP] = true
		}
	}
}

func loadBlockFile(statePath string, sections blockFileSection) (blockFile, bool) {
	blockedPath := filepath.Join(statePath, "blocked_ips.json")
	data, err := os.ReadFile(blockedPath) // #nosec G304 -- filepath.Join under operator-configured statePath.
	if err != nil {
		return blockFile{}, false
	}

	var raw struct {
		IPs     json.RawMessage `json:"ips"`
		Pending json.RawMessage `json:"pending"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		csmlog.Warn("alert class split: blocked_ips.json unparseable, its blocks count as unhandled",
			"path", blockedPath, "err", err)
		return blockFile{}, false
	}

	var bf blockFile
	if sections&blockFileIPsSection != 0 && len(raw.IPs) > 0 && string(raw.IPs) != "null" {
		if err := json.Unmarshal(raw.IPs, &bf.IPs); err != nil {
			csmlog.Warn("alert class split: blocked_ips.json blocked entries unparseable, they count as unhandled",
				"path", blockedPath, "err", err)
		}
	}
	if sections&blockFilePendingSection != 0 && len(raw.Pending) > 0 && string(raw.Pending) != "null" {
		if err := json.Unmarshal(raw.Pending, &bf.Pending); err != nil {
			csmlog.Warn("alert class split: blocked_ips.json pending entries unparseable, they count as unhandled",
				"path", blockedPath, "err", err)
		}
	}

	return bf, true
}

// IPResponsePolicy reports whether an IP disposition on a finding's source
// fully answers the finding, so SplitByClass moves it to the summary. blocked
// is true for a firewall block and false for a challenge.
type IPResponsePolicy func(cfg *config.Config, f Finding, blocked bool) bool

var (
	ipResponsePolicyMu sync.RWMutex
	ipResponsePolicy   IPResponsePolicy

	summaryNoticeMu     sync.RWMutex
	summaryNoticePolicy func(Finding) bool

	webTrafficMu     sync.RWMutex
	webTrafficPolicy func(Finding) bool
)

// SetIPResponsePolicy installs or clears the policy SplitByClass consults
// and returns the previous one. The check classification lives in the
// checks package, which imports this one and registers it at package
// initialization so every dispatch path uses the same policy.
func SetIPResponsePolicy(p IPResponsePolicy) IPResponsePolicy {
	ipResponsePolicyMu.Lock()
	defer ipResponsePolicyMu.Unlock()
	previous := ipResponsePolicy
	ipResponsePolicy = p
	return previous
}

func currentIPResponsePolicy() IPResponsePolicy {
	ipResponsePolicyMu.RLock()
	p := ipResponsePolicy
	ipResponsePolicyMu.RUnlock()
	return p
}

// SetSummaryNoticePolicy installs or clears the policy that names summary
// notices by their own content, and returns the previous one. The checks
// package registers it at package initialization, like SetIPResponsePolicy.
// With no policy no finding is a summary notice, so every one stays
// immediate unless its source is handled.
func SetSummaryNoticePolicy(p func(Finding) bool) func(Finding) bool {
	summaryNoticeMu.Lock()
	defer summaryNoticeMu.Unlock()
	previous := summaryNoticePolicy
	summaryNoticePolicy = p
	return previous
}

func currentSummaryNoticePolicy() func(Finding) bool {
	summaryNoticeMu.RLock()
	p := summaryNoticePolicy
	summaryNoticeMu.RUnlock()
	return p
}

// SetWebTrafficPolicy installs or clears the policy that names findings about
// requests on the web ports, and returns the previous one. A block of a
// Cloudflare-covered address does not answer them. The checks package
// registers it at package initialization, like SetIPResponsePolicy.
func SetWebTrafficPolicy(p func(Finding) bool) func(Finding) bool {
	webTrafficMu.Lock()
	defer webTrafficMu.Unlock()
	previous := webTrafficPolicy
	webTrafficPolicy = p
	return previous
}

func currentWebTrafficPolicy() func(Finding) bool {
	webTrafficMu.RLock()
	p := webTrafficPolicy
	webTrafficMu.RUnlock()
	return p
}
