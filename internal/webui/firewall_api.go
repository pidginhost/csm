package webui

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/platform"
	"github.com/pidginhost/csm/internal/store"
)

// dropAutoBlockThreatRow removes the auto-block threat row for ip after an
// operator unblock. Operator permanent blocks are left in place: a
// firewall-only unblock must not silently clear a deliberate block. Under
// older builds a stale auto-block row could outlive the firewall block and
// ip_reputation would re-flag the IP into a new block loop.
func dropAutoBlockThreatRow(ip string) {
	if parsed := net.ParseIP(ip); parsed != nil {
		ip = parsed.String()
	}
	if sdb := store.Global(); sdb != nil {
		_, _ = sdb.RemoveTemporaryBlock(ip)
	}
	if tdb := checks.GetThreatDB(); tdb != nil {
		tdb.RemoveTemporary(ip)
	}
}

type firewallAllowView struct {
	IP        string `json:"ip"`
	Reason    string `json:"reason"`
	Source    string `json:"source"`
	ExpiresAt string `json:"expires_at,omitempty"`
	ExpiresIn string `json:"expires_in"`
}

type firewallPortAllowView struct {
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Proto  string `json:"proto"`
	Reason string `json:"reason"`
	Source string `json:"source"`
}

const cphulkFirewallCheckTimeout = 8 * time.Second

var firewallCheckCommandOutput = func(ctx context.Context, name string, args ...string) ([]byte, error) {
	// #nosec G204 -- command names are fixed by trusted call sites; HTTP input
	// is parsed as an IP and passed as an execve argument without shell expansion.
	return exec.CommandContext(ctx, name, args...).Output()
}

func formatRemaining(expiresAt time.Time) string {
	if expiresAt.IsZero() {
		return "permanent"
	}
	remaining := time.Until(expiresAt)
	if remaining < 0 {
		remaining = 0
	}
	return fmt.Sprintf("%dh%dm", int(remaining.Hours()), int(remaining.Minutes())%60)
}

// apiFirewallStatus returns the firewall engine configuration and state summary.
func (s *Server) apiFirewallStatus(w http.ResponseWriter, _ *http.Request) {
	cfg := config.EffectiveFirewallConfig(s.liveCfg())
	state, err := firewall.LoadState(s.cfg.StatePath)
	if err != nil {
		writeJSONError(w, "firewall state unavailable (corrupt state file)", http.StatusInternalServerError)
		return
	}
	now := time.Now()

	blockedPermanent := 0
	blockedTemporary := 0
	for _, entry := range state.Blocked {
		if entry.ExpiresAt.IsZero() {
			blockedPermanent++
			continue
		}
		if now.Before(entry.ExpiresAt) {
			blockedTemporary++
		}
	}

	allowPermanent := 0
	allowTemporary := 0
	for _, entry := range state.Allowed {
		if entry.ExpiresAt.IsZero() {
			allowPermanent++
			continue
		}
		if now.Before(entry.ExpiresAt) {
			allowTemporary++
		}
	}

	result := map[string]interface{}{
		"enabled":              cfg.Enabled,
		"ipv6":                 cfg.IPv6,
		"tcp_in":               cfg.TCPIn,
		"tcp_out":              cfg.TCPOut,
		"udp_in":               cfg.UDPIn,
		"udp_out":              cfg.UDPOut,
		"restricted_tcp":       cfg.RestrictedTCP,
		"passive_ftp":          [2]int{cfg.PassiveFTPStart, cfg.PassiveFTPEnd},
		"conn_rate_limit":      cfg.ConnRateLimit,
		"conn_limit":           cfg.ConnLimit,
		"syn_flood_protection": cfg.SYNFloodProtection,
		"udp_flood":            cfg.UDPFlood,
		"smtp_block":           cfg.SMTPBlock,
		"log_dropped":          cfg.LogDropped,
		"deny_ip_limit":        cfg.DenyIPLimit,
		"blocked_count":        blockedPermanent + blockedTemporary,
		"blocked_net_count":    len(state.BlockedNet),
		"blocked_permanent":    blockedPermanent,
		"blocked_temporary":    blockedTemporary,
		"allowed_count":        allowPermanent + allowTemporary,
		"allow_permanent":      allowPermanent,
		"allow_temporary":      allowTemporary,
		"port_allow_count":     len(state.PortAllowed),
		"infra_ips":            cfg.InfraIPs,
		"infra_count":          len(cfg.InfraIPs),
		"port_flood_rules":     len(cfg.PortFlood),
		"country_block":        cfg.CountryBlock,
		"dyndns_hosts":         cfg.DynDNSHosts,
	}
	writeJSON(w, result)
}

// apiFirewallAllowed returns active firewall allow rules and port exceptions.
func (s *Server) apiFirewallAllowed(w http.ResponseWriter, _ *http.Request) {
	state, err := firewall.LoadState(s.cfg.StatePath)
	if err != nil {
		writeJSONError(w, "firewall state unavailable (corrupt state file)", http.StatusInternalServerError)
		return
	}
	now := time.Now()

	var allowed []firewallAllowView
	for _, entry := range state.Allowed {
		if !entry.ExpiresAt.IsZero() && !now.Before(entry.ExpiresAt) {
			continue
		}
		view := firewallAllowView{
			IP:        entry.IP,
			Reason:    entry.Reason,
			Source:    entry.Source,
			ExpiresIn: formatRemaining(entry.ExpiresAt),
		}
		if view.Source == "" {
			view.Source = firewall.InferProvenance("allow", entry.Reason)
		}
		if !entry.ExpiresAt.IsZero() {
			view.ExpiresAt = entry.ExpiresAt.Format(time.RFC3339)
		}
		allowed = append(allowed, view)
	}
	sort.Slice(allowed, func(i, j int) bool {
		return allowed[i].IP < allowed[j].IP
	})

	portAllowed := make([]firewallPortAllowView, 0, len(state.PortAllowed))
	for _, entry := range state.PortAllowed {
		portAllowed = append(portAllowed, firewallPortAllowView{
			IP:     entry.IP,
			Port:   entry.Port,
			Proto:  entry.Proto,
			Reason: entry.Reason,
			Source: entry.Source,
		})
		if portAllowed[len(portAllowed)-1].Source == "" {
			portAllowed[len(portAllowed)-1].Source = firewall.InferProvenance("allow_port", entry.Reason)
		}
	}
	sort.Slice(portAllowed, func(i, j int) bool {
		if portAllowed[i].IP != portAllowed[j].IP {
			return portAllowed[i].IP < portAllowed[j].IP
		}
		if portAllowed[i].Port != portAllowed[j].Port {
			return portAllowed[i].Port < portAllowed[j].Port
		}
		return portAllowed[i].Proto < portAllowed[j].Proto
	})

	writeJSON(w, map[string]interface{}{
		"allowed":      allowed,
		"port_allowed": portAllowed,
	})
}

// apiFirewallAllowIP adds a firewall allow rule, temporary when duration > 0.
func (s *Server) apiFirewallAllowIP(w http.ResponseWriter, r *http.Request) {
	s.threatActionMu.Lock()
	defer s.threatActionMu.Unlock()

	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IP       string `json:"ip"`
		Reason   string `json:"reason"`
		Duration string `json:"duration"`
	}
	if err := decodeJSONBodyLimited(w, r, 64*1024, &req); err != nil || req.IP == "" {
		writeJSONError(w, "IP is required", http.StatusBadRequest)
		return
	}
	parsedIP, err := parseAndValidateIP(req.IP)
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Audit, incident and threat records key on the canonical spelling.
	req.IP = parsedIP.String()
	if req.Reason == "" {
		req.Reason = "Allowed via CSM Web UI"
	}

	dur, err := parseDuration(req.Duration)
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if dur > 0 {
		allower, ok := s.blocker.(ipTempAllower)
		if !ok || allower == nil {
			writeJSONError(w, "Firewall allow rules are not available", http.StatusServiceUnavailable)
			return
		}
		if err := allower.TempAllowIP(req.IP, req.Reason, dur); err != nil {
			writeJSONError(w, fmt.Sprintf("Allow failed: %v", err), http.StatusInternalServerError)
			return
		}
		s.auditLog(r, "firewall_allow", req.IP, fmt.Sprintf("temporary allow %s: %s", dur, req.Reason))
		writeOK(w, map[string]interface{}{"ip": req.IP, "temporary": true})
		return
	}

	allower, ok := s.blocker.(ipAllower)
	if !ok || allower == nil {
		writeJSONError(w, "Firewall allow rules are not available", http.StatusServiceUnavailable)
		return
	}
	if err := allower.AllowIP(req.IP, req.Reason); err != nil {
		writeJSONError(w, fmt.Sprintf("Allow failed: %v", err), http.StatusInternalServerError)
		return
	}
	s.auditLog(r, "firewall_allow", req.IP, "permanent allow: "+req.Reason)
	writeOK(w, map[string]interface{}{"ip": req.IP, "temporary": false})
}

// apiFirewallRemoveAllow removes a firewall allow rule.
func (s *Server) apiFirewallRemoveAllow(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IP string `json:"ip"`
	}
	if err := decodeJSONBodyLimited(w, r, 64*1024, &req); err != nil || req.IP == "" {
		writeJSONError(w, "IP is required", http.StatusBadRequest)
		return
	}
	parsedIP, err := parseAndValidateIP(req.IP)
	if err != nil {
		writeJSONError(w, fmt.Sprintf("invalid IP address: %s", req.IP), http.StatusBadRequest)
		return
	}
	// Audit, incident and threat records key on the canonical spelling.
	req.IP = parsedIP.String()

	allower, ok := s.blocker.(allowRemover)
	if !ok || allower == nil {
		writeJSONError(w, "Firewall allow rules are not available", http.StatusServiceUnavailable)
		return
	}
	if err := allower.RemoveAllowIP(req.IP); err != nil {
		writeJSONError(w, fmt.Sprintf("Remove failed: %v", err), http.StatusInternalServerError)
		return
	}
	s.auditLog(r, "firewall_remove_allow", req.IP, "removed allow rule")
	writeOK(w, map[string]interface{}{"ip": req.IP})
}

// apiFirewallAudit returns recent firewall audit log entries.
func (s *Server) apiFirewallAudit(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 100)

	// Filters apply to the whole log and the limit to what they matched, so a
	// search reaches entries older than the newest page.
	entries := firewall.ReadAuditLog(s.cfg.StatePath, 0)

	type auditView struct {
		Timestamp string `json:"timestamp"`
		Action    string `json:"action"`
		IP        string `json:"ip"`
		Reason    string `json:"reason"`
		Source    string `json:"source"`
		Duration  string `json:"duration"`
		TimeAgo   string `json:"time_ago"`
	}

	search := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("search")))
	actionFilter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("action")))
	sourceFilter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("source")))

	var result []auditView
	for _, e := range entries {
		source := e.Source
		if source == "" {
			source = firewall.InferProvenance(e.Action, e.Reason)
		}
		if actionFilter != "" && strings.ToLower(e.Action) != actionFilter {
			continue
		}
		if sourceFilter != "" && strings.ToLower(source) != sourceFilter {
			continue
		}
		if search != "" {
			haystack := strings.ToLower(strings.Join([]string{e.Action, e.IP, e.Reason, source}, " "))
			if !strings.Contains(haystack, search) {
				continue
			}
		}
		result = append(result, auditView{
			Timestamp: e.Timestamp.UTC().Format(time.RFC3339),
			Action:    e.Action,
			IP:        e.IP,
			Reason:    e.Reason,
			Source:    source,
			Duration:  e.Duration,
			TimeAgo:   timeAgo(e.Timestamp),
		})
	}
	if limit == 0 {
		writeAll(w, result)
		return
	}
	// The newest entries are last in the log.
	total := len(result)
	if total > limit {
		result = result[total-limit:]
	}
	writeCapped(w, result, total, limit, nil)
}

// apiFirewallSubnets returns currently blocked subnets.
func (s *Server) apiFirewallSubnets(w http.ResponseWriter, _ *http.Request) {
	state, err := firewall.LoadState(s.cfg.StatePath)
	if err != nil {
		writeJSONError(w, "firewall state unavailable (corrupt state file)", http.StatusInternalServerError)
		return
	}

	type subnetView struct {
		CIDR      string `json:"cidr"`
		Reason    string `json:"reason"`
		Source    string `json:"source"`
		BlockedAt string `json:"blocked_at"`
		TimeAgo   string `json:"time_ago"`
		ExpiresIn string `json:"expires_in"`
	}

	var result []subnetView
	for _, sn := range state.BlockedNet {
		v := subnetView{
			CIDR:      sn.CIDR,
			Reason:    sn.Reason,
			Source:    sn.Source,
			BlockedAt: sn.BlockedAt.Format(time.RFC3339),
			TimeAgo:   timeAgo(sn.BlockedAt),
		}
		if v.Source == "" {
			v.Source = firewall.InferProvenance("block_subnet", sn.Reason)
		}
		v.ExpiresIn = formatRemaining(sn.ExpiresAt)
		result = append(result, v)
	}
	writeAll(w, result)
}

// apiFirewallDenySubnet blocks a subnet via the firewall engine.
func (s *Server) apiFirewallDenySubnet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		CIDR     string `json:"cidr"`
		Reason   string `json:"reason"`
		Duration string `json:"duration"`
	}
	if err := decodeJSONBodyLimited(w, r, 64*1024, &req); err != nil || req.CIDR == "" {
		writeJSONError(w, "CIDR is required", http.StatusBadRequest)
		return
	}
	if _, err := validateCIDR(req.CIDR); err != nil {
		writeJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Reason == "" {
		req.Reason = "Blocked via CSM Web UI"
	}

	dur, err := parseDuration(req.Duration)
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	sb, ok := s.blocker.(subnetBlocker)
	if !ok || sb == nil {
		writeJSONError(w, "Firewall engine not available", http.StatusServiceUnavailable)
		return
	}

	if err := sb.BlockSubnet(req.CIDR, req.Reason, dur); err != nil {
		writeJSONError(w, fmt.Sprintf("Block failed: %v", err), http.StatusInternalServerError)
		return
	}
	lifetime := "permanent"
	if dur > 0 {
		lifetime = dur.String()
	}
	s.auditLog(r, "firewall_deny_subnet", req.CIDR, lifetime+": "+req.Reason)
	writeOK(w, map[string]interface{}{"cidr": req.CIDR})
}

// apiFirewallRemoveSubnet removes a subnet block.
func (s *Server) apiFirewallRemoveSubnet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		CIDR string `json:"cidr"`
	}
	if err := decodeJSONBodyLimited(w, r, 64*1024, &req); err != nil || req.CIDR == "" {
		writeJSONError(w, "CIDR is required", http.StatusBadRequest)
		return
	}
	if _, _, err := net.ParseCIDR(req.CIDR); err != nil {
		writeJSONError(w, "Invalid CIDR notation", http.StatusBadRequest)
		return
	}

	sb, ok := s.blocker.(subnetUnblocker)
	if !ok || sb == nil {
		writeJSONError(w, "Firewall engine not available", http.StatusServiceUnavailable)
		return
	}

	if err := sb.UnblockSubnet(req.CIDR); err != nil {
		writeJSONError(w, fmt.Sprintf("Remove failed: %v", err), http.StatusInternalServerError)
		return
	}
	s.auditLog(r, "firewall_remove_subnet", req.CIDR, "removed subnet block")
	writeOK(w, map[string]interface{}{"cidr": req.CIDR})
}

// apiFirewallFlush clears all blocked IPs.
func (s *Server) apiFirewallFlush(w http.ResponseWriter, r *http.Request) {
	s.threatActionMu.Lock()
	defer s.threatActionMu.Unlock()

	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	fb, ok := s.blocker.(blockFlusher)
	if !ok || fb == nil {
		writeJSONError(w, "Firewall engine not available", http.StatusServiceUnavailable)
		return
	}

	result, err := checks.FlushAutoBlockState(s.cfg.StatePath, fb.FlushBlocked)
	if result.SnapshotErr != nil {
		csmlog.Warn("web firewall flush could not snapshot persisted blocks", "err", result.SnapshotErr)
	}
	if err != nil {
		if result.Flushed {
			writeJSONError(w, fmt.Sprintf("Firewall flushed but auto-block cleanup failed: %v", err), http.StatusInternalServerError)
		} else {
			writeJSONError(w, fmt.Sprintf("Flush failed: %v", err), http.StatusInternalServerError)
		}
		return
	}
	s.auditLog(r, "firewall_flush", "blocked set", fmt.Sprintf("flushed: %v", result.Flushed))
	writeOK(w, nil)
}

// apiFirewallFlushCphulk clears cPHulk login history for one IP without touching firewall state.
func (s *Server) apiFirewallFlushCphulk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IP string `json:"ip"`
	}
	if err := decodeJSONBodyLimited(w, r, 64*1024, &req); err != nil || req.IP == "" {
		writeJSONError(w, "IP is required", http.StatusBadRequest)
		return
	}
	parsedIP, err := parseAndValidateIP(req.IP)
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Audit, incident and threat records key on the canonical spelling.
	req.IP = parsedIP.String()

	if err := flushCphulk(req.IP); err != nil {
		writeJSONError(w, "Could not clear cPHulk login history: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.auditLog(r, "cphulk_clear", req.IP, "cleared cPHulk login history")
	writeOK(w, map[string]interface{}{"ip": req.IP})
}

// apiFirewallCheck checks if an IP is blocked in CSM or cphulk.
// GET /api/v1/firewall/check?ip=1.2.3.4
// phclient calls this route and reads success, permanent, temporary and
// cphulk (the cpanel-service shape it replaced), so the body keeps
// "success": true next to the fields; it is a deprecated alias:
//
//	{"success": true, "ip": "1.2.3.4", "permanent": "reason or null", "temporary": "reason or null", "cphulk": true/false}
//
// Failures are error statuses like every other route; phclient treats any
// non-2xx as a failed call.
func (s *Server) apiFirewallCheck(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if ip == "" || net.ParseIP(ip) == nil {
		writeJSONError(w, "The ip is not valid or it was not set.", http.StatusBadRequest)
		return
	}

	result := map[string]interface{}{
		"success":   true,
		"ip":        ip,
		"permanent": nil,
		"temporary": nil,
		"cphulk":    false,
	}

	// Check CSM firewall state
	state, err := firewall.LoadState(s.cfg.StatePath)
	if err != nil {
		// A corrupt state file means we cannot tell whether the IP is
		// blocked; report failure rather than a misleading "not blocked".
		writeJSONError(w, "Firewall state unavailable", http.StatusInternalServerError)
		return
	}
	now := time.Now()
	// Compare as parsed addresses: an IPv6 block saved in one spelling
	// must be found when queried in another.
	queried := net.ParseIP(ip)
	for _, b := range state.Blocked {
		if entryIP := net.ParseIP(b.IP); entryIP != nil && entryIP.Equal(queried) {
			if b.ExpiresAt.IsZero() {
				result["permanent"] = b.Reason
			} else if now.Before(b.ExpiresAt) {
				result["temporary"] = fmt.Sprintf("%s (expires in %s)", b.Reason,
					time.Until(b.ExpiresAt).Truncate(time.Minute))
			}
		}
	}

	// Check blocked subnets
	parsedIP := net.ParseIP(ip)
	for _, sn := range state.BlockedNet {
		_, network, err := net.ParseCIDR(sn.CIDR)
		if err == nil && network.Contains(parsedIP) {
			result["permanent"] = fmt.Sprintf("Subnet block: %s - %s", sn.CIDR, sn.Reason)
		}
	}

	// Check cphulk (cPanel brute force detector) - read-only check.
	if platform.Detect().IsCPanel() && cphulkTempBanContainsIP(r.Context(), ip) {
		result["cphulk"] = true
	} else {
		cphulkOut, cphulkErr := runFirewallCheckCommand(r.Context(), "whmapi1", "read_cphulk_records",
			"list_name=black", "--output=json")
		if cphulkErr == nil && cphulkBlocksIP(cphulkOut, ip) {
			result["cphulk"] = true
		}
	}

	writeJSON(w, result)
}

// cphulkBlocksIP scopes the match to cPHulk record IP fields. A raw token
// search would still match unrelated strings such as operator notes.
func cphulkBlocksIP(jsonOut []byte, ip string) bool {
	if ip == "" {
		return false
	}
	var payload struct {
		Data struct {
			Records []map[string]json.RawMessage `json:"records"`
		} `json:"data"`
	}
	if err := json.Unmarshal(jsonOut, &payload); err != nil {
		return false
	}
	for _, record := range payload.Data.Records {
		for key, raw := range record {
			if !isCphulkRecordIPField(key) {
				continue
			}
			var value string
			if err := json.Unmarshal(raw, &value); err != nil {
				continue
			}
			if value == ip {
				return true
			}
		}
	}
	return false
}

func isCphulkRecordIPField(key string) bool {
	switch strings.ToLower(key) {
	case "ip", "ip_address":
		return true
	default:
		return false
	}
}

func runFirewallCheckCommand(parent context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parent, cphulkFirewallCheckTimeout)
	defer cancel()
	return firewallCheckCommandOutput(ctx, name, args...)
}

// cPHulk brute-force temp bans live in the cphulk-TempBan nftables set, not in
// read_cphulk_records, so ask nftables for exact element membership instead of
// scanning a textual set dump where one IP could match unrelated text.
func cphulkTempBanContainsIP(parent context.Context, ip string) bool {
	lookupIP, ok := cphulkTempBanLookupIP(ip)
	if !ok {
		return false
	}
	_, err := runFirewallCheckCommand(parent, "nft", "get", "element",
		"inet", "filter", "cphulk-TempBan", "{", lookupIP, "}")
	return err == nil
}

func cphulkTempBanLookupIP(ip string) (string, bool) {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return "", false
	}
	if ip4 := parsed.To4(); ip4 != nil {
		return net.IP(ip4).String(), true
	}
	return parsed.String(), true
}

// apiFirewallUnban unblocks an IP from CSM + cphulk in one call.
// POST /api/v1/firewall/unban  body: {"ip": "1.2.3.4"}
func (s *Server) apiFirewallUnban(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IP string `json:"ip"`
	}
	if err := decodeJSONBodyLimited(w, r, 64*1024, &req); err != nil || req.IP == "" {
		writeJSONError(w, "The ip is not valid or it was not set.", http.StatusBadRequest)
		return
	}
	parsedIP, err := parseAndValidateIP(req.IP)
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Audit, incident and threat records key on the canonical spelling.
	req.IP = parsedIP.String()

	// 1. Unblock from CSM firewall (individual IP)
	if s.blocker != nil {
		_ = s.blocker.UnblockIP(req.IP)
	}
	dropAutoBlockThreatRow(req.IP)

	// 2. Also remove from any covering subnet block. A corrupt state file
	// only costs us the subnet sweep; the IP unblock above already ran, so
	// skip this step rather than fail the whole unban.
	state, stateErr := firewall.LoadState(s.cfg.StatePath)
	subnetRemoved := ""
	if sb, ok := s.blocker.(subnetUnblocker); ok && stateErr == nil && state != nil {
		for _, sn := range state.BlockedNet {
			_, network, err := net.ParseCIDR(sn.CIDR)
			if err == nil && network.Contains(parsedIP) {
				if sb.UnblockSubnet(sn.CIDR) == nil {
					subnetRemoved = sn.CIDR
				}
				break
			}
		}
	}

	// 3. Flush from cphulk
	_ = flushCphulk(req.IP) // best effort: the unblock is what was asked

	// "success" is the deprecated alias phclient reads; see apiFirewallCheck.
	result := map[string]interface{}{"ok": true, "success": true, "ip": req.IP}
	if subnetRemoved != "" {
		result["subnet_removed"] = subnetRemoved
	}
	details := "unblock, clear auto-block state, flush cPHulk"
	if subnetRemoved != "" {
		details += ", removed subnet " + subnetRemoved
	}
	s.auditLog(r, "firewall_unban", req.IP, details)
	writeJSON(w, result)
}
