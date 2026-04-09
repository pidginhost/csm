package webui

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/firewall"
)

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
	cfg := s.cfg.Firewall
	state, _ := firewall.LoadState(s.cfg.StatePath)
	now := time.Now()

	// Use top-level infra_ips if firewall.infra_ips is empty (daemon syncs at runtime)
	infraIPs := cfg.InfraIPs
	if len(infraIPs) == 0 {
		infraIPs = s.cfg.InfraIPs
	}

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
		"infra_ips":            infraIPs,
		"infra_count":          len(infraIPs),
		"port_flood_rules":     len(cfg.PortFlood),
		"country_block":        cfg.CountryBlock,
		"dyndns_hosts":         cfg.DynDNSHosts,
	}
	writeJSON(w, result)
}

// apiFirewallAllowed returns active firewall allow rules and port exceptions.
func (s *Server) apiFirewallAllowed(w http.ResponseWriter, _ *http.Request) {
	state, _ := firewall.LoadState(s.cfg.StatePath)
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
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
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
	if _, err := parseAndValidateIP(req.IP); err != nil {
		writeJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Reason == "" {
		req.Reason = "Allowed via CSM Web UI"
	}

	dur := parseDuration(req.Duration)
	if dur > 0 {
		allower, ok := s.blocker.(interface {
			TempAllowIP(string, string, time.Duration) error
		})
		if !ok || allower == nil {
			writeJSONError(w, "Firewall allow rules are not available", http.StatusServiceUnavailable)
			return
		}
		if err := allower.TempAllowIP(req.IP, req.Reason, dur); err != nil {
			writeJSONError(w, fmt.Sprintf("Allow failed: %v", err), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]string{"status": "temp_allowed", "ip": req.IP})
		return
	}

	allower, ok := s.blocker.(interface {
		AllowIP(string, string) error
	})
	if !ok || allower == nil {
		writeJSONError(w, "Firewall allow rules are not available", http.StatusServiceUnavailable)
		return
	}
	if err := allower.AllowIP(req.IP, req.Reason); err != nil {
		writeJSONError(w, fmt.Sprintf("Allow failed: %v", err), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"status": "allowed", "ip": req.IP})
}

// apiFirewallRemoveAllow removes a firewall allow rule.
func (s *Server) apiFirewallRemoveAllow(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IP string `json:"ip"`
	}
	if err := decodeJSONBodyLimited(w, r, 64*1024, &req); err != nil || req.IP == "" {
		writeJSONError(w, "IP is required", http.StatusBadRequest)
		return
	}
	if _, err := parseAndValidateIP(req.IP); err != nil {
		writeJSONError(w, fmt.Sprintf("invalid IP address: %s", req.IP), http.StatusBadRequest)
		return
	}

	allower, ok := s.blocker.(interface {
		RemoveAllowIP(string) error
	})
	if !ok || allower == nil {
		writeJSONError(w, "Firewall allow rules are not available", http.StatusServiceUnavailable)
		return
	}
	if err := allower.RemoveAllowIP(req.IP); err != nil {
		writeJSONError(w, fmt.Sprintf("Remove failed: %v", err), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"status": "removed", "ip": req.IP})
}

// apiFirewallAudit returns recent firewall audit log entries.
func (s *Server) apiFirewallAudit(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 100)

	entries := firewall.ReadAuditLog(s.cfg.StatePath, limit)
	if entries == nil {
		writeJSON(w, []interface{}{})
		return
	}

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
			Timestamp: e.Timestamp.Format("2006-01-02 15:04:05"),
			Action:    e.Action,
			IP:        e.IP,
			Reason:    e.Reason,
			Source:    source,
			Duration:  e.Duration,
			TimeAgo:   timeAgo(e.Timestamp),
		})
	}
	writeJSON(w, result)
}

// apiFirewallSubnets returns currently blocked subnets.
func (s *Server) apiFirewallSubnets(w http.ResponseWriter, _ *http.Request) {
	state, _ := firewall.LoadState(s.cfg.StatePath)

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
	if result == nil {
		writeJSON(w, []interface{}{})
		return
	}
	writeJSON(w, result)
}

// apiFirewallDenySubnet blocks a subnet via the firewall engine.
func (s *Server) apiFirewallDenySubnet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
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

	dur := parseDuration(req.Duration)

	sb, ok := s.blocker.(interface {
		BlockSubnet(string, string, time.Duration) error
	})
	if !ok || sb == nil {
		writeJSONError(w, "Firewall engine not available", http.StatusServiceUnavailable)
		return
	}

	if err := sb.BlockSubnet(req.CIDR, req.Reason, dur); err != nil {
		writeJSONError(w, fmt.Sprintf("Block failed: %v", err), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"status": "blocked", "cidr": req.CIDR})
}

// apiFirewallRemoveSubnet removes a subnet block.
func (s *Server) apiFirewallRemoveSubnet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
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

	sb, ok := s.blocker.(interface {
		UnblockSubnet(string) error
	})
	if !ok || sb == nil {
		writeJSONError(w, "Firewall engine not available", http.StatusServiceUnavailable)
		return
	}

	if err := sb.UnblockSubnet(req.CIDR); err != nil {
		writeJSONError(w, fmt.Sprintf("Remove failed: %v", err), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"status": "removed", "cidr": req.CIDR})
}

// apiFirewallFlush clears all blocked IPs.
func (s *Server) apiFirewallFlush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	fb, ok := s.blocker.(interface{ FlushBlocked() error })
	if !ok || fb == nil {
		writeJSONError(w, "Firewall engine not available", http.StatusServiceUnavailable)
		return
	}

	if err := fb.FlushBlocked(); err != nil {
		writeJSONError(w, fmt.Sprintf("Flush failed: %v", err), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"status": "flushed"})
}

// apiFirewallFlushCphulk clears cPHulk login history for one IP without touching firewall state.
func (s *Server) apiFirewallFlushCphulk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IP string `json:"ip"`
	}
	if err := decodeJSONBodyLimited(w, r, 64*1024, &req); err != nil || req.IP == "" {
		writeJSONError(w, "IP is required", http.StatusBadRequest)
		return
	}
	if _, err := parseAndValidateIP(req.IP); err != nil {
		writeJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	flushCphulk(req.IP)
	writeJSON(w, map[string]string{"status": "flushed", "ip": req.IP})
}

// apiFirewallCheck checks if an IP is blocked in CSM or cphulk.
// GET /api/v1/firewall/check?ip=1.2.3.4
// Response matches cpanel-service format for phclient compatibility:
//
//	{"success": true, "ip": "1.2.3.4", "permanent": "reason or null", "temporary": "reason or null", "cphulk": true/false}
func (s *Server) apiFirewallCheck(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if ip == "" || net.ParseIP(ip) == nil {
		writeJSON(w, map[string]interface{}{"success": false, "error_msg": "The ip is not valid or it was not set."})
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
	state, _ := firewall.LoadState(s.cfg.StatePath)
	now := time.Now()
	for _, b := range state.Blocked {
		if b.IP == ip {
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

	// Check cphulk (cPanel brute force detector) - read-only check
	cphulkOut, cphulkErr := exec.Command("whmapi1", "read_cphulk_records",
		"list_name=black", "--output=json").Output()
	if cphulkErr == nil {
		if bytes.Contains(cphulkOut, []byte(ip)) {
			result["cphulk"] = true
		}
	}

	writeJSON(w, result)
}

// apiFirewallUnban unblocks an IP from CSM + cphulk in one call.
// POST /api/v1/firewall/unban  body: {"ip": "1.2.3.4"}
func (s *Server) apiFirewallUnban(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IP string `json:"ip"`
	}
	if err := decodeJSONBodyLimited(w, r, 64*1024, &req); err != nil || req.IP == "" {
		writeJSON(w, map[string]interface{}{"success": false, "error_msg": "The ip is not valid or it was not set."})
		return
	}
	if _, err := parseAndValidateIP(req.IP); err != nil {
		writeJSON(w, map[string]interface{}{"success": false, "error_msg": err.Error()})
		return
	}

	// 1. Unblock from CSM firewall (individual IP)
	if s.blocker != nil {
		_ = s.blocker.UnblockIP(req.IP)
	}

	// 2. Also remove from any covering subnet block
	state, _ := firewall.LoadState(s.cfg.StatePath)
	parsedIP := net.ParseIP(req.IP)
	subnetRemoved := ""
	if sb, ok := s.blocker.(interface{ UnblockSubnet(string) error }); ok {
		for _, sn := range state.BlockedNet {
			_, network, err := net.ParseCIDR(sn.CIDR)
			if err == nil && network.Contains(parsedIP) {
				_ = sb.UnblockSubnet(sn.CIDR)
				subnetRemoved = sn.CIDR
				break
			}
		}
	}

	// 3. Flush from cphulk
	flushCphulk(req.IP)

	result := map[string]interface{}{"success": true, "ip": req.IP}
	if subnetRemoved != "" {
		result["subnet_removed"] = subnetRemoved
	}
	writeJSON(w, result)
}
