package webui

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/pidginhost/cpanel-security-monitor/internal/firewall"
)

// apiFirewallStatus returns the firewall engine configuration and state summary.
func (s *Server) apiFirewallStatus(w http.ResponseWriter, _ *http.Request) {
	cfg := s.cfg.Firewall
	state, _ := firewall.LoadState(s.cfg.StatePath)

	// Use top-level infra_ips if firewall.infra_ips is empty (daemon syncs at runtime)
	infraIPs := cfg.InfraIPs
	if len(infraIPs) == 0 {
		infraIPs = s.cfg.InfraIPs
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
		"blocked_count":        len(state.Blocked),
		"blocked_net_count":    len(state.BlockedNet),
		"allowed_count":        len(state.Allowed),
		"infra_ips":            infraIPs,
		"infra_count":          len(infraIPs),
		"port_flood_rules":     len(cfg.PortFlood),
		"country_block":        cfg.CountryBlock,
		"dyndns_hosts":         cfg.DynDNSHosts,
	}
	writeJSON(w, result)
}

// apiFirewallAudit returns recent firewall audit log entries.
func (s *Server) apiFirewallAudit(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if n := parseIntSimple(l); n > 0 {
			limit = n
		}
	}

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
		Duration  string `json:"duration"`
		TimeAgo   string `json:"time_ago"`
	}

	var result []auditView
	for _, e := range entries {
		result = append(result, auditView{
			Timestamp: e.Timestamp.Format("2006-01-02 15:04:05"),
			Action:    e.Action,
			IP:        e.IP,
			Reason:    e.Reason,
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
		BlockedAt string `json:"blocked_at"`
		TimeAgo   string `json:"time_ago"`
	}

	var result []subnetView
	for _, sn := range state.BlockedNet {
		result = append(result, subnetView{
			CIDR:      sn.CIDR,
			Reason:    sn.Reason,
			BlockedAt: sn.BlockedAt.Format(time.RFC3339),
			TimeAgo:   timeAgo(sn.BlockedAt),
		})
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
		CIDR   string `json:"cidr"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.CIDR == "" {
		writeJSONError(w, "CIDR is required", http.StatusBadRequest)
		return
	}
	if _, _, err := net.ParseCIDR(req.CIDR); err != nil {
		writeJSONError(w, "Invalid CIDR notation", http.StatusBadRequest)
		return
	}
	if req.Reason == "" {
		req.Reason = "Blocked via CSM Web UI"
	}

	sb, ok := s.blocker.(interface {
		BlockSubnet(string, string) error
	})
	if !ok || sb == nil {
		writeJSONError(w, "Firewall engine not available", http.StatusServiceUnavailable)
		return
	}

	if err := sb.BlockSubnet(req.CIDR, req.Reason); err != nil {
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.CIDR == "" {
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

func parseIntSimple(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}
