package webui

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/pidginhost/csm/internal/attackdb"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/threat"
)

func (s *Server) handleThreat(w http.ResponseWriter, _ *http.Request) {
	s.renderTemplate(w, "threat.html", map[string]string{
		"Hostname": s.cfg.Hostname,
	})
}

// GET /api/v1/threat/stats
func (s *Server) apiThreatStats(w http.ResponseWriter, r *http.Request) {
	adb := attackdb.Global()
	if adb == nil {
		writeJSON(w, map[string]string{"error": "attack database not initialized"})
		return
	}
	writeJSON(w, adb.Stats())
}

// GET /api/v1/threat/top-attackers?limit=25
func (s *Server) apiThreatTopAttackers(w http.ResponseWriter, r *http.Request) {
	adb := attackdb.Global()
	if adb == nil {
		writeJSON(w, []struct{}{})
		return
	}

	limit := 25
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 200 {
			limit = n
		}
	}

	recs := adb.TopAttackers(limit)

	// Enrich with unified intelligence
	ips := make([]string, len(recs))
	for i, rec := range recs {
		ips[i] = rec.IP
	}
	intels := threat.LookupBatch(ips, s.cfg.StatePath)

	type enriched struct {
		*attackdb.IPRecord
		UnifiedScore int    `json:"unified_score"`
		Verdict      string `json:"verdict"`
		AbuseScore   int    `json:"abuse_score"`
		InThreatDB   bool   `json:"in_threat_db"`
		Blocked      bool   `json:"currently_blocked"`
		Country      string `json:"country,omitempty"`
		ASOrg        string `json:"as_org,omitempty"`
	}

	results := make([]enriched, len(recs))
	for i, rec := range recs {
		results[i] = enriched{
			IPRecord:     rec,
			UnifiedScore: intels[i].UnifiedScore,
			Verdict:      intels[i].Verdict,
			AbuseScore:   intels[i].AbuseScore,
			InThreatDB:   intels[i].InThreatDB,
			Blocked:      intels[i].CurrentlyBlocked,
		}
		if gdb := s.geoIPDB.Load(); gdb != nil {
			geo := gdb.Lookup(rec.IP)
			results[i].Country = geo.Country
			results[i].ASOrg = geo.ASOrg
		}
	}

	writeJSON(w, results)
}

// GET /api/v1/threat/ip?ip=1.2.3.4
func (s *Server) apiThreatIP(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if ip == "" || net.ParseIP(ip) == nil {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]string{"error": "invalid or missing ip parameter"})
		return
	}

	intel := threat.Lookup(ip, s.cfg.StatePath)

	// Enrich with GeoIP data if available
	if gdb := s.geoIPDB.Load(); gdb != nil {
		geo := gdb.Lookup(ip)
		intel.Country = geo.Country
		intel.CountryName = geo.CountryName
		intel.City = geo.City
		intel.ASN = geo.ASN
		intel.ASOrg = geo.ASOrg
		intel.Network = geo.Network
	}

	writeJSON(w, intel)
}

// GET /api/v1/threat/events?ip=1.2.3.4&limit=50
func (s *Server) apiThreatEvents(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if ip == "" || net.ParseIP(ip) == nil {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]string{"error": "invalid or missing ip parameter"})
		return
	}

	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}

	adb := attackdb.Global()
	if adb == nil {
		writeJSON(w, []struct{}{})
		return
	}

	events := adb.QueryEvents(ip, limit)
	if events == nil {
		events = []attackdb.Event{}
	}
	writeJSON(w, events)
}

// GET /api/v1/threat/db-stats
func (s *Server) apiThreatDBStats(w http.ResponseWriter, r *http.Request) {
	result := make(map[string]interface{})

	if tdb := checks.GetThreatDB(); tdb != nil {
		result["threat_db"] = tdb.Stats()
	}
	if adb := attackdb.Global(); adb != nil {
		result["attack_db"] = map[string]interface{}{
			"total_ips": adb.TotalIPs(),
			"top_line":  adb.FormatTopLine(),
		}
	}

	writeJSON(w, result)
}

// POST /api/v1/threat/whitelist-ip — mark an IP as a known customer
// Unblocks, removes from threat DB + attack DB, adds to whitelist.
func (s *Server) apiThreatWhitelistIP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IP == "" {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]string{"error": "IP is required"})
		return
	}
	if net.ParseIP(req.IP) == nil {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]string{"error": "invalid IP address"})
		return
	}

	var actions []string

	// 1. Unblock from firewall
	if s.blocker != nil {
		if err := s.blocker.UnblockIP(req.IP); err == nil {
			actions = append(actions, "unblocked from firewall")
		}
		// Also add to firewall allow list so it doesn't get re-blocked
		if allower, ok := s.blocker.(interface {
			AllowIP(string, string) error
		}); ok {
			if err := allower.AllowIP(req.IP, "CSM whitelist: customer IP"); err == nil {
				actions = append(actions, "added to firewall allow list")
			}
		}
	}

	// 2. Remove from threat DB permanent blocklist + add to whitelist
	if tdb := checks.GetThreatDB(); tdb != nil {
		tdb.RemovePermanent(req.IP)
		tdb.AddWhitelist(req.IP)
		actions = append(actions, "removed from threat DB, added to whitelist")
	}

	// 3. Remove from attack DB
	if adb := attackdb.Global(); adb != nil {
		adb.RemoveIP(req.IP)
		actions = append(actions, "removed from attack DB")
	}

	// 4. Flush cphulk
	flushCphulk(req.IP)

	s.auditLog(r, "whitelist_ip", req.IP, "permanent whitelist")
	writeJSON(w, map[string]interface{}{
		"status":  "whitelisted",
		"ip":      req.IP,
		"actions": actions,
	})
}

// GET /api/v1/threat/whitelist — list all whitelisted IPs
func (s *Server) apiThreatWhitelist(w http.ResponseWriter, r *http.Request) {
	tdb := checks.GetThreatDB()
	if tdb == nil {
		writeJSON(w, []string{})
		return
	}
	writeJSON(w, tdb.WhitelistedIPs())
}

// POST /api/v1/threat/unwhitelist-ip — remove an IP from the whitelist
func (s *Server) apiThreatUnwhitelistIP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IP == "" {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]string{"error": "IP is required"})
		return
	}
	if net.ParseIP(req.IP) == nil {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]string{"error": "invalid IP address"})
		return
	}

	if tdb := checks.GetThreatDB(); tdb != nil {
		tdb.RemoveWhitelist(req.IP)
	}

	// Also remove from firewall allow list
	if s.blocker != nil {
		if remover, ok := s.blocker.(interface {
			RemoveAllowIP(string) error
		}); ok {
			_ = remover.RemoveAllowIP(req.IP)
		}
	}

	writeJSON(w, map[string]string{"status": "removed", "ip": req.IP})
}

// POST /api/v1/threat/block-ip — manually block an IP for 24 hours.
func (s *Server) apiThreatBlockIP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IP == "" {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]string{"error": "IP is required"})
		return
	}
	if net.ParseIP(req.IP) == nil {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]string{"error": "invalid IP address"})
		return
	}

	var actions []string

	// 1. Block in firewall with 24h expiry
	if s.blocker != nil {
		if err := s.blocker.BlockIP(req.IP, "Manually blocked via CSM Web UI", 24*time.Hour); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			writeJSON(w, map[string]string{"error": fmt.Sprintf("block failed: %v", err)})
			return
		}
		actions = append(actions, "blocked in firewall for 24h")
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		writeJSON(w, map[string]string{"error": "firewall engine not available"})
		return
	}

	// 2. Add to threat DB permanent blocklist
	if tdb := checks.GetThreatDB(); tdb != nil {
		tdb.AddPermanent(req.IP, "Manually blocked via CSM Web UI")
		actions = append(actions, "added to threat DB")
	}

	// 3. Record in attack DB
	if adb := attackdb.Global(); adb != nil {
		adb.MarkBlocked(req.IP)
		actions = append(actions, "recorded in attack DB")
	}

	s.auditLog(r, "block_ip", req.IP, "manual block 24h")
	writeJSON(w, map[string]interface{}{
		"status":  "blocked",
		"ip":      req.IP,
		"actions": actions,
	})
}

// POST /api/v1/threat/clear-ip — unblock + clear from all DBs without whitelisting.
// For dynamic IP customers: one-time cleanup, IP can be re-blocked later.
func (s *Server) apiThreatClearIP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IP == "" {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]string{"error": "IP is required"})
		return
	}
	if net.ParseIP(req.IP) == nil {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]string{"error": "invalid IP address"})
		return
	}

	var actions []string

	// 1. Unblock from firewall (but don't add to allow list)
	if s.blocker != nil {
		if err := s.blocker.UnblockIP(req.IP); err == nil {
			actions = append(actions, "unblocked from firewall")
		}
	}

	// 2. Remove from threat DB permanent blocklist (but don't whitelist)
	if tdb := checks.GetThreatDB(); tdb != nil {
		tdb.RemovePermanent(req.IP)
		actions = append(actions, "removed from threat DB")
	}

	// 3. Remove from attack DB
	if adb := attackdb.Global(); adb != nil {
		adb.RemoveIP(req.IP)
		actions = append(actions, "removed from attack DB")
	}

	// 4. Flush cphulk
	flushCphulk(req.IP)
	actions = append(actions, "flushed cPanel login history")

	s.auditLog(r, "clear_ip", req.IP, "unblock & clear")
	writeJSON(w, map[string]interface{}{
		"status":  "cleared",
		"ip":      req.IP,
		"actions": actions,
	})
}

// POST /api/v1/threat/temp-whitelist-ip — whitelist for a specified duration.
func (s *Server) apiThreatTempWhitelistIP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IP    string `json:"ip"`
		Hours int    `json:"hours"` // default 24
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IP == "" {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]string{"error": "IP is required"})
		return
	}
	if net.ParseIP(req.IP) == nil {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]string{"error": "invalid IP address"})
		return
	}
	if req.Hours <= 0 {
		req.Hours = 24
	}
	if req.Hours > 168 { // max 7 days
		req.Hours = 168
	}

	ttl := time.Duration(req.Hours) * time.Hour
	var actions []string

	// 1. Unblock from firewall
	if s.blocker != nil {
		if err := s.blocker.UnblockIP(req.IP); err == nil {
			actions = append(actions, "unblocked from firewall")
		}
		// Temp allow in firewall too
		if allower, ok := s.blocker.(interface {
			TempAllowIP(string, string, time.Duration) error
		}); ok {
			if err := allower.TempAllowIP(req.IP, "CSM temp whitelist", ttl); err == nil {
				actions = append(actions, fmt.Sprintf("temp allowed in firewall for %dh", req.Hours))
			}
		}
	}

	// 2. Remove from threat DB + temp whitelist
	if tdb := checks.GetThreatDB(); tdb != nil {
		tdb.RemovePermanent(req.IP)
		tdb.TempWhitelist(req.IP, ttl)
		actions = append(actions, fmt.Sprintf("temp whitelisted for %dh", req.Hours))
	}

	// 3. Remove from attack DB
	if adb := attackdb.Global(); adb != nil {
		adb.RemoveIP(req.IP)
		actions = append(actions, "removed from attack DB")
	}

	// 4. Flush cphulk
	flushCphulk(req.IP)

	s.auditLog(r, "temp_whitelist_ip", req.IP, fmt.Sprintf("%dh temp whitelist", req.Hours))
	writeJSON(w, map[string]interface{}{
		"status":  "temp_whitelisted",
		"ip":      req.IP,
		"hours":   req.Hours,
		"actions": actions,
	})
}

// writeJSON is defined in api.go
