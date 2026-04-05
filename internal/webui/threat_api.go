package webui

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
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

	limit := queryInt(r, "limit", 25)
	if limit > 200 {
		limit = 200
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
		writeJSONError(w, "invalid or missing ip parameter", http.StatusBadRequest)
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
		writeJSONError(w, "invalid or missing ip parameter", http.StatusBadRequest)
		return
	}

	limit := queryInt(r, "limit", 50)
	if limit > 500 {
		limit = 500
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

// POST /api/v1/threat/whitelist-ip - mark an IP as a known customer
// Unblocks, removes from threat DB + attack DB, adds to whitelist.
func (s *Server) apiThreatWhitelistIP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IP == "" {
		writeJSONError(w, "IP is required", http.StatusBadRequest)
		return
	}
	if net.ParseIP(req.IP) == nil {
		writeJSONError(w, "invalid IP address", http.StatusBadRequest)
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

// GET /api/v1/threat/whitelist - list all whitelisted IPs
func (s *Server) apiThreatWhitelist(w http.ResponseWriter, r *http.Request) {
	tdb := checks.GetThreatDB()
	if tdb == nil {
		writeJSON(w, []string{})
		return
	}
	writeJSON(w, tdb.WhitelistedIPs())
}

// POST /api/v1/threat/unwhitelist-ip - remove an IP from the whitelist
func (s *Server) apiThreatUnwhitelistIP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IP == "" {
		writeJSONError(w, "IP is required", http.StatusBadRequest)
		return
	}
	if net.ParseIP(req.IP) == nil {
		writeJSONError(w, "invalid IP address", http.StatusBadRequest)
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

// POST /api/v1/threat/block-ip - manually block an IP for 24 hours.
func (s *Server) apiThreatBlockIP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IP == "" {
		writeJSONError(w, "IP is required", http.StatusBadRequest)
		return
	}
	if _, err := parseAndValidateIP(req.IP); err != nil {
		writeJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	var actions []string

	// 1. Block in firewall with 24h expiry
	if s.blocker != nil {
		if err := s.blocker.BlockIP(req.IP, "Manually blocked via CSM Web UI", 24*time.Hour); err != nil {
			writeJSONError(w, fmt.Sprintf("block failed: %v", err), http.StatusInternalServerError)
			return
		}
		actions = append(actions, "blocked in firewall for 24h")
	} else {
		writeJSONError(w, "firewall engine not available", http.StatusServiceUnavailable)
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

// POST /api/v1/threat/clear-ip - unblock + clear from all DBs without whitelisting.
// For dynamic IP customers: one-time cleanup, IP can be re-blocked later.
func (s *Server) apiThreatClearIP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IP == "" {
		writeJSONError(w, "IP is required", http.StatusBadRequest)
		return
	}
	if net.ParseIP(req.IP) == nil {
		writeJSONError(w, "invalid IP address", http.StatusBadRequest)
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

// POST /api/v1/threat/temp-whitelist-ip - whitelist for a specified duration.
func (s *Server) apiThreatTempWhitelistIP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IP    string `json:"ip"`
		Hours int    `json:"hours"` // default 24
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IP == "" {
		writeJSONError(w, "IP is required", http.StatusBadRequest)
		return
	}
	if net.ParseIP(req.IP) == nil {
		writeJSONError(w, "invalid IP address", http.StatusBadRequest)
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

// POST /api/v1/threat/bulk-action - block or whitelist multiple IPs at once.
func (s *Server) apiThreatBulkAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IPs    []string `json:"ips"`
		Action string   `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if len(req.IPs) == 0 || len(req.IPs) > 100 {
		writeJSONError(w, "IPs must be 1-100 items", http.StatusBadRequest)
		return
	}
	if req.Action != "block" && req.Action != "whitelist" {
		writeJSONError(w, "Action must be 'block' or 'whitelist'", http.StatusBadRequest)
		return
	}

	count := 0
	for _, ipStr := range req.IPs {
		if net.ParseIP(ipStr) == nil {
			continue
		}
		switch req.Action {
		case "block":
			// Mirror apiThreatBlockIP flow
			if s.blocker != nil {
				if err := s.blocker.BlockIP(ipStr, "Bulk blocked via CSM Web UI", 24*time.Hour); err != nil {
					continue
				}
			}
			if tdb := checks.GetThreatDB(); tdb != nil {
				tdb.AddPermanent(ipStr, "Bulk blocked via CSM Web UI")
			}
			if adb := attackdb.Global(); adb != nil {
				adb.MarkBlocked(ipStr)
			}
			count++

		case "whitelist":
			// Mirror apiThreatWhitelistIP flow
			if s.blocker != nil {
				_ = s.blocker.UnblockIP(ipStr)
				if allower, ok := s.blocker.(interface {
					AllowIP(string, string) error
				}); ok {
					_ = allower.AllowIP(ipStr, "CSM bulk whitelist")
				}
			}
			if tdb := checks.GetThreatDB(); tdb != nil {
				tdb.RemovePermanent(ipStr)
				tdb.AddWhitelist(ipStr)
			}
			if adb := attackdb.Global(); adb != nil {
				adb.RemoveIP(ipStr)
			}
			flushCphulk(ipStr)
			count++
		}
	}

	s.auditLog(r, "threat_bulk_"+req.Action, fmt.Sprintf("%d IPs", count), "")
	writeJSON(w, map[string]interface{}{"ok": true, "count": count})
}

// writeJSON is defined in api.go
