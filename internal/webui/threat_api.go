package webui

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/attackdb"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/threat"
)

func (s *Server) handleThreat(w http.ResponseWriter, r *http.Request) {
	s.renderTemplate(w, r, "threat.html", map[string]string{
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
	s.threatActionMu.Lock()
	defer s.threatActionMu.Unlock()

	if r.Method != "POST" {
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
	// Every downstream key (firewall, threat DB, attack DB, audit) uses the
	// canonical form; a padded or upper-case spelling validated but then
	// matched nothing and still answered 200.
	req.IP = parsedIP.String()

	var actions []string

	var historyErr error
	if err := checks.ForgetNetblockHistory(s.cfg.StatePath, req.IP, func() {
		// 1. Unblock from firewall
		if s.blocker != nil {
			if err := s.blocker.UnblockIP(req.IP); err == nil {
				actions = append(actions, "unblocked from firewall")
			}
			// Also add to firewall allow list so it doesn't get re-blocked
			if allower, ok := s.blocker.(ipAllower); ok {
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
	}); err != nil {
		// The firewall and database changes above already happened. Finish the
		// action, including its audit entry, and report the failure after.
		historyErr = err
	} else {
		actions = append(actions, "removed from subnet block history")
	}

	// 4. Flush cphulk
	flushCphulk(req.IP)

	warning := ""
	if s.blocker != nil {
		warning = coveringSubnetWarning(s.blocker, req.IP)
	}
	detail := "permanent whitelist"
	if warning != "" {
		detail += "; " + warning
	}
	s.auditLog(r, "whitelist_ip", req.IP, detail)
	if historyErr != nil {
		writeJSONError(w, "IP action applied, but subnet history cleanup failed: "+historyErr.Error(), http.StatusInternalServerError)
		return
	}
	resp := map[string]interface{}{
		"status":  "whitelisted",
		"ip":      req.IP,
		"actions": actions,
	}
	if warning != "" {
		resp["warning"] = warning
	}
	writeJSON(w, resp)
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
	s.threatActionMu.Lock()
	defer s.threatActionMu.Unlock()

	if r.Method != "POST" {
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
	// Every downstream key (firewall, threat DB, attack DB, audit) uses the
	// canonical form; a padded or upper-case spelling validated but then
	// matched nothing and still answered 200.
	req.IP = parsedIP.String()

	if tdb := checks.GetThreatDB(); tdb != nil {
		if tdb.IsConfigWhitelisted(req.IP) {
			writeJSONError(w, "IP is managed by reputation.whitelist; edit the config and reload", http.StatusConflict)
			return
		}
		tdb.RemoveWhitelist(req.IP)
	}
	s.auditLog(r, "unwhitelist_ip", req.IP, "removed from runtime whitelist and firewall allow list")

	// Also remove from firewall allow list
	if s.blocker != nil {
		if remover, ok := s.blocker.(allowRemover); ok {
			_ = remover.RemoveAllowIP(req.IP)
		}
	}

	writeJSON(w, map[string]string{"status": "removed", "ip": req.IP})
}

// manualBlockTTL is the lifetime of the Web UI "Block (24h)" action. The
// threat evidence it records carries the same expiry, so the address stops
// counting as malicious when the firewall block lapses.
const manualBlockTTL = 24 * time.Hour

const (
	manualBlockReason        = "Manually blocked via CSM Web UI"
	manualPermBlockReason    = "Permanently blocked via CSM Web UI"
	bulkBlockReason          = "Bulk blocked via CSM Web UI"
	bulkPermanentBlockReason = "Bulk permanently blocked via CSM Web UI"
)

// POST /api/v1/threat/block-ip - manually block an IP for 24 hours.
func (s *Server) apiThreatBlockIP(w http.ResponseWriter, r *http.Request) {
	s.operatorBlockIP(w, r, false)
}

// POST /api/v1/threat/block-ip-permanent - block an IP with no expiry.
// Permanence is chosen by the authenticated operator action alone: no
// request field can turn the 24h block into a permanent one.
func (s *Server) apiThreatBlockIPPermanent(w http.ResponseWriter, r *http.Request) {
	s.operatorBlockIP(w, r, true)
}

func (s *Server) operatorBlockIP(w http.ResponseWriter, r *http.Request, permanent bool) {
	s.threatActionMu.Lock()
	defer s.threatActionMu.Unlock()

	if r.Method != "POST" {
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
	// Every downstream key (firewall, threat DB, attack DB, audit) uses the
	// canonical form; a padded or upper-case spelling validated but then
	// matched nothing and still answered 200.
	req.IP = parsedIP.String()

	reason := manualBlockReason
	ttl := manualBlockTTL
	if permanent {
		reason = manualPermBlockReason
		ttl = 0
	}

	var actions []string

	// 1. Block in firewall. A zero timeout is a permanent firewall block.
	if s.blocker == nil {
		writeJSONError(w, "firewall engine not available", http.StatusServiceUnavailable)
		return
	}
	// Operator-initiated: bypass auto_response.dry_run gate.
	if err := s.blockIPPreservingLifetime(req.IP, reason, ttl); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, firewall.ErrPermanentBlock) || errors.Is(err, firewall.ErrLongerBlock) {
			status = http.StatusConflict
		}
		writeJSONError(w, fmt.Sprintf("block failed: %v", err), status)
		return
	}
	invalidateIPUndo(req.IP)
	if permanent {
		actions = append(actions, "blocked in firewall permanently")
	} else {
		actions = append(actions, "blocked in firewall for 24h")
	}

	// 2. Record threat evidence with the same lifetime as the block.
	if tdb := checks.GetThreatDB(); tdb != nil {
		if permanent {
			tdb.AddPermanent(req.IP, reason)
			actions = append(actions, "added to threat DB permanently")
		} else {
			tdb.AddOperatorTemporary(req.IP, reason, ttl)
			actions = append(actions, "added to threat DB for 24h")
		}
	}

	// 3. Record in attack DB
	if adb := attackdb.Global(); adb != nil {
		adb.MarkBlocked(req.IP)
		actions = append(actions, "recorded in attack DB")
	}

	if permanent {
		s.auditLog(r, "block_ip_permanent", req.IP, "manual permanent block")
	} else {
		s.auditLog(r, "block_ip", req.IP, "manual block 24h")
	}
	writeJSON(w, map[string]interface{}{
		"status":    "blocked",
		"ip":        req.IP,
		"permanent": permanent,
		"actions":   actions,
	})
}

// POST /api/v1/threat/clear-ip - unblock + clear from all DBs without whitelisting.
// For dynamic IP customers: one-time cleanup, IP can be re-blocked later.
func (s *Server) apiThreatClearIP(w http.ResponseWriter, r *http.Request) {
	s.threatActionMu.Lock()
	defer s.threatActionMu.Unlock()

	if r.Method != "POST" {
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
	// Every downstream key (firewall, threat DB, attack DB, audit) uses the
	// canonical form; a padded or upper-case spelling validated but then
	// matched nothing and still answered 200.
	req.IP = parsedIP.String()

	var actions []string

	var historyErr error
	if err := checks.ForgetNetblockHistory(s.cfg.StatePath, req.IP, func() {
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
	}); err != nil {
		// The firewall and database changes above already happened. Finish the
		// action, including its audit entry, and report the failure after.
		historyErr = err
	} else {
		actions = append(actions, "removed from subnet block history")
	}

	// 4. Flush cphulk
	flushCphulk(req.IP)
	actions = append(actions, "flushed cPanel login history")

	s.auditLog(r, "clear_ip", req.IP, "unblock & clear")
	if historyErr != nil {
		writeJSONError(w, "IP action applied, but subnet history cleanup failed: "+historyErr.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]interface{}{
		"status":  "cleared",
		"ip":      req.IP,
		"actions": actions,
	})
}

// POST /api/v1/threat/temp-whitelist-ip - whitelist for a specified duration.
func (s *Server) apiThreatTempWhitelistIP(w http.ResponseWriter, r *http.Request) {
	s.threatActionMu.Lock()
	defer s.threatActionMu.Unlock()

	if r.Method != "POST" {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IP    string `json:"ip"`
		Hours int    `json:"hours"` // default 24
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
	// Every downstream key (firewall, threat DB, attack DB, audit) uses the
	// canonical form; a padded or upper-case spelling validated but then
	// matched nothing and still answered 200.
	req.IP = parsedIP.String()
	if req.Hours <= 0 {
		req.Hours = 24
	}
	if req.Hours > 168 { // max 7 days
		req.Hours = 168
	}

	ttl := time.Duration(req.Hours) * time.Hour
	var actions []string

	var historyErr error
	if err := checks.ForgetNetblockHistory(s.cfg.StatePath, req.IP, func() {
		// 1. Unblock from firewall
		if s.blocker != nil {
			if err := s.blocker.UnblockIP(req.IP); err == nil {
				actions = append(actions, "unblocked from firewall")
			}
			// Temp allow in firewall too
			if allower, ok := s.blocker.(ipTempAllower); ok {
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
	}); err != nil {
		// The firewall and database changes above already happened. Finish the
		// action, including its audit entry, and report the failure after.
		historyErr = err
	} else {
		actions = append(actions, "removed from subnet block history")
	}

	// 4. Flush cphulk
	flushCphulk(req.IP)

	s.auditLog(r, "temp_whitelist_ip", req.IP, fmt.Sprintf("%dh temp whitelist", req.Hours))
	if historyErr != nil {
		writeJSONError(w, "IP action applied, but subnet history cleanup failed: "+historyErr.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]interface{}{
		"status":  "temp_whitelisted",
		"ip":      req.IP,
		"hours":   req.Hours,
		"actions": actions,
	})
}

// threatBulkActionMax bounds the addresses one bulk threat action changes. Each
// request returns one undo token, so the UI refuses larger selections instead
// of splitting them.
const threatBulkActionMax = 100

// POST /api/v1/threat/bulk-action - block or whitelist multiple IPs at once.
func (s *Server) apiThreatBulkAction(w http.ResponseWriter, r *http.Request) {
	s.threatActionMu.Lock()
	defer s.threatActionMu.Unlock()

	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IPs    []string `json:"ips"`
		Action string   `json:"action"`
	}
	if err := decodeJSONBodyLimited(w, r, 64*1024, &req); err != nil {
		writeJSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if len(req.IPs) == 0 || len(req.IPs) > threatBulkActionMax {
		writeJSONError(w, fmt.Sprintf("IPs must be 1-%d items", threatBulkActionMax), http.StatusBadRequest)
		return
	}
	blockAction := req.Action == "block" || req.Action == "block_permanent"
	if !blockAction && req.Action != "whitelist" {
		writeJSONError(w, "Action must be 'block', 'block_permanent' or 'whitelist'", http.StatusBadRequest)
		return
	}
	if blockAction && s.blocker == nil {
		writeJSONError(w, "firewall engine not available", http.StatusServiceUnavailable)
		return
	}
	// Permanence follows the operator action, never a per-IP request field.
	permanent := req.Action == "block_permanent"
	blockReason := bulkBlockReason
	blockTTL := manualBlockTTL
	if permanent {
		blockReason = bulkPermanentBlockReason
		blockTTL = 0
	}

	priorBlocks := make(map[string]firewall.BlockedEntry)
	expectedBlocks := make(map[string]firewall.BlockedEntry)
	seen := make(map[string]bool, len(req.IPs))

	count := 0
	succeeded := make([]string, 0, len(req.IPs))
	var removedThreats []undoThreatRow
	var warnings []string
	for _, ipStr := range req.IPs {
		parsedIP, err := parseAndValidateIP(ipStr)
		if err != nil {
			continue
		}
		ipStr = parsedIP.String()
		if seen[ipStr] {
			continue
		}
		seen[ipStr] = true

		switch {
		case blockAction:
			// Mirror the single-IP block flow.
			// Operator-initiated bulk block: bypass auto_response.dry_run gate.
			before, after, err := s.blockIPForUndo(ipStr, blockReason, blockTTL)
			if err != nil {
				warnings = append(warnings, ipStr+": "+err.Error())
				continue
			}
			if before != nil {
				priorBlocks[ipStr] = *before
			}
			if after != nil {
				expectedBlocks[ipStr] = *after
			}
			invalidateIPUndo(ipStr)
			// Capture whatever evidence is already on file so the undo
			// restores it instead of dropping an older permanent row this
			// block did not create.
			if row, ok := captureUndoThreatRow(ipStr, false); ok {
				removedThreats = append(removedThreats, row)
			}
			if tdb := checks.GetThreatDB(); tdb != nil {
				if permanent {
					tdb.AddPermanent(ipStr, blockReason)
				} else {
					tdb.AddOperatorTemporary(ipStr, blockReason, blockTTL)
				}
			}
			if adb := attackdb.Global(); adb != nil {
				adb.MarkBlocked(ipStr)
			}
			succeeded = append(succeeded, ipStr)
			count++

		default:
			// Capture the live threat row before dropping it so an undo can
			// restore it exactly, preserving source/expiry, instead of
			// leaving a whitelisted attacker with no threat record.
			if row, ok := captureUndoThreatRow(ipStr, false); ok {
				removedThreats = append(removedThreats, row)
			}
			// Serialize the firewall mutation and history cleanup as one operator action.
			if err := checks.ForgetNetblockHistory(s.cfg.StatePath, ipStr, func() {
				// Mirror apiThreatWhitelistIP flow
				if s.blocker != nil {
					_ = s.blocker.UnblockIP(ipStr)
					if allower, ok := s.blocker.(ipAllower); ok {
						_ = allower.AllowIP(ipStr, "CSM bulk whitelist")
					}
					if warning := coveringSubnetWarning(s.blocker, ipStr); warning != "" {
						warnings = append(warnings, ipStr+": "+warning)
					}
				}
				if tdb := checks.GetThreatDB(); tdb != nil {
					tdb.RemovePermanent(ipStr)
					tdb.AddWhitelist(ipStr)
				}
				if adb := attackdb.Global(); adb != nil {
					adb.RemoveIP(ipStr)
				}
			}); err != nil {
				warnings = append(warnings, ipStr+": subnet history cleanup failed: "+err.Error())
				continue
			}

			flushCphulk(ipStr)
			succeeded = append(succeeded, ipStr)
			count++
		}
	}

	auditDetail := ""
	if blockAction {
		auditDetail = "24h block"
		if permanent {
			auditDetail = "permanent block"
		}
		auditDetail += ": "
	}
	auditDetail += strings.Join(succeeded, ", ")
	s.auditLog(r, "threat_bulk_"+req.Action, fmt.Sprintf("%d IPs", count), auditDetail)

	var undoToken string
	if count > 0 {
		inverse := undoInverseThreatBlock
		summary := fmt.Sprintf("Blocked %d IPs", count)
		action := "threat_bulk_block"
		switch {
		case permanent:
			summary = fmt.Sprintf("Permanently blocked %d IPs", count)
			action = "threat_bulk_block_permanent"
		case !blockAction:
			inverse = undoInverseThreatWhitelist
			summary = fmt.Sprintf("Whitelisted %d IPs", count)
			action = "threat_bulk_whitelist"
		}
		undoToken = s.recordUndoEntry(r, action, inverse, summary,
			undoPayloadIPs{IPs: succeeded, RestoreThreats: removedThreats, BlockSnapshot: blockAction, RestoreBlocks: priorBlocks, ExpectedBlocks: expectedBlocks})
	}

	writeJSON(w, map[string]interface{}{
		"ok":         true,
		"count":      count,
		"permanent":  permanent,
		"undo_token": undoToken,
		"warnings":   warnings,
	})
}

// writeJSON is defined in api.go
