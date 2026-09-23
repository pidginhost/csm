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
		writeJSONError(w, "attack database not initialized", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, adb.Stats())
}

// GET /api/v1/threat/top-attackers?limit=25
func (s *Server) apiThreatTopAttackers(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 25)
	if limit > 200 {
		limit = 200
	}
	adb := attackdb.Global()
	if adb == nil {
		writeItems(w, []struct{}{}, map[string]interface{}{"limit": limit, "truncated": false})
		return
	}

	// One record past the limit tells whether the list was cut.
	recs := adb.TopAttackers(limit + 1)
	truncated := len(recs) > limit
	if truncated {
		recs = recs[:limit]
	}

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

	writeItems(w, results, map[string]interface{}{"limit": limit, "truncated": truncated})
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
		writeItems(w, []attackdb.Event{}, map[string]interface{}{"limit": limit, "truncated": false})
		return
	}

	// One event past the limit tells whether older events were left out.
	events := adb.QueryEvents(ip, limit+1)
	truncated := len(events) > limit
	if truncated {
		events = events[:limit]
	}
	writeItems(w, events, map[string]interface{}{"limit": limit, "truncated": truncated})
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

	actions, historyErr := s.releaseIP(req.IP, ipRelease{allow: releaseAllow, reason: "CSM whitelist: customer IP"})

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
		"ip":      req.IP,
		"actions": actions,
	}
	if warning != "" {
		resp["warning"] = warning
	}
	writeOK(w, resp)
}

// GET /api/v1/threat/whitelist - list all whitelisted IPs
func (s *Server) apiThreatWhitelist(w http.ResponseWriter, r *http.Request) {
	tdb := checks.GetThreatDB()
	if tdb == nil {
		writeAll(w, []checks.WhitelistIP{})
		return
	}
	writeAll(w, tdb.WhitelistedIPs())
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

	writeOK(w, map[string]interface{}{"ip": req.IP})
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
	writeOK(w, map[string]interface{}{
		"ip":        req.IP,
		"permanent": permanent,
		"actions":   actions,
	})
}

// POST /api/v1/threat/clear-ip - unblock + clear from all DBs without whitelisting.
// For dynamic IP customers: one-time cleanup, IP can be re-blocked later.
// ipRelease says how releaseIP lets an address go. The zero value unblocks
// and forgets it without allowing it (Unblock & Clear).
type ipRelease struct {
	allow  releaseAllowMode
	ttl    time.Duration // for releaseTempAllow
	reason string        // firewall allow rule comment
}

type releaseAllowMode int

const (
	releaseNoAllow releaseAllowMode = iota
	releaseAllow
	releaseTempAllow
)

// releaseIP is the shared tail of whitelist, temporary whitelist, clear and
// bulk whitelist: unblock the address in the firewall, allow it as rel says,
// drop it from the threat database's permanent list (whitelisting it there
// too when allowed), and forget it in the attack database, all inside the
// netblock-history lock so the history cleanup is one operator action with
// the firewall change. cPHulk's login history is flushed after. It returns
// the steps that took effect and the history cleanup error; the firewall and
// database changes have happened either way, so callers still audit.
func (s *Server) releaseIP(ip string, rel ipRelease) ([]string, error) {
	var actions []string
	hours := int(rel.ttl / time.Hour)
	err := checks.ForgetNetblockHistory(s.cfg.StatePath, ip, func() {
		if s.blocker != nil {
			if err := s.blocker.UnblockIP(ip); err == nil {
				actions = append(actions, "unblocked from firewall")
			}
			switch rel.allow {
			case releaseAllow:
				if allower, ok := s.blocker.(ipAllower); ok {
					if err := allower.AllowIP(ip, rel.reason); err == nil {
						actions = append(actions, "added to firewall allow list")
					}
				}
			case releaseTempAllow:
				if allower, ok := s.blocker.(ipTempAllower); ok {
					if err := allower.TempAllowIP(ip, rel.reason, rel.ttl); err == nil {
						actions = append(actions, fmt.Sprintf("temp allowed in firewall for %dh", hours))
					}
				}
			}
		}
		if tdb := checks.GetThreatDB(); tdb != nil {
			tdb.RemovePermanent(ip)
			switch rel.allow {
			case releaseAllow:
				tdb.AddWhitelist(ip)
				actions = append(actions, "removed from threat DB, added to whitelist")
			case releaseTempAllow:
				tdb.TempWhitelist(ip, rel.ttl)
				actions = append(actions, fmt.Sprintf("temp whitelisted for %dh", hours))
			default:
				actions = append(actions, "removed from threat DB")
			}
		}
		if adb := attackdb.Global(); adb != nil {
			adb.RemoveIP(ip)
			actions = append(actions, "removed from attack DB")
		}
	})
	if err == nil {
		actions = append(actions, "removed from subnet block history")
	}
	if flushCphulk(ip) == nil {
		actions = append(actions, "flushed cPanel login history")
	}
	return actions, err
}

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

	actions, historyErr := s.releaseIP(req.IP, ipRelease{})

	s.auditLog(r, "clear_ip", req.IP, "unblock & clear")
	if historyErr != nil {
		writeJSONError(w, "IP action applied, but subnet history cleanup failed: "+historyErr.Error(), http.StatusInternalServerError)
		return
	}
	writeOK(w, map[string]interface{}{
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
	actions, historyErr := s.releaseIP(req.IP, ipRelease{allow: releaseTempAllow, ttl: ttl, reason: "CSM temp whitelist"})

	s.auditLog(r, "temp_whitelist_ip", req.IP, fmt.Sprintf("%dh temp whitelist", req.Hours))
	if historyErr != nil {
		writeJSONError(w, "IP action applied, but subnet history cleanup failed: "+historyErr.Error(), http.StatusInternalServerError)
		return
	}
	writeOK(w, map[string]interface{}{
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
			if _, err := s.releaseIP(ipStr, ipRelease{allow: releaseAllow, reason: "CSM bulk whitelist"}); err != nil {
				warnings = append(warnings, ipStr+": subnet history cleanup failed: "+err.Error())
				continue
			}
			if s.blocker != nil {
				if warning := coveringSubnetWarning(s.blocker, ipStr); warning != "" {
					warnings = append(warnings, ipStr+": "+warning)
				}
			}
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

	if warnings == nil {
		warnings = []string{}
	}
	fields := map[string]interface{}{
		"count":     count,
		"permanent": permanent,
		"warnings":  warnings,
	}
	if count == 0 {
		// Nothing changed: an error, with the reasons each address gave.
		msg := "No address was changed"
		if len(warnings) > 0 {
			msg += ": " + strings.Join(warnings, "; ")
		}
		fields["error"] = msg
		writeJSONStatus(w, http.StatusUnprocessableEntity, fields)
		return
	}
	if undoToken != "" {
		fields["undo_token"] = undoToken
	}
	writeOK(w, fields)
}

// writeJSON is defined in api.go
