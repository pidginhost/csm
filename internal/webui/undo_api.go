package webui

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/store"
)

// Recognised inverse-action keys. Each handler that records an undo entry
// sets one of these on the entry; apiUndoRun dispatches based on the value.
const (
	undoInverseThreatBlock       = "threat_bulk_unblock"
	undoInverseThreatUnblock     = "threat_bulk_block"
	undoInverseThreatWhitelist   = "threat_bulk_unwhitelist"
	undoInverseThreatUnwhitelist = "threat_bulk_whitelist"
	undoInverseFirewallUnblock   = "firewall_bulk_reblock"
)

// undoPayloadIPs is the payload schema for every undo entry we currently
// generate: a list of IPs plus an optional reason and timeout. Future undo
// kinds can add their own payload structs alongside this one.
type undoPayloadIPs struct {
	IPs     []string `json:"ips"`
	Reason  string   `json:"reason,omitempty"`
	Timeout string   `json:"timeout,omitempty"` // ParseDuration-compatible
	// RestoreThreats carries the threat-DB rows a bulk whitelist removed so
	// the matching undo can put them back exactly. Only the whitelist path
	// sets it.
	RestoreThreats []undoThreatRow `json:"restore_threats,omitempty"`
}

// undoThreatRow captures a removed threat-DB row's identity so undo can
// restore it with the same source and expiry, instead of resurrecting an
// auto-block row as a never-expiring operator block (or vice versa).
type undoThreatRow struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	Source    string    `json:"source,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitzero"`
}

// recordUndoEntry persists an undo entry for the operator who issued r and
// returns the new entry's ID. The ID lets the calling handler surface the
// undo token to the client in the same response. Any store error is logged
// and swallowed so a bulk action never fails just because the undo queue
// could not be written.
func (s *Server) recordUndoEntry(r *http.Request, action, inverse, summary string, payload undoPayloadIPs) string {
	if r == nil {
		return ""
	}
	opkey := s.operatorKey(r)
	if opkey == "" {
		return ""
	}
	sdb := store.Global()
	if sdb == nil {
		return ""
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	entry, err := sdb.AppendUndoEntry(opkey, store.UndoEntry{
		Action:  action,
		Inverse: inverse,
		Payload: raw,
		Summary: summary,
	})
	if err != nil {
		log.Printf("webui: record undo entry: %v", err)
		return ""
	}
	return entry.ID
}

// undoPendingView is the JSON shape returned to the client. The payload is
// stripped because the client only needs identity + summary to render the
// banner; the server keeps the payload for the actual undo run.
type undoPendingView struct {
	ID         string    `json:"id"`
	Action     string    `json:"action"`
	Inverse    string    `json:"inverse"`
	Summary    string    `json:"summary"`
	RecordedAt time.Time `json:"recorded_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// apiUndoPending returns the latest non-expired undo entry for the operator,
// or an empty object when no entry is queued.
func (s *Server) apiUndoPending(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	opkey := s.operatorKey(r)
	if opkey == "" {
		writeJSONError(w, "Unauthenticated", http.StatusUnauthorized)
		return
	}
	sdb := store.Global()
	if sdb == nil {
		writeJSON(w, map[string]interface{}{})
		return
	}
	entry, ok, err := sdb.LatestUndoEntry(opkey)
	if err != nil {
		writeJSONError(w, "Store error", http.StatusInternalServerError)
		return
	}
	if !ok {
		writeJSON(w, map[string]interface{}{})
		return
	}
	writeJSON(w, undoPendingView{
		ID:         entry.ID,
		Action:     entry.Action,
		Inverse:    entry.Inverse,
		Summary:    entry.Summary,
		RecordedAt: entry.RecordedAt,
		ExpiresAt:  entry.RecordedAt.Add(store.UndoTTL),
	})
}

type undoRunRequest struct {
	ID string `json:"id"`
}

type undoRunResponse struct {
	Status  string `json:"status"`
	Action  string `json:"action"`
	Inverse string `json:"inverse"`
	Count   int    `json:"count"`
}

// apiUndoRun consumes the named undo entry (or the most recent one when id
// is empty) and dispatches its inverse. Each successful undo also writes a
// "undo_<original>" audit entry so the trail records the reversal.
func (s *Server) apiUndoRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	opkey := s.operatorKey(r)
	if opkey == "" {
		writeJSONError(w, "Unauthenticated", http.StatusUnauthorized)
		return
	}
	var req undoRunRequest
	if err := decodeJSONBodyLimited(w, r, 4*1024, &req); err != nil {
		writeJSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	sdb := store.Global()
	if sdb == nil {
		writeJSONError(w, "Store unavailable", http.StatusServiceUnavailable)
		return
	}
	var (
		entry store.UndoEntry
		ok    bool
		err   error
	)
	if req.ID == "" {
		entry, ok, err = sdb.LatestUndoEntry(opkey)
		if err == nil && ok {
			_, _, err = sdb.ConsumeUndoEntry(opkey, entry.ID)
		}
	} else {
		entry, ok, err = sdb.ConsumeUndoEntry(opkey, req.ID)
	}
	if err != nil {
		writeJSONError(w, "Store error", http.StatusInternalServerError)
		return
	}
	if !ok {
		writeJSONError(w, "Undo window expired", http.StatusGone)
		return
	}

	resp, runErr := s.runUndoEntry(r, entry)
	if runErr != nil {
		writeJSONError(w, runErr.Error(), http.StatusInternalServerError)
		return
	}
	s.auditLog(r, "undo_"+entry.Action, fmt.Sprintf("%d items", resp.Count), entry.Summary)
	writeJSON(w, resp)
}

func (s *Server) runUndoEntry(r *http.Request, entry store.UndoEntry) (undoRunResponse, error) {
	var payload undoPayloadIPs
	if len(entry.Payload) > 0 {
		if err := json.Unmarshal(entry.Payload, &payload); err != nil {
			return undoRunResponse{}, fmt.Errorf("decode payload: %w", err)
		}
	}
	resp := undoRunResponse{
		Status:  "ok",
		Action:  entry.Action,
		Inverse: entry.Inverse,
	}
	switch entry.Inverse {
	case undoInverseThreatBlock:
		// Original action blocked IPs; inverse unblocks them.
		resp.Count = s.undoBulkBlock(payload.IPs)
	case undoInverseThreatUnblock:
		// Original unblocked IPs; inverse re-blocks them with the saved reason.
		timeout := parseDuration(payload.Timeout)
		if timeout == 0 {
			timeout = 24 * time.Hour
		}
		reason := payload.Reason
		if reason == "" {
			reason = "Undo: re-block via CSM Web UI"
		}
		count, err := s.undoBulkReblock(payload.IPs, reason, timeout)
		if err != nil {
			return undoRunResponse{}, err
		}
		resp.Count = count
	case undoInverseThreatWhitelist:
		resp.Count = s.undoBulkWhitelist(payload)
	case undoInverseThreatUnwhitelist:
		resp.Count = s.undoBulkUnwhitelist(payload.IPs)
	case undoInverseFirewallUnblock:
		reason := payload.Reason
		if reason == "" {
			reason = "Undo: re-block via CSM Web UI"
		}
		timeout := parseDuration(payload.Timeout)
		if timeout == 0 {
			timeout = 24 * time.Hour
		}
		count, err := s.undoBulkReblock(payload.IPs, reason, timeout)
		if err != nil {
			return undoRunResponse{}, err
		}
		restoreUndoThreatRows(payload.RestoreThreats)
		resp.Count = count
	default:
		return undoRunResponse{}, fmt.Errorf("unknown inverse action %q", entry.Inverse)
	}
	return resp, nil
}

func captureUndoThreatRow(ip string, autoBlockOnly bool) (undoThreatRow, bool) {
	sdb := store.Global()
	if sdb == nil {
		return undoThreatRow{}, false
	}
	entry, ok := sdb.GetPermanentBlock(ip)
	if !ok || entry.Expired(time.Now()) {
		return undoThreatRow{}, false
	}
	if autoBlockOnly && entry.Source != store.ThreatSourceAutoBlock {
		return undoThreatRow{}, false
	}
	return undoThreatRow{
		IP:        entry.IP,
		Reason:    entry.Reason,
		Source:    entry.Source,
		ExpiresAt: entry.ExpiresAt,
	}, true
}

func restoreUndoThreatRows(rows []undoThreatRow) {
	tdb := checks.GetThreatDB()
	if tdb == nil {
		return
	}
	now := time.Now()
	for _, row := range rows {
		if _, err := parseAndValidateIP(row.IP); err != nil {
			continue
		}
		if shouldRestoreUndoThreatAsPermanent(row, now) {
			tdb.AddPermanent(row.IP, row.Reason)
			continue
		}
		if row.ExpiresAt.IsZero() {
			continue
		}
		ttl := row.ExpiresAt.Sub(now)
		if ttl <= 0 {
			continue // already lapsed; nothing worth restoring
		}
		tdb.AddTemporary(row.IP, row.Reason, ttl)
	}
}

func shouldRestoreUndoThreatAsPermanent(row undoThreatRow, now time.Time) bool {
	if row.Source == store.ThreatSourceOperator {
		return row.ExpiresAt.IsZero()
	}
	if row.Source != "" || !row.ExpiresAt.IsZero() {
		return false
	}
	legacy := store.PermanentBlockEntry{Reason: row.Reason}
	return !legacy.Expired(now)
}

func (s *Server) undoBulkBlock(ips []string) int {
	count := 0
	for _, ip := range ips {
		if _, err := parseAndValidateIP(ip); err != nil {
			continue
		}
		if s.blocker != nil {
			_ = s.blocker.UnblockIP(ip)
		}
		if tdb := checks.GetThreatDB(); tdb != nil {
			tdb.RemovePermanent(ip)
		}
		flushCphulk(ip)
		count++
	}
	return count
}

func (s *Server) undoBulkReblock(ips []string, reason string, timeout time.Duration) (int, error) {
	if s.blocker == nil {
		return 0, fmt.Errorf("firewall engine not available")
	}
	count := 0
	for _, ip := range ips {
		if _, err := parseAndValidateIP(ip); err != nil {
			continue
		}
		if err := blockIPForOperator(s.blocker, ip, reason, timeout); err != nil {
			continue
		}
		count++
	}
	return count, nil
}

func (s *Server) undoBulkWhitelist(payload undoPayloadIPs) int {
	count := 0
	for _, ip := range payload.IPs {
		if _, err := parseAndValidateIP(ip); err != nil {
			continue
		}
		if tdb := checks.GetThreatDB(); tdb != nil {
			tdb.RemoveWhitelist(ip)
		}
		// The bulk whitelist added a firewall allow rule; leaving it lets a
		// mis-whitelisted attacker bypass every future block indefinitely.
		if s.blocker != nil {
			if remover, ok := s.blocker.(interface{ RemoveAllowIP(string) error }); ok {
				_ = remover.RemoveAllowIP(ip)
			}
		}
		count++
	}
	// Restore the threat rows the whitelist removed. RemoveWhitelist ran for
	// every IP above, so the whitelist no longer suppresses these adds.
	restoreUndoThreatRows(payload.RestoreThreats)
	return count
}

func (s *Server) undoBulkUnwhitelist(ips []string) int {
	count := 0
	for _, ip := range ips {
		if _, err := parseAndValidateIP(ip); err != nil {
			continue
		}
		if tdb := checks.GetThreatDB(); tdb != nil {
			tdb.AddWhitelist(ip)
		}
		count++
	}
	return count
}
