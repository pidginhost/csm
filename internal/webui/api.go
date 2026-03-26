package webui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
	"github.com/pidginhost/cpanel-security-monitor/internal/state"
)

// apiStatus returns daemon status and uptime.
func (s *Server) apiStatus(w http.ResponseWriter, _ *http.Request) {
	status := map[string]interface{}{
		"hostname":     s.cfg.Hostname,
		"uptime":       time.Since(s.startTime).String(),
		"started_at":   s.startTime.Format(time.RFC3339),
		"ws_clients":   s.hub.ClientCount(),
		"rules_loaded": s.sigCount,
	}
	writeJSON(w, status)
}

// apiFindings returns current active state entries.
func (s *Server) apiFindings(w http.ResponseWriter, _ *http.Request) {
	entries := s.store.Entries()

	type entryView struct {
		Check     string `json:"check"`
		Message   string `json:"message"`
		FirstSeen string `json:"first_seen"`
		LastSeen  string `json:"last_seen"`
		Baseline  bool   `json:"is_baseline"`
	}

	var result []entryView
	for key, entry := range entries {
		check, message := state.ParseKey(key)
		result = append(result, entryView{
			Check:     check,
			Message:   message,
			FirstSeen: entry.FirstSeen.Format(time.RFC3339),
			LastSeen:  entry.LastSeen.Format(time.RFC3339),
			Baseline:  entry.IsBaseline,
		})
	}
	writeJSON(w, result)
}

// apiHistory returns paginated history from history.jsonl.
func (s *Server) apiHistory(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 50)
	offset := queryInt(r, "offset", 0)

	findings, total := s.store.ReadHistory(limit, offset)

	result := map[string]interface{}{
		"findings": findings,
		"total":    total,
		"limit":    limit,
		"offset":   offset,
	}
	writeJSON(w, result)
}

// apiQuarantine lists quarantined files with metadata.
func (s *Server) apiQuarantine(w http.ResponseWriter, _ *http.Request) {
	const quarantineDir = "/opt/csm/quarantine"

	type quarantineEntry struct {
		ID           string `json:"id"`
		OriginalPath string `json:"original_path"`
		Size         int64  `json:"size"`
		QuarantineAt string `json:"quarantined_at"`
		Reason       string `json:"reason"`
	}

	var entries []quarantineEntry

	metaFiles, _ := filepath.Glob(filepath.Join(quarantineDir, "*.meta"))
	for _, metaFile := range metaFiles {
		data, err := os.ReadFile(metaFile)
		if err != nil {
			continue
		}

		var meta struct {
			OriginalPath string    `json:"original_path"`
			Size         int64     `json:"size"`
			QuarantineAt time.Time `json:"quarantine_at"`
			Reason       string    `json:"reason"`
		}
		if err := json.Unmarshal(data, &meta); err != nil {
			continue
		}

		id := filepath.Base(metaFile)
		id = id[:len(id)-5] // remove .meta

		entries = append(entries, quarantineEntry{
			ID:           id,
			OriginalPath: meta.OriginalPath,
			Size:         meta.Size,
			QuarantineAt: meta.QuarantineAt.Format(time.RFC3339),
			Reason:       meta.Reason,
		})
	}

	writeJSON(w, entries)
}

// apiStats returns severity counts and per-check breakdown.
func (s *Server) apiStats(w http.ResponseWriter, _ *http.Request) {
	findings, _ := s.store.ReadHistory(500, 0)

	critical, high, warning := 0, 0, 0
	byCheck := make(map[string]int)
	last24h := time.Now().Add(-24 * time.Hour)

	for _, f := range findings {
		if f.Timestamp.Before(last24h) {
			continue
		}
		switch f.Severity {
		case alert.Critical:
			critical++
		case alert.High:
			high++
		case alert.Warning:
			warning++
		}
		byCheck[f.Check]++
	}

	result := map[string]interface{}{
		"last_24h": map[string]interface{}{
			"critical": critical,
			"high":     high,
			"warning":  warning,
			"total":    critical + high + warning,
		},
		"by_check": byCheck,
	}
	writeJSON(w, result)
}

// --- Action endpoints ---

// apiBlockIP blocks an IP via CSF.
// POST /api/v1/block-ip  body: {"ip": "1.2.3.4", "reason": "..."}
func (s *Server) apiBlockIP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IP     string `json:"ip"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if req.IP == "" {
		writeJSONError(w, "IP is required", http.StatusBadRequest)
		return
	}
	if req.Reason == "" {
		req.Reason = "Blocked via CSM Web UI"
	}

	out, err := exec.Command("csf", "-d", req.IP, req.Reason).CombinedOutput()
	if err != nil {
		writeJSONError(w, fmt.Sprintf("CSF block failed: %s", string(out)), http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]string{"status": "blocked", "ip": req.IP})
}

// apiUnblockIP removes an IP from CSF.
// POST /api/v1/unblock-ip  body: {"ip": "1.2.3.4"}
func (s *Server) apiUnblockIP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IP == "" {
		writeJSONError(w, "IP is required", http.StatusBadRequest)
		return
	}

	out, err := exec.Command("csf", "-dr", req.IP).CombinedOutput()
	if err != nil {
		writeJSONError(w, fmt.Sprintf("CSF unblock failed: %s", string(out)), http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]string{"status": "unblocked", "ip": req.IP})
}

// apiBlockedIPs returns the list of currently blocked IPs from CSF.
func (s *Server) apiBlockedIPs(w http.ResponseWriter, _ *http.Request) {
	// Read from CSM's block state file
	stateFile := filepath.Join(s.cfg.StatePath, "blocked_ips.json")
	data, err := os.ReadFile(stateFile)
	if err != nil {
		writeJSON(w, []interface{}{})
		return
	}

	var blockState struct {
		IPs []struct {
			IP        string    `json:"ip"`
			Reason    string    `json:"reason"`
			BlockedAt time.Time `json:"blocked_at"`
			ExpiresAt time.Time `json:"expires_at"`
		} `json:"ips"`
	}
	if err := json.Unmarshal(data, &blockState); err != nil {
		writeJSON(w, []interface{}{})
		return
	}

	type blockedView struct {
		IP        string `json:"ip"`
		Reason    string `json:"reason"`
		BlockedAt string `json:"blocked_at"`
		ExpiresAt string `json:"expires_at"`
		ExpiresIn string `json:"expires_in"`
	}

	var result []blockedView
	for _, b := range blockState.IPs {
		expiresIn := time.Until(b.ExpiresAt)
		if expiresIn < 0 {
			continue // already expired
		}
		result = append(result, blockedView{
			IP:        b.IP,
			Reason:    b.Reason,
			BlockedAt: b.BlockedAt.Format(time.RFC3339),
			ExpiresAt: b.ExpiresAt.Format(time.RFC3339),
			ExpiresIn: fmt.Sprintf("%dh%dm", int(expiresIn.Hours()), int(expiresIn.Minutes())%60),
		})
	}
	writeJSON(w, result)
}

// apiDismissFinding marks a finding as baseline (acknowledged/dismissed).
// POST /api/v1/dismiss  body: {"key": "check:message"}
func (s *Server) apiDismissFinding(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Key == "" {
		writeJSONError(w, "Key is required", http.StatusBadRequest)
		return
	}

	s.store.DismissFinding(req.Key)
	writeJSON(w, map[string]string{"status": "dismissed", "key": req.Key})
}

// apiQuarantineRestore restores a quarantined file to its original location.
// POST /api/v1/quarantine-restore  body: {"id": "filename"}
func (s *Server) apiQuarantineRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
		writeJSONError(w, "ID is required", http.StatusBadRequest)
		return
	}

	const quarantineDir = "/opt/csm/quarantine"

	// Sanitize ID to prevent path traversal
	id := filepath.Base(req.ID)
	metaFile := filepath.Join(quarantineDir, id+".meta")
	quarFile := filepath.Join(quarantineDir, id)

	metaData, err := os.ReadFile(metaFile)
	if err != nil {
		writeJSONError(w, "Quarantine entry not found", http.StatusNotFound)
		return
	}

	var meta struct {
		OriginalPath string `json:"original_path"`
		Owner        int    `json:"owner_uid"`
		Group        int    `json:"group_gid"`
		Mode         string `json:"mode"`
	}
	if unmarshalErr := json.Unmarshal(metaData, &meta); unmarshalErr != nil {
		writeJSONError(w, "Invalid metadata", http.StatusInternalServerError)
		return
	}

	// Ensure parent directory exists
	parentDir := filepath.Dir(meta.OriginalPath)
	if mkdirErr := os.MkdirAll(parentDir, 0755); mkdirErr != nil {
		writeJSONError(w, fmt.Sprintf("Cannot create parent directory: %v", err), http.StatusInternalServerError)
		return
	}

	// Copy file back (don't use rename — might be cross-device)
	data, err := os.ReadFile(quarFile)
	if err != nil {
		writeJSONError(w, fmt.Sprintf("Cannot read quarantined file: %v", err), http.StatusInternalServerError)
		return
	}

	if err := os.WriteFile(meta.OriginalPath, data, 0644); err != nil {
		writeJSONError(w, fmt.Sprintf("Cannot write restored file: %v", err), http.StatusInternalServerError)
		return
	}

	// Restore ownership
	_ = syscall.Chown(meta.OriginalPath, meta.Owner, meta.Group)

	// Remove quarantined copies
	os.Remove(quarFile)
	os.Remove(metaFile)

	writeJSON(w, map[string]string{
		"status":  "restored",
		"path":    meta.OriginalPath,
		"warning": "File restored to original location. Re-scan recommended.",
	})
}

func writeJSONError(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(data)
}

func queryInt(r *http.Request, key string, defaultVal int) int {
	val := r.URL.Query().Get(key)
	if val == "" {
		return defaultVal
	}
	n, err := strconv.Atoi(val)
	if err != nil || n < 0 {
		return defaultVal
	}
	return n
}
