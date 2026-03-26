package webui

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
	"github.com/pidginhost/cpanel-security-monitor/internal/checks"
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

// apiFindings returns current scan results — "what's wrong right now."
func (s *Server) apiFindings(w http.ResponseWriter, _ *http.Request) {
	latest := s.store.LatestFindings()

	type entryView struct {
		Severity int    `json:"severity"`
		Check    string `json:"check"`
		Message  string `json:"message"`
		Details  string `json:"details,omitempty"`
		Time     string `json:"time"`
		HasFix   bool   `json:"has_fix"`
	}

	var result []entryView
	for _, f := range latest {
		if f.Check == "auto_response" || f.Check == "auto_block" || f.Check == "check_timeout" || f.Check == "health" {
			continue
		}
		result = append(result, entryView{
			Severity: int(f.Severity),
			Check:    f.Check,
			Message:  f.Message,
			Details:  f.Details,
			Time:     f.Timestamp.Format(time.RFC3339),
			HasFix:   checks.HasFix(f.Check),
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

// apiHealth returns daemon health status.
func (s *Server) apiHealth(w http.ResponseWriter, _ *http.Request) {
	health := map[string]interface{}{
		"daemon_mode":    true,
		"uptime":         time.Since(s.startTime).String(),
		"uptime_seconds": int(time.Since(s.startTime).Seconds()),
		"ws_clients":     s.hub.ClientCount(),
		"rules_loaded":   s.sigCount,
		"fanotify":       s.fanotifyActive,
		"log_watchers":   s.logWatcherCount,
	}
	writeJSON(w, health)
}

// apiHistoryCSV exports history as CSV download.
func (s *Server) apiHistoryCSV(w http.ResponseWriter, _ *http.Request) {
	findings, _ := s.store.ReadHistory(5000, 0)

	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=csm-history.csv")

	// CSV header
	fmt.Fprintf(w, "Timestamp,Severity,Check,Message,Details\n")
	for _, f := range findings {
		sev := "WARNING"
		switch f.Severity {
		case alert.Critical:
			sev = "CRITICAL"
		case alert.High:
			sev = "HIGH"
		}
		// Escape CSV fields
		msg := csvEscape(f.Message)
		details := csvEscape(f.Details)
		fmt.Fprintf(w, "%s,%s,%s,%s,%s\n",
			f.Timestamp.Format(time.RFC3339), sev, f.Check, msg, details)
	}
}

func csvEscape(s string) string {
	if strings.ContainsAny(s, ",\"\n\r") {
		return "\"" + strings.ReplaceAll(s, "\"", "\"\"") + "\""
	}
	return s
}

// apiFix applies a known remediation action for a finding.
// POST /api/v1/fix  body: {"check": "check_type", "message": "...", "details": "..."}
func (s *Server) apiFix(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Check   string `json:"check"`
		Message string `json:"message"`
		Details string `json:"details"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Check == "" {
		writeJSONError(w, "check and message are required", http.StatusBadRequest)
		return
	}

	if !checks.HasFix(req.Check) {
		writeJSONError(w, "no automated fix available for this check type", http.StatusBadRequest)
		return
	}

	result := checks.ApplyFix(req.Check, req.Message, req.Details)

	// If fix succeeded, dismiss the finding from state
	if result.Success {
		key := req.Check + ":" + req.Message
		s.store.DismissFinding(key)
	}

	writeJSON(w, result)
}

// apiBulkFix applies fixes to multiple findings at once.
// POST /api/v1/fix-bulk  body: [{"check":"...", "message":"...", "details":"..."}, ...]
func (s *Server) apiBulkFix(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var reqs []struct {
		Check   string `json:"check"`
		Message string `json:"message"`
		Details string `json:"details"`
	}
	if err := json.NewDecoder(r.Body).Decode(&reqs); err != nil {
		writeJSONError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	var results []checks.RemediationResult
	for _, req := range reqs {
		if !checks.HasFix(req.Check) {
			results = append(results, checks.RemediationResult{
				Error: fmt.Sprintf("no fix for %s", req.Check),
			})
			continue
		}
		result := checks.ApplyFix(req.Check, req.Message, req.Details)
		if result.Success {
			key := req.Check + ":" + req.Message
			s.store.DismissFinding(key)
		}
		results = append(results, result)
	}

	succeeded := 0
	for _, r := range results {
		if r.Success {
			succeeded++
		}
	}

	writeJSON(w, map[string]interface{}{
		"results":   results,
		"total":     len(results),
		"succeeded": succeeded,
		"failed":    len(results) - succeeded,
	})
}

// apiFixPreview returns what a fix would do without applying it.
// GET /api/v1/fix-preview?check=...&message=...
func (s *Server) apiFixPreview(w http.ResponseWriter, r *http.Request) {
	checkType := r.URL.Query().Get("check")
	message := r.URL.Query().Get("message")

	desc := checks.FixDescription(checkType, message)
	if desc == "" {
		writeJSONError(w, "no fix available", http.StatusNotFound)
		return
	}

	writeJSON(w, map[string]string{
		"check":       checkType,
		"description": desc,
	})
}

// apiAccounts returns a list of cPanel account usernames for the scan dropdown.
func (s *Server) apiAccounts(w http.ResponseWriter, _ *http.Request) {
	entries, err := os.ReadDir("/home")
	if err != nil {
		writeJSON(w, []string{})
		return
	}

	var accounts []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		// Skip system/hidden directories
		if strings.HasPrefix(name, ".") || name == "virtfs" || name == "cPanelInstall" ||
			name == "cpanelsolr" || name == "lost+found" {
			continue
		}
		// Must have public_html to be a real cPanel account
		if _, err := os.Stat(filepath.Join("/home", name, "public_html")); err == nil {
			accounts = append(accounts, name)
		}
	}

	writeJSON(w, accounts)
}

// --- Action endpoints ---

// apiBlockIP blocks an IP via the firewall engine (or CSF fallback).
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
	if net.ParseIP(req.IP) == nil {
		writeJSONError(w, "Invalid IP address format", http.StatusBadRequest)
		return
	}
	if req.Reason == "" {
		req.Reason = "Blocked via CSM Web UI"
	}

	if s.blocker != nil {
		if err := s.blocker.BlockIP(req.IP, req.Reason, 0); err != nil {
			writeJSONError(w, fmt.Sprintf("Block failed: %v", err), http.StatusInternalServerError)
			return
		}
	} else {
		out, err := exec.Command("csf", "-d", req.IP, req.Reason).CombinedOutput()
		if err != nil {
			writeJSONError(w, fmt.Sprintf("CSF block failed: %s", string(out)), http.StatusInternalServerError)
			return
		}
	}

	writeJSON(w, map[string]string{"status": "blocked", "ip": req.IP})
}

// apiUnblockIP removes an IP from the firewall (or CSF fallback).
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

	if s.blocker != nil {
		if err := s.blocker.UnblockIP(req.IP); err != nil {
			writeJSONError(w, fmt.Sprintf("Unblock failed: %v", err), http.StatusInternalServerError)
			return
		}
	} else {
		out, err := exec.Command("csf", "-dr", req.IP).CombinedOutput()
		if err != nil {
			writeJSONError(w, fmt.Sprintf("CSF unblock failed: %s", string(out)), http.StatusInternalServerError)
			return
		}
	}

	writeJSON(w, map[string]string{"status": "unblocked", "ip": req.IP})
}

// apiBlockedIPs returns the list of currently blocked IPs.
// Reads from firewall engine state if available, falls back to CSF blocked_ips.json.
func (s *Server) apiBlockedIPs(w http.ResponseWriter, _ *http.Request) {
	type blockedView struct {
		IP        string `json:"ip"`
		Reason    string `json:"reason"`
		BlockedAt string `json:"blocked_at"`
		ExpiresAt string `json:"expires_at"`
		ExpiresIn string `json:"expires_in"`
	}

	var result []blockedView
	now := time.Now()

	// Try firewall engine state first
	fwFile := filepath.Join(s.cfg.StatePath, "firewall", "state.json")
	if fwData, err := os.ReadFile(fwFile); err == nil {
		var fwState struct {
			Blocked []struct {
				IP        string    `json:"ip"`
				Reason    string    `json:"reason"`
				BlockedAt time.Time `json:"blocked_at"`
				ExpiresAt time.Time `json:"expires_at"`
			} `json:"blocked"`
		}
		if json.Unmarshal(fwData, &fwState) == nil {
			for _, b := range fwState.Blocked {
				if !b.ExpiresAt.IsZero() && now.After(b.ExpiresAt) {
					continue
				}
				view := blockedView{
					IP:        b.IP,
					Reason:    b.Reason,
					BlockedAt: b.BlockedAt.Format(time.RFC3339),
				}
				if !b.ExpiresAt.IsZero() {
					remaining := time.Until(b.ExpiresAt)
					view.ExpiresAt = b.ExpiresAt.Format(time.RFC3339)
					view.ExpiresIn = fmt.Sprintf("%dh%dm", int(remaining.Hours()), int(remaining.Minutes())%60)
				} else {
					view.ExpiresIn = "permanent"
				}
				result = append(result, view)
			}
			writeJSON(w, result)
			return
		}
	}

	// Fall back to CSF blocked_ips.json
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

	for _, b := range blockState.IPs {
		view := blockedView{
			IP:        b.IP,
			Reason:    b.Reason,
			BlockedAt: b.BlockedAt.Format(time.RFC3339),
		}
		if !b.ExpiresAt.IsZero() {
			expiresIn := time.Until(b.ExpiresAt)
			if expiresIn < 0 {
				continue // expired
			}
			view.ExpiresAt = b.ExpiresAt.Format(time.RFC3339)
			view.ExpiresIn = fmt.Sprintf("%dh%dm", int(expiresIn.Hours()), int(expiresIn.Minutes())%60)
		} else {
			view.ExpiresIn = "permanent"
		}
		result = append(result, view)
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
	s.store.DismissLatestFinding(req.Key)
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
		writeJSONError(w, fmt.Sprintf("Cannot create parent directory: %v", mkdirErr), http.StatusInternalServerError)
		return
	}

	// Check if quarantined item is a directory or file
	quarInfo, err := os.Stat(quarFile)
	if err != nil {
		writeJSONError(w, fmt.Sprintf("Cannot stat quarantined file: %v", err), http.StatusInternalServerError)
		return
	}

	// Parse original mode from metadata (format: "-rw-r--r--" or "drwxr-xr-x")
	restoredMode := os.FileMode(0644)
	if meta.Mode != "" && len(meta.Mode) >= 10 {
		restoredMode = parseModeString(meta.Mode)
	}

	if quarInfo.IsDir() {
		// Directory restore: use os.Rename (same device)
		if err := os.Rename(quarFile, meta.OriginalPath); err != nil {
			writeJSONError(w, fmt.Sprintf("Cannot restore directory: %v", err), http.StatusInternalServerError)
			return
		}
	} else {
		// File restore: copy back with original permissions
		data, readErr := os.ReadFile(quarFile)
		if readErr != nil {
			writeJSONError(w, fmt.Sprintf("Cannot read quarantined file: %v", readErr), http.StatusInternalServerError)
			return
		}
		if writeErr := os.WriteFile(meta.OriginalPath, data, restoredMode); writeErr != nil {
			writeJSONError(w, fmt.Sprintf("Cannot write restored file: %v", writeErr), http.StatusInternalServerError)
			return
		}
		os.Remove(quarFile)
	}

	// Restore ownership
	_ = syscall.Chown(meta.OriginalPath, meta.Owner, meta.Group)
	// Restore mode explicitly (WriteFile may be affected by umask)
	_ = os.Chmod(meta.OriginalPath, restoredMode)

	// Remove metadata sidecar
	os.Remove(metaFile)

	writeJSON(w, map[string]string{
		"status":  "restored",
		"path":    meta.OriginalPath,
		"warning": "File restored to original location. Re-scan recommended.",
	})
}

// apiScanAccount runs an on-demand scan for a single cPanel account.
// POST /api/v1/scan-account  body: {"account": "username"}
func (s *Server) apiScanAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Account string `json:"account"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Account == "" {
		writeJSONError(w, "Account name is required", http.StatusBadRequest)
		return
	}

	// Sanitize — only allow alphanumeric + underscore (cPanel usernames)
	for _, c := range req.Account {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			writeJSONError(w, "Invalid account name", http.StatusBadRequest)
			return
		}
	}

	// Rate limit: only one scan at a time
	if !s.acquireScan() {
		writeJSONError(w, "A scan is already in progress. Please wait.", http.StatusTooManyRequests)
		return
	}
	defer s.releaseScan()

	start := time.Now()
	findings := checks.RunAccountScan(s.cfg, s.store, req.Account)
	elapsed := time.Since(start).Round(time.Millisecond)

	result := map[string]interface{}{
		"account":  req.Account,
		"findings": findings,
		"count":    len(findings),
		"elapsed":  elapsed.String(),
	}
	writeJSON(w, result)
}

// parseModeString converts a permission string like "-rw-r--r--" to os.FileMode.
func parseModeString(s string) os.FileMode {
	if len(s) < 10 {
		return 0644
	}
	var mode os.FileMode
	perms := s[len(s)-9:] // last 9 chars: "rwxr-xr-x"
	bits := []os.FileMode{
		0400, 0200, 0100, // owner r/w/x
		0040, 0020, 0010, // group r/w/x
		0004, 0002, 0001, // other r/w/x
	}
	for i, b := range bits {
		if i < len(perms) && perms[i] != '-' {
			mode |= b
		}
	}
	if mode == 0 {
		mode = 0644 // fallback
	}
	return mode
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
