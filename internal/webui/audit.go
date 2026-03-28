package webui

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	uiAuditFile    = "ui_audit.jsonl"
	maxUIAuditSize = 10 * 1024 * 1024 // 10 MB
)

// UIAuditEntry records a UI action for compliance and accountability.
type UIAuditEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"`              // block, unblock, dismiss, fix, whitelist, etc.
	Target    string    `json:"target"`              // IP, finding key, file path
	Details   string    `json:"details,omitempty"`   // extra context
	SourceIP  string    `json:"source_ip,omitempty"` // admin's IP
}

// auditLog records a UI action to the audit log.
func (s *Server) auditLog(r *http.Request, action, target, details string) {
	entry := UIAuditEntry{
		Timestamp: time.Now(),
		Action:    action,
		Target:    target,
		Details:   details,
		SourceIP:  extractClientIP(r),
	}

	path := filepath.Join(s.cfg.StatePath, uiAuditFile)
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	data = append(data, '\n')

	// Rotate if too large
	if info, statErr := os.Stat(path); statErr == nil && info.Size() > maxUIAuditSize {
		_ = os.Rename(path, path+".1")
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	_, _ = f.Write(data)
}

func extractClientIP(r *http.Request) string {
	// Use RemoteAddr directly — XFF is trivially spoofable and this is
	// a security audit log, so we only trust the TCP connection source.
	host := r.RemoteAddr
	// Strip port from "ip:port" or "[ipv6]:port"
	if last := strings.LastIndex(host, ":"); last >= 0 {
		if host[0] == '[' {
			// IPv6: [::1]:port
			if bracket := strings.Index(host, "]"); bracket >= 0 {
				return host[1:bracket]
			}
		}
		return host[:last]
	}
	return host
}

// readUIAuditLog returns the last N audit entries.
func readUIAuditLog(statePath string, limit int) []UIAuditEntry {
	path := filepath.Join(statePath, uiAuditFile)
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	var all []UIAuditEntry
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 256*1024), 256*1024)
	for scanner.Scan() {
		var entry UIAuditEntry
		if json.Unmarshal(scanner.Bytes(), &entry) == nil {
			all = append(all, entry)
		}
	}

	// Return newest first
	for i, j := 0, len(all)-1; i < j; i, j = i+1, j-1 {
		all[i], all[j] = all[j], all[i]
	}

	if limit > 0 && len(all) > limit {
		all = all[:limit]
	}
	return all
}

func (s *Server) handleAudit(w http.ResponseWriter, _ *http.Request) {
	_ = s.templates["audit.html"].ExecuteTemplate(w, "audit.html", map[string]string{
		"Hostname": s.cfg.Hostname,
	})
}

// GET /api/v1/audit — return UI audit log
func (s *Server) apiUIAudit(w http.ResponseWriter, r *http.Request) {
	entries := readUIAuditLog(s.cfg.StatePath, 200)
	if entries == nil {
		entries = []UIAuditEntry{}
	}
	writeJSON(w, entries)
}
