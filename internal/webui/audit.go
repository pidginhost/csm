package webui

import (
	"bufio"
	"context"
	"encoding/json"
	"log"
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
	// Actor is the name of the credential that acted, and Via says whether
	// it came as an API token or a browser login.
	Actor string `json:"actor,omitempty"`
	Via   string `json:"via,omitempty"`
}

// auditLog records a UI action to the audit log, attributed to the
// credential behind r.
func (s *Server) auditLog(r *http.Request, action, target, details string) {
	actor, via := s.requestActor(r)
	s.auditLogAs(r, actor, via, action, target, details)
}

// auditLogAs records a UI action for an actor resolved by the caller. Login
// has no session yet, and logout or revocation ends the session that made
// the request, so those handlers name the actor themselves.
func (s *Server) auditLogAs(r *http.Request, actor, via, action, target, details string) {
	entry := UIAuditEntry{
		Timestamp: time.Now(),
		Action:    action,
		Target:    target,
		Details:   details,
		SourceIP:  extractClientIP(r),
		Actor:     actor,
		Via:       via,
	}

	path := filepath.Join(s.cfg.StatePath, uiAuditFile)
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	data = append(data, '\n')

	// Rotation and append are one step: two writers that both saw an
	// oversized log would otherwise rotate twice and rename the fresh file
	// over the archived history.
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	if info, statErr := os.Stat(path); statErr == nil && info.Size() > maxUIAuditSize {
		if renameErr := os.Rename(path, path+".1"); renameErr != nil {
			log.Printf("webui: audit rotation failed for %s: %v", path, renameErr)
		}
	}

	// #nosec G304 -- filepath.Join under operator-configured StatePath.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		log.Printf("webui: audit open failed for %s: %v", path, err)
		return
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		log.Printf("webui: audit write failed for %s: %v", path, err)
		return
	}
	if err := f.Close(); err != nil {
		log.Printf("webui: audit close failed for %s: %v", path, err)
	}
}

type auditActorKey struct{}

type auditActor struct{ name, via string }

func withAuditActor(r *http.Request, actor, via string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), auditActorKey{}, auditActor{actor, via}))
}

// requestActor uses the identity captured at authorization so an action
// finishing after logout or expiry keeps its actor. Direct callers resolve
// against startup credentials without refreshing session activity.
func (s *Server) requestActor(r *http.Request) (actor, via string) {
	if r == nil {
		return "", ""
	}
	if actor, ok := r.Context().Value(auditActorKey{}).(auditActor); ok {
		return actor.name, actor.via
	}
	// Match authorization's cookie-first order, including credential binding.
	if tok, ok := s.cookieSessionCredential(r, "admin", false); ok {
		return tok.Name, "browser"
	}
	if tok, ok := s.bearerCredentialWithScope(r, "admin"); ok {
		return tok.Name, "api"
	}
	return "", ""
}

func extractClientIP(r *http.Request) string {
	// Use RemoteAddr directly - XFF is trivially spoofable and this is
	// a security audit log, so we only trust the TCP connection source.
	return clientIPKey(r.RemoteAddr)
}

// readUIAuditLog returns the last N audit entries.
func readUIAuditLog(statePath string, limit int) []UIAuditEntry {
	path := filepath.Join(statePath, uiAuditFile)
	// #nosec G304 -- filepath.Join under operator-configured statePath.
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	var all []UIAuditEntry
	scanner := bufio.NewScanner(f)
	// Bulk undo targets can exceed the old per-line limit. One such entry
	// must not stop the reader before every subsequent operator action.
	scanner.Buffer(make([]byte, 256*1024), maxUIAuditSize)
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

// searchAuditEntries returns audit entries whose target or details contain the search string.
func (s *Server) searchAuditEntries(search string, limit int) []UIAuditEntry {
	if search == "" || limit <= 0 {
		return nil
	}
	readLimit := limit * 10
	if readLimit > 5000 {
		readLimit = 5000
	}
	all := readUIAuditLog(s.cfg.StatePath, readLimit)
	searchLower := strings.ToLower(search)
	var matched []UIAuditEntry
	for _, e := range all {
		if strings.Contains(strings.ToLower(e.Target), searchLower) ||
			strings.Contains(strings.ToLower(e.Details), searchLower) ||
			strings.Contains(strings.ToLower(e.Action), searchLower) {
			matched = append(matched, e)
			if len(matched) >= limit {
				break
			}
		}
	}
	return matched
}

func (s *Server) handleAudit(w http.ResponseWriter, _ *http.Request) {
	s.renderTemplate(w, "audit.html", map[string]string{
		"Hostname": s.cfg.Hostname,
	})
}

// GET /api/v1/audit - return UI audit log
func (s *Server) apiUIAudit(w http.ResponseWriter, r *http.Request) {
	entries := readUIAuditLog(s.cfg.StatePath, 200)
	if entries == nil {
		entries = []UIAuditEntry{}
	}
	writeJSON(w, entries)
}
