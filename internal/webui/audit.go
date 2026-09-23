package webui

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
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

// readUIAuditLog returns the last N audit entries, newest first (all when
// limit is 0). It reads the log from the end, so asking for the newest few
// does not parse up to maxUIAuditSize of older entries.
func readUIAuditLog(statePath string, limit int) []UIAuditEntry {
	path := filepath.Join(statePath, uiAuditFile)
	// #nosec G304 -- filepath.Join under operator-configured statePath.
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil
	}
	return tailAuditEntries(f, info.Size(), limit)
}

// tailAuditEntries parses the audit lines in r[0:size] newest first and stops
// once limit entries are found (0 means all). Lines that are blank or not an
// entry are skipped; one line may be as long as the log (bulk undo targets).
func tailAuditEntries(r io.ReaderAt, size int64, limit int) []UIAuditEntry {
	var out []UIAuditEntry
	done := func(line []byte) bool {
		line = bytes.TrimRight(line, "\r")
		if len(line) == 0 {
			return false
		}
		var entry UIAuditEntry
		if json.Unmarshal(line, &entry) == nil {
			out = append(out, entry)
		}
		return limit > 0 && len(out) >= limit
	}

	// head holds the bytes before the earliest newline seen so far: the
	// unfinished start of a line. Chunks grow with it, so a long line is
	// read in a logarithmic number of steps.
	var head []byte
	end := size
	for end > 0 {
		n := int64(64 * 1024)
		if int64(len(head)) > n {
			n = int64(len(head))
		}
		start := max(end-n, 0)
		data := make([]byte, end-start, end-start+int64(len(head)))
		if _, err := r.ReadAt(data, start); err != nil && err != io.EOF {
			return out
		}
		data = append(data, head...)
		for {
			i := bytes.LastIndexByte(data, '\n')
			if i < 0 {
				break
			}
			if done(data[i+1:]) {
				return out
			}
			data = data[:i]
		}
		head = data
		end = start
	}
	done(head)
	return out
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

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	s.renderTemplate(w, r, "audit.html", map[string]string{
		"Hostname": s.cfg.Hostname,
	})
}

// uiAuditPageLimit is how many of the newest UI audit entries the API returns.
const uiAuditPageLimit = 200

// GET /api/v1/audit - return the newest UI audit log entries
func (s *Server) apiUIAudit(w http.ResponseWriter, r *http.Request) {
	// One entry past the limit tells whether older entries were left out.
	entries := readUIAuditLog(s.cfg.StatePath, uiAuditPageLimit+1)
	truncated := len(entries) > uiAuditPageLimit
	if truncated {
		entries = entries[:uiAuditPageLimit]
	}
	writeItems(w, entries, map[string]interface{}{"limit": uiAuditPageLimit, "truncated": truncated})
}
