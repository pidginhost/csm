package webui

import (
	"net/http"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/session"
)

type browserSessionView struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Created   time.Time `json:"created"`
	LastSeen  time.Time `json:"last_seen"`
	Expires   time.Time `json:"expires"`
	RemoteIP  string    `json:"remote_ip"`
	UserAgent string    `json:"user_agent"`
	Current   bool      `json:"current"`
}

func (s *Server) browserSessionViews(r *http.Request) ([]browserSessionView, error) {
	if s.sessions == nil {
		return nil, errNoStore
	}
	records, err := s.sessions.List(s.sessionNow())
	if err != nil {
		return nil, err
	}
	current := ""
	if cookie, err := r.Cookie("csm_auth"); err == nil {
		current = session.Hash(cookie.Value)
	}
	views := make([]browserSessionView, 0, len(records))
	for _, rec := range records {
		views = append(views, browserSessionView{ID: rec.ID, Name: rec.Name, Created: rec.Created,
			LastSeen: rec.LastSeen, Expires: rec.Expires, RemoteIP: rec.RemoteIP, UserAgent: rec.UserAgent, Current: rec.Verifier == current})
	}
	return views, nil
}

func (s *Server) apiSessions(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/sessions")
	if id != "" {
		id = strings.TrimPrefix(id, "/")
		if !validSessionID(id) {
			writeJSONError(w, "Session not found", http.StatusNotFound)
			return
		}
	}
	switch r.Method {
	case http.MethodGet:
		if id != "" {
			writeJSONError(w, "Session not found", http.StatusNotFound)
			return
		}
		views, err := s.browserSessionViews(r)
		if err != nil {
			writeJSONError(w, "Session store unavailable", http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, map[string]any{"sessions": views})
	case http.MethodDelete:
		if s.sessions == nil {
			writeJSONError(w, "Session store unavailable", http.StatusServiceUnavailable)
			return
		}
		actor, via := s.requestActor(r)
		if id != "" && !s.sessionExists(id) {
			writeJSONError(w, "Session not found", http.StatusNotFound)
			return
		}
		var err error
		if id == "" {
			err = s.sessions.RevokeAll()
		} else {
			err = s.sessions.Revoke(id)
		}
		if err != nil {
			writeJSONError(w, "Cannot revoke browser session", http.StatusServiceUnavailable)
			return
		}
		s.auditSessionRevoke(r, actor, via, id)
		if id == "" {
			clearBrowserCookie(w)
		}
		writeOK(w, nil)
	default:
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// sessionExists reports whether id names an active browser session, so
// revoking an unknown one answers 404 instead of a success that did nothing.
func (s *Server) sessionExists(id string) bool {
	records, err := s.sessions.List(s.sessionNow())
	if err != nil {
		return false
	}
	for _, rec := range records {
		if rec.ID == id {
			return true
		}
	}
	return false
}

func validSessionID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, ch := range id {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return false
		}
	}
	return true
}

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	views, err := s.browserSessionViews(r)
	if err != nil {
		http.Error(w, "Session store unavailable", http.StatusServiceUnavailable)
		return
	}
	s.renderTemplate(w, r, "sessions.html", map[string]any{"Sessions": views})
}

func (s *Server) handleSessionRevoke(w http.ResponseWriter, r *http.Request) {
	if s.sessions == nil {
		http.Error(w, "Session store unavailable", http.StatusServiceUnavailable)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	id := r.PostForm.Get("id")
	actor, via := s.requestActor(r)
	var err error
	switch {
	case id == "all":
		err = s.sessions.RevokeAll()
	case validSessionID(id):
		err = s.sessions.Revoke(id)
	default:
		http.Error(w, "Invalid session", http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, "Cannot revoke browser session", http.StatusServiceUnavailable)
		return
	}
	target := id
	if id == "all" {
		target = ""
	}
	s.auditSessionRevoke(r, actor, via, target)
	if id == "all" {
		clearBrowserCookie(w)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/sessions", http.StatusSeeOther)
}

// auditSessionRevoke records a revocation for the actor resolved before it,
// since revoking the caller's own session also ends its attribution. An
// empty id means every browser session.
func (s *Server) auditSessionRevoke(r *http.Request, actor, via, id string) {
	if id == "" {
		s.auditLogAs(r, actor, via, "session_revoke_all", "browser sessions", "every browser session logged out")
		return
	}
	s.auditLogAs(r, actor, via, "session_revoke", id, "browser session revoked")
}
