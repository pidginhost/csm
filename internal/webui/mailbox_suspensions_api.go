package webui

import (
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/pidginhost/csm/internal/store"
)

// MailboxSuspensionRow is a suspension CSM made, with the mail server's live
// state when it could be read.
type MailboxSuspensionRow struct {
	store.MailboxSuspension
	Active        bool `json:"active"`
	StatusUnknown bool `json:"status_unknown,omitempty"`
}

// MailboxSuspensions lists and releases the suspensions CSM made. The daemon
// implements it; tests use a fake.
type MailboxSuspensions interface {
	ListSuspensions() ([]MailboxSuspensionRow, error)
	ReleaseSuspension(id, actor string) error
}

// ErrSuspensionReleased reports a release of a suspension already lifted.
var ErrSuspensionReleased = errors.New("suspension already released")

var suspensionIDRe = regexp.MustCompile(`^[0-9a-f]{16}$`)

// SetMailboxSuspensions installs the daemon's suspension service.
func (s *Server) SetMailboxSuspensions(m MailboxSuspensions) {
	s.mailboxSuspensions = m
}

// apiEmailSuspensionsList handles GET /api/v1/email/suspensions.
func (s *Server) apiEmailSuspensionsList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.mailboxSuspensions == nil {
		writeAll(w, []MailboxSuspensionRow{})
		return
	}
	rows, err := s.mailboxSuspensions.ListSuspensions()
	if err != nil {
		writeJSONError(w, "Failed to list suspended mailboxes", http.StatusInternalServerError)
		return
	}
	writeAll(w, rows)
}

// apiEmailSuspensionAction handles POST /api/v1/email/suspensions/{id}/release.
// It changes the mail server, so it runs under auth + CSRF and is audit-logged.
func (s *Server) apiEmailSuspensionAction(w http.ResponseWriter, r *http.Request) {
	tail := strings.TrimPrefix(r.URL.Path, "/api/v1/email/suspensions/")
	id, action, _ := strings.Cut(tail, "/")
	if !suspensionIDRe.MatchString(id) {
		writeJSONError(w, "Invalid suspension ID", http.StatusBadRequest)
		return
	}
	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if action != "release" {
		writeJSONError(w, "Unknown action; use /release", http.StatusBadRequest)
		return
	}
	if s.mailboxSuspensions == nil {
		writeJSONError(w, "Mailbox suspensions are not available on this host", http.StatusServiceUnavailable)
		return
	}
	actor, _ := s.requestActor(r)
	if err := s.mailboxSuspensions.ReleaseSuspension(id, actor); err != nil {
		switch {
		case errors.Is(err, store.ErrMailboxSuspensionNotFound):
			writeJSONError(w, "Suspension not found", http.StatusNotFound)
		case errors.Is(err, ErrSuspensionReleased):
			writeJSONError(w, "Suspension already released", http.StatusConflict)
		default:
			writeJSONError(w, "Release failed: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}
	s.auditLog(r, "email_mailbox_release", id, "released a mailbox suspension")
	writeOK(w, map[string]any{"id": id})
}
