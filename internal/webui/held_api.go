package webui

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/pidginhost/csm/internal/mailfwd/quarantine"
	"github.com/pidginhost/csm/internal/platform"
)

// heldIDRe bounds a held-message id to a Maildir filename shape. The store also
// defends (filepath.Base + regular-file check), but validating at the handler
// boundary rejects traversal/control input before it reaches the filesystem.
var heldIDRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// heldForwardStore is the held-forward quarantine surface the webui needs.
// *quarantine.Quarantine satisfies it; tests use a fake.
type heldForwardStore interface {
	List() ([]quarantine.HeldMessage, error)
	Release(id string) error
	Delete(id string) error
}

const forwardQuarantineDir = "/var/lib/csm/forward_quarantine/held"

// selectForwardHeld returns the held-forward store for the host. Only
// cPanel/exim writes held copies; other platforms have none.
func selectForwardHeld() heldForwardStore {
	if platform.Detect().IsCPanel() {
		return quarantine.New(forwardQuarantineDir)
	}
	return nil
}

// apiEmailHeldList handles GET /api/v1/email/held and returns the forward
// copies the guard has held.
func (s *Server) apiEmailHeldList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.forwardHeld == nil {
		writeJSON(w, []quarantine.HeldMessage{})
		return
	}
	msgs, err := s.forwardHeld.List()
	if err != nil {
		writeJSONError(w, "Failed to list held forwards", http.StatusInternalServerError)
		return
	}
	if msgs == nil {
		msgs = []quarantine.HeldMessage{}
	}
	writeJSON(w, msgs)
}

// apiEmailHeldAction handles POST /api/v1/email/held/{id}/release (re-inject the
// held copy to its external recipient) and DELETE /api/v1/email/held/{id}
// (discard). Both mutate, so they run under auth + CSRF and are audit-logged.
func (s *Server) apiEmailHeldAction(w http.ResponseWriter, r *http.Request) {
	tail := strings.TrimPrefix(r.URL.Path, "/api/v1/email/held/")
	if tail == "" {
		writeJSONError(w, "Missing held message ID", http.StatusBadRequest)
		return
	}
	parts := strings.SplitN(tail, "/", 2)
	id := parts[0]
	action := ""
	if len(parts) == 2 {
		action = parts[1]
	}

	if !heldIDRe.MatchString(id) || strings.Contains(id, "..") {
		writeJSONError(w, "Invalid held message ID", http.StatusBadRequest)
		return
	}

	if s.forwardHeld == nil {
		writeJSONError(w, "Forward guard not available on this host", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodPost:
		if action != "release" {
			writeJSONError(w, "Unknown action; use /release", http.StatusBadRequest)
			return
		}
		if err := s.forwardHeld.Release(id); err != nil {
			writeJSONError(w, "Failed to release held forward: "+err.Error(), http.StatusInternalServerError)
			return
		}
		s.auditLog(r, "email_held_release", id, "re-injected held forward copy to its external recipient")
		writeJSON(w, map[string]string{"status": "released", "id": id})

	case http.MethodDelete:
		if action != "" {
			writeJSONError(w, "Unknown action", http.StatusBadRequest)
			return
		}
		if err := s.forwardHeld.Delete(id); err != nil {
			writeJSONError(w, "Failed to delete held forward: "+err.Error(), http.StatusInternalServerError)
			return
		}
		s.auditLog(r, "email_held_delete", id, "deleted held forward copy")
		writeJSON(w, map[string]string{"status": "deleted", "id": id})

	default:
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
