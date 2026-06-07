package webui

import (
	"fmt"
	"net/http"

	"github.com/pidginhost/csm/internal/mailfwd/intel"
	"github.com/pidginhost/csm/internal/platform"
)

// selectQueueReporter picks the queue-composition source for the host. Only
// cPanel/exim is wired; other platforms get the empty reporter.
func selectQueueReporter() intel.QueueReporter {
	if platform.Detect().IsCPanel() {
		return intel.NewEximQueueSource()
	}
	return intel.EmptyQueueReporter{}
}

// selectQueueFlusher picks the backscatter-flush executor for the host. Only
// cPanel/exim is wired; other platforms get the empty flusher.
func selectQueueFlusher() intel.QueueFlusher {
	if platform.Detect().IsCPanel() {
		return intel.NewEximQueueFlusher()
	}
	return intel.EmptyQueueFlusher{}
}

// apiEmailFlushBackscatter handles POST /api/v1/email/queue/flush-backscatter.
// It removes only frozen null-sender messages -- undeliverable bounce
// backscatter -- from the exim queue. Mutating, so it runs under auth + CSRF
// and is audit-logged.
func (s *Server) apiEmailFlushBackscatter(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.queueFlusher == nil {
		writeJSONError(w, "Mail queue flush not available on this host", http.StatusServiceUnavailable)
		return
	}

	res, err := s.queueFlusher.FlushBackscatter()
	if err != nil {
		writeJSONError(w, "Failed to flush backscatter", http.StatusInternalServerError)
		return
	}

	s.auditLog(r, "email_flush_backscatter", "mail-queue",
		fmt.Sprintf("removed %d frozen null-sender message(s)", res.Removed))
	writeJSON(w, res)
}

// apiEmailQueueComposition handles GET /api/v1/email/queue-composition and
// returns the makeup of the exim queue: real mail vs null-sender bounce
// backscatter, frozen count, oldest age, and the most-stuck recipients.
func (s *Server) apiEmailQueueComposition(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.queueReporter == nil {
		writeJSON(w, intel.QueueComposition{TopRecipients: []intel.RecipientCount{}})
		return
	}

	comp, err := s.queueReporter.Composition()
	if err != nil {
		writeJSONError(w, "Failed to read mail queue", http.StatusInternalServerError)
		return
	}
	writeJSON(w, comp)
}
