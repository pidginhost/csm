package webui

import (
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
