package webui

import (
	"net/http"

	"github.com/pidginhost/csm/internal/mailfwd/intel"
	"github.com/pidginhost/csm/internal/platform"
)

// selectDeferralReporter picks the deferral-intel source for the host. Only
// cPanel/exim is wired; other platforms get the empty reporter until their
// adapters land (Phase 3).
func selectDeferralReporter() intel.Reporter {
	if platform.Detect().IsCPanel() {
		return intel.NewEximSource()
	}
	return intel.EmptyReporter{}
}

// apiEmailDeferrals handles GET /api/v1/email/deferrals and returns the
// outbound-deferral picture parsed from exim_mainlog: per-provider deferral
// rollup and per-outbound-IP reputation with stated reason codes.
func (s *Server) apiEmailDeferrals(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.deferralReporter == nil {
		writeJSON(w, intel.Report{
			Providers:   []intel.ProviderRollup{},
			OutboundIPs: []intel.OutboundIPRollup{},
		})
		return
	}

	rep, err := s.deferralReporter.Report()
	if err != nil {
		writeJSONError(w, "Failed to read deferral log", http.StatusInternalServerError)
		return
	}
	writeJSON(w, rep)
}
