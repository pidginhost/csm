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

	// The report reads up to 8 MiB of exim_mainlog, and the page asks for
	// it on every load and every minute while its tab is open, so one read
	// serves memoMaxAge. History does not change it: the mark stays fixed.
	// The memo is its own, so other memoized queries cannot evict it.
	res := s.deferralsMemo.get("", func() any {
		rep, err := s.deferralReporter.Report()
		return deferralsResult{rep, err}
	}).(deferralsResult)
	if res.err != nil {
		writeJSONError(w, "Failed to read deferral log", http.StatusInternalServerError)
		return
	}
	writeJSON(w, res.rep)
}

// deferralsResult is one memoized deferrals read. The exim source answers
// a missing or unreadable log with an empty report, never an error.
type deferralsResult struct {
	rep intel.Report
	err error
}
