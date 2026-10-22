package webui

import (
	"net/http"
	"time"

	"github.com/pidginhost/csm/internal/mailstats"
)

// emailSendersLimit bounds the account rows; the totals stay whole.
const emailSendersLimit = 100

// emailSendersResponse is the outgoing mail of a range by hosting account,
// and how many outbound abuse events the range holds.
type emailSendersResponse struct {
	mailstats.SendersReport
	AbuseEvents int `json:"abuse_events"`
}

// apiEmailSenders handles GET /api/v1/email/senders: the messages each
// hosting account sent in from/to (see emailRange), busiest first, and the
// count of the outbound abuse events /api/v1/email/relay-abuse lists for the
// same range, under the same scan cap and memo. The rows name accounts, so
// the route is admin only.
func (s *Server) apiEmailSenders(w http.ResponseWriter, r *http.Request) {
	from, to, ok := emailRange(w, r.URL.Query(), time.Now())
	if !ok {
		return
	}
	resp := emailSendersResponse{SendersReport: mailstats.SendersReport{Accounts: []mailstats.AccountSends{}}}
	if c := s.mailStatsCounter(); c != nil {
		resp.SendersReport = c.TopSenders(from, to, emailSendersLimit)
	}
	resp.AbuseEvents = s.buildRelayAbuseResponse("senders-abuse", from, to, 1).Total
	writeJSON(w, resp)
}
