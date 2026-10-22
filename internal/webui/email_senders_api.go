package webui

import (
	"net/http"
	"time"

	"github.com/pidginhost/csm/internal/mailstats"
)

// emailSendersLimit bounds the account rows; the totals stay whole.
const emailSendersLimit = 100

// emailSendersResponse is the outgoing mail of a range by hosting account,
// how many outbound abuse events the range holds, and how many of them name
// each account, by kind.
type emailSendersResponse struct {
	mailstats.SendersReport
	AbuseEvents    int                       `json:"abuse_events"`
	AbuseByAccount map[string]map[string]int `json:"abuse_by_account"`
	// AbuseTruncated says the scan cap cut AbuseEvents.
	AbuseTruncated bool `json:"abuse_events_truncated"`
}

// apiEmailSenders handles GET /api/v1/email/senders: the messages each
// hosting account sent in from/to (see emailRange), busiest first, and the
// count of the outbound abuse events /api/v1/email/relay-abuse lists for the
// same range, under the same scan cap and memo, with those naming an account
// counted per account and kind. The rows name accounts, so the route is admin
// only.
func (s *Server) apiEmailSenders(w http.ResponseWriter, r *http.Request) {
	from, to, ok := emailRange(w, r.URL.Query(), time.Now())
	if !ok {
		return
	}
	resp := emailSendersResponse{SendersReport: mailstats.SendersReport{Accounts: []mailstats.AccountSends{}}}
	if c := s.mailStatsCounter(); c != nil {
		resp.SendersReport = c.TopSenders(from, to, emailSendersLimit)
	}
	abuse := s.buildRelayAbuseResponse(from, to, 1)
	resp.AbuseEvents, resp.AbuseByAccount, resp.AbuseTruncated = abuse.Total, abuse.byAccount, abuse.TotalTruncated
	writeJSON(w, resp)
}
