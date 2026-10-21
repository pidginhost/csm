package webui

import (
	"net/http"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/mailstats"
)

// emailBlockCounts counts the active mail-related IP blocks, and those of
// them placed within the requested range.
type emailBlockCounts struct {
	Active  int `json:"active"`
	InRange int `json:"in_range"`
	// Unavailable marks the counts as meaningless because the firewall
	// state could not be read. A missing state file is not an error.
	Unavailable bool `json:"unavailable"`
}

// emailOverviewResponse is the Email page's headline numbers and chart. The
// counter's fields stay at the top level.
type emailOverviewResponse struct {
	mailstats.Overview
	Mode           string           `json:"mode"` // enforce | dry-run | off
	SMTPRestricted bool             `json:"smtp_restricted"`
	Queue          emailQueueState  `json:"queue"`
	Blocks         emailBlockCounts `json:"blocks"`
}

// mailBlockKeywords mark a block reason as mail-related.
var mailBlockKeywords = []string{"mail", "smtp", "spam", "phish", "mailer"}

// blockActive reports whether a block is in force at now. An unverified row
// was never proven in the kernel, and a zero expiry is permanent. Subnet
// blocks have no unverified state and pass false.
func blockActive(unverified bool, expires, now time.Time) bool {
	return !unverified && (expires.IsZero() || expires.After(now))
}

func mailRelatedReason(reason string) bool {
	reason = strings.ToLower(reason)
	for _, kw := range mailBlockKeywords {
		if strings.Contains(reason, kw) {
			return true
		}
	}
	return false
}

// mailBlockCounts counts the active mail-related IP blocks in the firewall
// state, and those placed in [from, to). A state that cannot be read is
// unavailable: zero would tell the operator nothing is blocked.
func mailBlockCounts(statePath string, from, to, now time.Time) emailBlockCounts {
	var counts emailBlockCounts
	st, err := firewall.LoadState(statePath)
	if err != nil {
		counts.Unavailable = true
		return counts
	}
	for _, b := range st.Blocked {
		if !blockActive(b.Unverified, b.ExpiresAt, now) || !mailRelatedReason(b.Reason) {
			continue
		}
		counts.Active++
		if !b.BlockedAt.Before(from) && b.BlockedAt.Before(to) {
			counts.InRange++
		}
	}
	return counts
}

func antispamMode(cfg *config.Config) string {
	switch as := cfg.EmailProtection.Antispam; {
	case !as.Enabled:
		return "off"
	case as.DryRun:
		return "dry-run"
	}
	return "enforce"
}

// apiEmailOverview handles GET /api/v1/email/overview: the mail decision
// counts for from/to (default the last 24 h), the live queue and the
// mail-related firewall blocks.
func (s *Server) apiEmailOverview(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	from, to, ok := historyRangeQuery(w, r.URL.Query(), now.Add(-24*time.Hour), now)
	if !ok {
		return
	}
	if to.Before(from) {
		from, to = to, from
	}

	cfg := s.liveCfg()
	resp := emailOverviewResponse{
		Overview:       mailstats.Overview{From: from, To: to},
		Mode:           antispamMode(cfg),
		SMTPRestricted: cfg.Firewall != nil && cfg.Firewall.SMTPBlock,
		Queue:          queueSnapshot(now),
		Blocks:         mailBlockCounts(s.cfg.StatePath, from, to, now),
	}
	if c := s.mailStatsCounter(); c != nil {
		resp.Overview = c.Overview(from, to)
	}
	resp.Queue.Warn, resp.Queue.Crit = cfg.Thresholds.MailQueueWarn, cfg.Thresholds.MailQueueCrit
	writeJSON(w, resp)
}
