package webui

import (
	"cmp"
	"context"
	"net/http"
	"slices"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/antispam/hostfacts"
	"github.com/pidginhost/csm/internal/config"
)

// rspamd's numbers are cached this long, and one read of its controller
// may take at most rspamdFetchTimeout.
const (
	rspamdStatsTTL     = 60 * time.Second
	rspamdFetchTimeout = 10 * time.Second
)

// Fixed reasons for the rspamd card. A read error is never shown: it can
// name the controller's address.
const (
	rspamdNoAnswer   = "rspamd's controller did not answer"
	rspamdNotChecked = "rspamd's controller has not been checked yet"
	rspamdOff        = "antispam is off"
)

// readRspamdStats reads rspamd's controller; tests replace it.
var readRspamdStats = hostfacts.ReadRspamdStats

// emailRspamdResponse is the Email page's rspamd card. Status and mode are
// current; stats or the reason there are none can be up to rspamdStatsTTL
// old, as FetchedAt says.
type emailRspamdResponse struct {
	Status    string                `json:"status"` // up | down | off
	Mode      string                `json:"mode"`   // enforce | dry-run | off
	Version   string                `json:"version,omitempty"`
	Available bool                  `json:"available"`
	Reason    string                `json:"reason,omitempty"`
	Stats     *antispam.RspamdStats `json:"stats,omitempty"`
	FetchedAt time.Time             `json:"fetched_at"`
}

// rspamdFetch is one read of the controller at ep: stats, or the reason
// there are none.
type rspamdFetch struct {
	ep     antispam.StatsEndpoint
	stats  *antispam.RspamdStats
	reason string
	at     time.Time
}

// apiEmailRspamd handles GET /api/v1/email/rspamd: whether rspamd is up, the
// antispam mode, and rspamd's own counters since it started.
func (s *Server) apiEmailRspamd(w http.ResponseWriter, r *http.Request) {
	cfg := s.liveCfg()
	resp := emailRspamdResponse{Status: s.rspamdStatus(cfg), Mode: antispamMode(cfg), FetchedAt: time.Now()}
	if resp.Status == "off" {
		resp.Reason = rspamdOff
		writeJSON(w, resp)
		return
	}
	var ep antispam.StatsEndpoint
	var reason string
	if s.rspamdEndpoint != nil {
		ep, reason = s.rspamdEndpoint()
	}
	resp.Version = ep.Version
	if ep.Address == "" {
		resp.Reason = cmp.Or(reason, rspamdNotChecked)
		writeJSON(w, resp)
		return
	}
	f := s.rspamdStats(r.Context(), ep)
	resp.Available, resp.Stats, resp.Reason, resp.FetchedAt = f.stats != nil, f.stats, f.reason, f.at
	if f.stats != nil {
		resp.Version = cmp.Or(f.stats.Version, ep.Version)
	}
	writeJSON(w, resp)
}

// rspamdStatus is off while antispam is disabled and down while the health
// probe reports rspamd down.
func (s *Server) rspamdStatus(cfg *config.Config) string {
	if !cfg.EmailProtection.Antispam.Enabled {
		return "off"
	}
	if s.store != nil && slices.ContainsFunc(s.store.LatestFindings(), func(f alert.Finding) bool {
		return f.Check == "antispam_rspamd_down"
	}) {
		return "down"
	}
	return "up"
}

// rspamdStats returns the cached read of ep, reading the controller again
// once the cache is older than rspamdStatsTTL or holds another endpoint.
// The lock is held across the read so a burst of requests reads once.
func (s *Server) rspamdStats(ctx context.Context, ep antispam.StatsEndpoint) rspamdFetch {
	s.rspamdMu.Lock()
	defer s.rspamdMu.Unlock()
	if c := s.rspamdCache; c.ep == ep && time.Since(c.at) < rspamdStatsTTL {
		return c
	}
	readCtx, cancel := context.WithTimeout(ctx, rspamdFetchTimeout)
	defer cancel()
	stats, err := readRspamdStats(readCtx, ep)
	f := rspamdFetch{ep: ep, at: time.Now()}
	if err != nil {
		f.reason = rspamdNoAnswer
		if ctx.Err() != nil {
			// The client went away; its failure says nothing about rspamd.
			return f
		}
	} else {
		f.stats = &stats
	}
	s.rspamdCache = f
	return f
}
