package webui

import (
	"cmp"
	"context"
	"net/http"
	"time"

	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/antispam/hostfacts"
	csmlog "github.com/pidginhost/csm/internal/log"
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
	resp := emailRspamdResponse{Status: "off", Mode: antispamMode(cfg), FetchedAt: time.Now()}
	if !cfg.EmailProtection.Antispam.Enabled {
		resp.Reason = rspamdOff
		writeJSON(w, resp)
		return
	}
	var ep antispam.StatsEndpoint
	var reason string
	var down bool
	if s.rspamdSource != nil {
		ep, reason, down = s.rspamdSource()
	}
	resp.Status = "up"
	if down {
		resp.Status = "down"
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

// rspamdStats returns the cached read of ep, reading the controller again
// once the cache is older than rspamdStatsTTL or holds another endpoint.
// The lock is held across the read so a burst of requests reads once. The
// read outlives a client that goes away, so its result is about rspamd and
// can be cached for the requests waiting on it.
func (s *Server) rspamdStats(ctx context.Context, ep antispam.StatsEndpoint) rspamdFetch {
	s.rspamdMu.Lock()
	defer s.rspamdMu.Unlock()
	if c := s.rspamdCache; c.ep == ep && time.Since(c.at) < rspamdStatsTTL {
		return c
	}
	readCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rspamdFetchTimeout)
	defer cancel()
	stats, err := readRspamdStats(readCtx, ep)
	f := rspamdFetch{ep: ep, at: time.Now()}
	if err != nil {
		// The read's errors are fixed text: no address, URL or password.
		csmlog.Warn("email page could not read rspamd's controller", "err", err)
		f.reason = rspamdNoAnswer
	} else {
		f.stats = &stats
	}
	s.rspamdCache = f
	return f
}
