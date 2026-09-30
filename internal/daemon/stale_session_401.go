package daemon

import (
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
)

// staleSession401Hold is how long a session-URL 401 waits for the evidence
// that would explain it. cPanel writes the token denial at most
// StaleSessionMatchWindow after the 401, and the access_log and session_log
// watchers each poll every logWatcherPollInterval, so the session_log line
// can be read up to one poll after the window closes; the second poll is
// slack for the read itself. A real credential failure is reported this
// much later than before, never dropped.
const staleSession401Hold = checks.StaleSessionMatchWindow + 2*logWatcherPollInterval

// staleSessionDenialRetention bounds memory only. Matching is by log time,
// so keeping a denial longer never widens what it explains; it only has to
// outlast a watcher that falls behind. cPanel writes a denial only for a
// live session, so the set stays small.
const staleSessionDenialRetention = 10 * time.Minute

// staleSessionRejectionRetention covers every request a rejected request
// can explain: that request is read within one hold of it and then waits
// one hold for the denial. Any client can make access_log lines, so this
// also bounds memory under a flood.
const staleSessionRejectionRetention = 2 * staleSession401Hold

// staleSession401s keeps a stale browser tab from being reported, and
// blocked, as an API authentication failure. A tab left open after its
// account logged in again elsewhere keeps the old URL security token; its
// next page load fails on every API call until cPanel purges the session
// for token failures. The 401 lines and the session_log purge are read by
// separate watchers, so a session-URL 401 is held until the purge could
// have been read, then reported unchanged if nothing explained it.
type staleSession401s struct {
	mu       sync.Mutex
	denials  []observedTokenDenial
	rejected []observedRejection
	held     []heldAPI401
}

type observedTokenDenial struct {
	denial checks.SessionTokenDenial
	seen   time.Time
}

type observedRejection struct {
	req  checks.StaleSessionRequest
	seen time.Time
}

type heldAPI401 struct {
	req     checks.StaleSessionRequest
	finding alert.Finding
	due     time.Time
}

func newStaleSession401s() *staleSession401s {
	return &staleSession401s{}
}

// filter sees every access_log line with the findings the handler made for
// it. It records session-URL 401s that name a user as evidence, and drops
// or holds the API auth failure for a line that evidence explains now or
// may explain once the session_log is read. Other findings pass through.
func (s *staleSession401s) filter(line string, findings []alert.Finding, now time.Time) []alert.Finding {
	req, candidate := checks.ParseStaleSessionRequest(line)
	if !candidate {
		return findings
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if req.User != "-" {
		s.rejected = append(s.rejected, observedRejection{req: req, seen: now})
		s.releaseExplainedLocked()
	}
	out := findings[:0:0]
	for _, f := range findings {
		if f.Check != "api_auth_failure_realtime" {
			out = append(out, f)
			continue
		}
		if s.evidenceLocked().Explains(req) {
			continue
		}
		if f.Timestamp.IsZero() {
			f.Timestamp = now
		}
		s.held = append(s.held, heldAPI401{req: req, finding: f, due: now.Add(staleSession401Hold)})
	}
	return out
}

// observeSessionLine records a token denial from session_log and releases
// the held 401s the evidence now explains.
func (s *staleSession401s) observeSessionLine(line string, now time.Time) {
	d, ok := checks.ParseSessionTokenDenial(line)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.denials = append(s.denials, observedTokenDenial{denial: d, seen: now})
	s.releaseExplainedLocked()
}

// due returns the held findings nothing explained within their hold and
// forgets evidence past retention.
func (s *staleSession401s) due(now time.Time) []alert.Finding {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []alert.Finding
	kept := s.held[:0]
	for _, h := range s.held {
		if now.Before(h.due) {
			kept = append(kept, h)
			continue
		}
		out = append(out, h.finding)
	}
	clear(s.held[len(kept):])
	s.held = kept

	denialCutoff := now.Add(-staleSessionDenialRetention)
	denials := s.denials[:0]
	for _, d := range s.denials {
		if d.seen.After(denialCutoff) {
			denials = append(denials, d)
		}
	}
	clear(s.denials[len(denials):])
	s.denials = denials

	rejectionCutoff := now.Add(-staleSessionRejectionRetention)
	rejected := s.rejected[:0]
	for _, r := range s.rejected {
		if r.seen.After(rejectionCutoff) {
			rejected = append(rejected, r)
		}
	}
	clear(s.rejected[len(rejected):])
	s.rejected = rejected
	return out
}

func (s *staleSession401s) releaseExplainedLocked() {
	if len(s.held) == 0 || len(s.denials) == 0 {
		return
	}
	evidence := s.evidenceLocked()
	kept := s.held[:0]
	for _, h := range s.held {
		if !evidence.Explains(h.req) {
			kept = append(kept, h)
		}
	}
	clear(s.held[len(kept):])
	s.held = kept
}

func (s *staleSession401s) evidenceLocked() checks.StaleSessionEvidence {
	var e checks.StaleSessionEvidence
	if len(s.denials) == 0 {
		return e
	}
	e.Denials = make([]checks.SessionTokenDenial, len(s.denials))
	for i, d := range s.denials {
		e.Denials[i] = d.denial
	}
	e.Rejected = make([]checks.StaleSessionRequest, len(s.rejected))
	for i, r := range s.rejected {
		e.Rejected[i] = r.req
	}
	return e
}

// cpanelSessionLogHandler feeds session_log to the password hijack detector
// and the stale-session correlation before the regular session handling.
func (d *Daemon) cpanelSessionLogHandler(line string, cfg *config.Config) []alert.Finding {
	ParseSessionLineForHijack(line, d.hijackDetector)
	d.staleSession401.observeSessionLine(line, time.Now())
	return parseSessionLogLine(line, cfg)
}

// cpanelAccessLogHandler holds back the API auth failures a stale browser
// session may explain.
func (d *Daemon) cpanelAccessLogHandler(line string, cfg *config.Config) []alert.Finding {
	return d.staleSession401.filter(line, parseAccessLogLineEnhanced(line, cfg), time.Now())
}

// emitDueStaleSession401 sends the held findings nothing explained. It waits
// for queue capacity like any producer outside a watcher; at shutdown the
// findings still held are dropped with the rest of the pipeline.
func (d *Daemon) emitDueStaleSession401(now time.Time) {
	for _, f := range d.staleSession401.due(now) {
		alert.Enqueue(d.alertCh, f, d.stopCh)
	}
}

func (d *Daemon) flushStaleSession401() {
	defer d.wg.Done()
	ticker := time.NewTicker(logWatcherPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-d.stopCh:
			return
		case now := <-ticker.C:
			d.emitDueStaleSession401(now)
		}
	}
}
