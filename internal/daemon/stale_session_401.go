package daemon

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
)

// staleSession401Hold is how long a session-URL 401 waits for the evidence
// that would explain it. An anonymous request may need a named request at
// the opposite edge of the denial's match window. Allow both windows plus
// one watcher poll and one poll of read slack. Unexplained failures leave
// correlation at this deadline and retain the original finding.
const staleSession401Hold = 2*checks.StaleSessionMatchWindow + 2*logWatcherPollInterval

// staleSessionDenialRetention bounds memory only. Matching is by log time,
// so keeping a denial longer never widens what it explains; it only has to
// outlast a watcher that falls behind. cPanel writes a denial only for a
// live session, so the set stays small.
const staleSessionDenialRetention = 10 * time.Minute

// Two requests explained by one denial can be two match windows apart.
// Keep the rejection through the later request's watcher delay and hold.
const staleSessionRejectionRetention = 2*checks.StaleSessionMatchWindow + 2*logWatcherPollInterval + staleSession401Hold

// staleSession401s keeps a stale browser tab from being reported, and
// blocked, as an API authentication failure. A tab left open after its
// account logged in again elsewhere keeps the old URL security token; its
// next page load fails on every API call until cPanel purges the session
// for token failures. The 401 lines and the session_log purge are read by
// separate watchers, so a session-URL 401 is held until the purge could
// have been read, then reported unchanged if nothing explained it.
type staleSession401s struct {
	mu        sync.Mutex
	denials   map[sessionEvidenceKey]observedExplanation
	rejected  map[sessionEvidenceKey]map[string]observedExplanation
	explained map[sessionEvidenceKey]observedExplanation
	held      []heldAPI401
}

// cPanel timestamps have second precision. Named evidence is keyed by
// account, anonymous evidence by URL token; neither can cross an address.
type sessionEvidenceKey struct {
	ip   string
	name string
	at   int64
}

type observedExplanation struct {
	seen    time.Time
	expires time.Time
}

type heldAPI401 struct {
	req     checks.StaleSessionRequest
	finding alert.Finding
	due     time.Time
}

func newStaleSession401s() *staleSession401s {
	return &staleSession401s{
		denials:   make(map[sessionEvidenceKey]observedExplanation),
		rejected:  make(map[sessionEvidenceKey]map[string]observedExplanation),
		explained: make(map[sessionEvidenceKey]observedExplanation),
	}
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
		key := sessionEvidenceKey{ip: req.IP, name: req.User, at: req.At.Unix()}
		if s.rejected[key] == nil {
			s.rejected[key] = make(map[string]observedExplanation)
		}
		r := observedExplanation{seen: now, expires: now.Add(staleSessionRejectionRetention)}
		rememberExplanation(s.rejected[key], req.Token, r)
		window := int64(checks.StaleSessionMatchWindow / time.Second)
		for at := key.at - window; at <= key.at+window; at++ {
			dKey := sessionEvidenceKey{ip: req.IP, name: req.User, at: at}
			if d, ok := s.denials[dKey]; ok && d.expires.After(now) {
				s.explainTokenLocked(req.IP, req.Token, at, d, r)
			}
		}
	}
	out := findings[:0:0]
	for _, f := range findings {
		if f.Check != "api_auth_failure_realtime" {
			out = append(out, f)
			continue
		}
		if s.explainsLocked(req, now, now) {
			continue
		}
		if f.Timestamp.IsZero() {
			f.Timestamp = now
		}
		s.held = append(s.held, heldAPI401{req: req, finding: f, due: now.Add(staleSession401Hold)})
	}
	return out
}

// observeSessionLine joins a denial with matching user-named requests.
// Held requests are resolved in batches by due, never rescanned per line.
func (s *staleSession401s) observeSessionLine(line string, now time.Time) {
	d, ok := checks.ParseSessionTokenDenial(line)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := sessionEvidenceKey{ip: d.IP, name: d.Account, at: d.At.Unix()}
	observed := observedExplanation{seen: now, expires: now.Add(staleSessionDenialRetention)}
	rememberExplanation(s.denials, key, observed)
	window := int64(checks.StaleSessionMatchWindow / time.Second)
	for at := key.at - window; at <= key.at+window; at++ {
		for token, r := range s.rejected[sessionEvidenceKey{ip: d.IP, name: d.Account, at: at}] {
			if r.expires.After(now) {
				s.explainTokenLocked(d.IP, token, key.at, observed, r)
			}
		}
	}
}

// due returns the held findings nothing explained within their hold and
// forgets evidence past retention.
func (s *staleSession401s) due(now time.Time) []alert.Finding {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []alert.Finding
	kept := s.held[:0]
	for _, h := range s.held {
		before := now
		if !now.Before(h.due) {
			// Evidence arriving at or after the deadline cannot retract a
			// finding, even when the flush goroutine has not run yet.
			before = h.due.Add(-time.Nanosecond)
		}
		if s.explainsLocked(h.req, h.due.Add(-staleSession401Hold), before) {
			continue
		}
		if now.Before(h.due) {
			kept = append(kept, h)
			continue
		}
		out = append(out, h.finding)
	}
	clear(s.held[len(kept):])
	s.held = kept
	if len(s.held) == 0 {
		s.held = nil
	} else if cap(s.held) > 2*len(s.held) {
		s.held = append([]heldAPI401(nil), s.held...)
	}
	pruneExplanations(s.denials, now)
	pruneExplanations(s.explained, now)
	for key, tokens := range s.rejected {
		pruneExplanations(tokens, now)
		if len(tokens) == 0 {
			delete(s.rejected, key)
		}
	}
	return out
}

func (s *staleSession401s) explainTokenLocked(ip, token string, at int64, d, r observedExplanation) {
	joined := observedExplanation{seen: d.seen, expires: d.expires}
	if r.seen.After(joined.seen) {
		joined.seen = r.seen
	}
	if r.expires.Before(joined.expires) {
		joined.expires = r.expires
	}
	rememberExplanation(s.explained, sessionEvidenceKey{ip: ip, name: token, at: at}, joined)
}

func (s *staleSession401s) explainsLocked(req checks.StaleSessionRequest, start, before time.Time) bool {
	evidence, name := s.denials, req.User
	if req.User == "-" {
		evidence, name = s.explained, req.Token
	}
	at := req.At.Unix()
	window := int64(checks.StaleSessionMatchWindow / time.Second)
	for second := at - window; second <= at+window; second++ {
		e, ok := evidence[sessionEvidenceKey{ip: req.IP, name: name, at: second}]
		if ok && !e.seen.After(before) && e.expires.After(start) {
			return true
		}
	}
	return false
}

// Repeated lines in one logged second need one piece of evidence, rather
// than one allocation per request. Preserve when it first became usable.
func rememberExplanation[K comparable](entries map[K]observedExplanation, key K, observed observedExplanation) {
	if old, ok := entries[key]; ok && old.expires.After(observed.seen) {
		if old.seen.Before(observed.seen) {
			observed.seen = old.seen
		}
		if old.expires.After(observed.expires) {
			observed.expires = old.expires
		}
	}
	entries[key] = observed
}

func pruneExplanations[K comparable](entries map[K]observedExplanation, now time.Time) {
	for key, e := range entries {
		if !e.expires.After(now) {
			delete(entries, key)
		}
	}
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
	return d.cpanelAccessLogObservedHandler(line, alert.Observation{}, cfg)
}

// cpanelAccessLogObservedHandler stamps the line's observation before the
// hold, so a held finding still names its line when it is emitted.
func (d *Daemon) cpanelAccessLogObservedHandler(line string, obs alert.Observation, cfg *config.Config) []alert.Finding {
	findings := parseAccessLogLineEnhanced(line, cfg)
	for i := range findings {
		if findings[i].Observation == (alert.Observation{}) {
			findings[i].Observation = obs
		}
	}
	return d.staleSession401.filter(line, findings, time.Now())
}

// Keep the same queue contract as LogWatcher: backpressure is counted and
// logged without stopping expiry of attacker-controlled correlation state.
func (d *Daemon) emitDueStaleSession401(now time.Time) {
	dropped := 0
	for _, f := range d.staleSession401.due(now) {
		if !alert.TryEnqueue(d.alertCh, f) {
			dropped++
		}
	}
	if dropped > 0 {
		fmt.Fprintf(os.Stderr, "[%s] Warning: alert channel full, dropped %d held cPanel API findings\n", ts(), dropped)
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
		case <-ticker.C:
			// A queued tick can be old after a large batch was processed.
			d.emitDueStaleSession401(time.Now())
		}
	}
}
