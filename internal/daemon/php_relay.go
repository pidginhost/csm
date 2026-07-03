package daemon

import (
	"bufio"
	"bytes"
	"encoding/gob"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/emailspool"
	"github.com/pidginhost/csm/internal/store"
)

var phpRelayEvaluatorRef atomic.Pointer[evaluator]

// SetPHPRelayEvaluator is called by daemon wiring once everything is up.
// nil disables php_relay path dispatch from parseEximLogLine.
func SetPHPRelayEvaluator(e *evaluator) {
	phpRelayEvaluatorRef.Store(e)
}

// PHPRelayEvaluator returns the registered evaluator, or nil if none.
func PHPRelayEvaluator() *evaluator {
	return phpRelayEvaluatorRef.Load()
}

// scriptKey = host(X-PHP-Script) + ":" + path(X-PHP-Script)
type scriptKey = string

// scriptEvent is one accepted outbound mail from a PHP script. The booleans
// are computed at acceptance time (Flow A); evaluatePaths counts them in
// the sliding window.
type scriptEvent struct {
	At               time.Time
	MsgID            string
	Subject          string
	FromMismatch     bool
	AdditionalSignal bool // Reply-To external mismatch OR X-Mailer suspicious-not-safe
	SourceIP         string
}

// rejectionEvent records a remote-MTA policy-block rejection for Path 3.
// Stage 1 defines the type for completeness; Stage 2 wires it.
//
//nolint:unused // wired by Path 3 in Stage 2
type rejectionEvent struct {
	At      time.Time
	MsgID   string
	MTACode string
	Snippet string
}

const (
	phpRelayMaxEventsPerScript     = 256
	phpRelayMaxRejectionsPerScript = 64
	phpRelayMaxActiveMsgsPerScript = 4096
	phpRelayScriptIdleHorizon      = 25 * time.Hour //nolint:unused // consumed by Flow E in Task O2
)

// scriptState tracks one script's recent activity. All fields read or
// written through the embedded mutex.
type scriptState struct {
	mu sync.Mutex

	events     []scriptEvent
	rejections []rejectionEvent //nolint:unused // wired by Path 3 in Stage 2
	firedAt    map[string]time.Time

	activeMsgs       map[string]time.Time // msgID -> acceptedAt
	activeMsgsCapped bool

	lastEvent time.Time

	maxEvents     int
	maxRejections int //nolint:unused // wired by Path 3 in Stage 2
	maxActiveMsgs int
}

func newScriptState() *scriptState {
	return &scriptState{
		firedAt:       make(map[string]time.Time, 4),
		activeMsgs:    make(map[string]time.Time, 64),
		maxEvents:     phpRelayMaxEventsPerScript,
		maxRejections: phpRelayMaxRejectionsPerScript,
		maxActiveMsgs: phpRelayMaxActiveMsgsPerScript,
	}
}

func (s *scriptState) append(e scriptEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.events) >= s.maxEvents {
		s.events = s.events[1:]
	}
	s.events = append(s.events, e)
	if e.At.After(s.lastEvent) {
		s.lastEvent = e.At
	}
}

// qualifyingCount returns the number of events whose At is at or after
// since AND for which match returns true.
func (s *scriptState) qualifyingCount(since time.Time, match func(scriptEvent) bool) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, e := range s.events {
		if e.At.Before(since) {
			continue
		}
		if match(e) {
			n++
		}
	}
	return n
}

// volumeCount returns events on or after since regardless of signal flags.
//
//nolint:unused // consumed by Path 2 evaluator in Task F2
func (s *scriptState) volumeCount(since time.Time) int {
	return s.qualifyingCount(since, func(scriptEvent) bool { return true })
}

func (s *scriptState) relayHit(k scriptKey, since time.Time, match func(scriptEvent) bool) (alert.RelayScriptHit, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	hit := alert.RelayScriptHit{ScriptKey: string(k)}
	var sampleAt time.Time
	for _, e := range s.events {
		if e.At.Before(since) || !match(e) {
			continue
		}
		hit.Hits++
		if e.At.After(hit.LastSeen) {
			hit.LastSeen = e.At
		}
		if e.Subject != "" && (sampleAt.IsZero() || e.At.After(sampleAt)) {
			hit.SampleSubject = truncateDaemon(e.Subject, phpRelayBreakdownSubjectMax)
			sampleAt = e.At
		}
	}
	if hit.Hits == 0 {
		return alert.RelayScriptHit{}, false
	}
	return hit, true
}

func (s *scriptState) recordActive(msgID string, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.activeMsgs[msgID]; !exists && len(s.activeMsgs) >= s.maxActiveMsgs {
		// Drop oldest.
		var oldestID string
		var oldest time.Time
		first := true
		for id, t := range s.activeMsgs {
			if first || t.Before(oldest) {
				oldestID = id
				oldest = t
				first = false
			}
		}
		if oldestID != "" {
			delete(s.activeMsgs, oldestID)
		}
		s.activeMsgsCapped = true
	}
	s.activeMsgs[msgID] = at
}

func (s *scriptState) removeActive(msgID string) {
	s.mu.Lock()
	delete(s.activeMsgs, msgID)
	s.mu.Unlock()
}

// snapshotActiveMsgs returns a copy of activeMsgs keys and the capped flag.
// The returned slice is independent of internal state; callers may mutate
// it without affecting the scriptState.
func (s *scriptState) snapshotActiveMsgs() ([]string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.activeMsgs))
	for id := range s.activeMsgs {
		out = append(out, id)
	}
	return out, s.activeMsgsCapped
}

// pruneActiveMsgsOlderThan drops activeMsgs entries older than cutoff.
// Called by Flow E's GC to bound the lifetime of unreaped ids.
func (s *scriptState) pruneActiveMsgsOlderThan(cutoff time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, at := range s.activeMsgs {
		if at.Before(cutoff) {
			delete(s.activeMsgs, id)
			n++
		}
	}
	return n
}

// shouldFire returns true and updates firedAt if the cooldown for path has
// elapsed since the last fire.
//
//nolint:unused // consumed by Path 1/2/3 evaluators in Tasks F1/F2/G1
func (s *scriptState) shouldFire(path string, now time.Time, cooldown time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if last, ok := s.firedAt[path]; ok && now.Sub(last) < cooldown {
		return false
	}
	s.firedAt[path] = now
	return true
}

// perScriptWindow keeps a scriptState per scriptKey.
type perScriptWindow struct {
	states sync.Map // map[scriptKey]*scriptState
}

func newPerScriptWindow() *perScriptWindow { return &perScriptWindow{} }

func (w *perScriptWindow) getOrCreate(k scriptKey) *scriptState {
	if v, ok := w.states.Load(k); ok {
		return v.(*scriptState)
	}
	fresh := newScriptState()
	actual, _ := w.states.LoadOrStore(k, fresh)
	return actual.(*scriptState)
}

// SweepIdle drops scriptState entries whose lastEvent is before cutoff.
// Returns the number of entries dropped. Called by Flow E.
//
//nolint:unused // consumed by Flow E GC in Task O2
func (w *perScriptWindow) SweepIdle(cutoff time.Time) int {
	n := 0
	w.states.Range(func(k, v any) bool {
		s := v.(*scriptState)
		s.mu.Lock()
		idle := s.lastEvent.Before(cutoff)
		s.mu.Unlock()
		if idle {
			w.states.Delete(k)
			n++
		}
		return true
	})
	return n
}

// PruneActiveMsgs iterates retained scriptStates and prunes activeMsgs
// entries older than cutoff. Used by Flow E so still-active scripts don't
// accumulate ghost activeMsgs whose corresponding messages have left the
// queue without a "Completed" log line being parsed. Returns the total
// number of activeMsgs entries removed across all scripts.
func (w *perScriptWindow) PruneActiveMsgs(cutoff time.Time) int {
	n := 0
	w.states.Range(func(_, v any) bool {
		n += v.(*scriptState).pruneActiveMsgsOlderThan(cutoff)
		return true
	})
	return n
}

// Snapshot returns the current per-script states (for csm phprelay status).
//
//nolint:unused // consumed by csm phprelay status command in Task M1
func (w *perScriptWindow) Snapshot() map[scriptKey]*scriptState {
	out := make(map[scriptKey]*scriptState)
	w.states.Range(func(k, v any) bool {
		out[k.(scriptKey)] = v.(*scriptState)
		return true
	})
	return out
}

type ipState struct {
	mu      sync.Mutex
	scripts map[scriptKey]*ipScriptState
	// recipients maps a normalized recipient address to the last time it was
	// seen from this source IP. A window is safe to gate only when at least one
	// recipient parse succeeded and no parse gap was seen in that same window.
	recipients             map[string]time.Time
	lastRecipientAt        time.Time
	lastRecipientUnknownAt time.Time
	lastEvent              time.Time
}

type ipScriptState struct {
	lastSeen      time.Time
	sampleAt      time.Time
	sampleSubject string
}

type perIPWindow struct {
	states   sync.Map // map[string]*ipState
	capPerIP int
}

func newPerIPWindow(capPerIP int) *perIPWindow {
	if capPerIP <= 0 {
		capPerIP = 64
	}
	return &perIPWindow{capPerIP: capPerIP}
}

func (w *perIPWindow) append(ip string, k scriptKey, at time.Time, subject ...string) {
	if ip == "" {
		return
	}
	v, _ := w.states.LoadOrStore(ip, &ipState{scripts: make(map[scriptKey]*ipScriptState, 8)})
	s := v.(*ipState)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.scripts[k]; !exists && len(s.scripts) >= w.capPerIP {
		var oldestK scriptKey
		var oldest time.Time
		first := true
		for kk, ss := range s.scripts {
			if first || ss.lastSeen.Before(oldest) {
				oldestK = kk
				oldest = ss.lastSeen
				first = false
			}
		}
		delete(s.scripts, oldestK)
	}
	ss := s.scripts[k]
	if ss == nil {
		ss = &ipScriptState{}
		s.scripts[k] = ss
	}
	sampleSubject := ""
	if len(subject) > 0 {
		sampleSubject = truncateDaemon(subject[0], phpRelayBreakdownSubjectMax)
	}
	if at.After(ss.lastSeen) {
		ss.lastSeen = at
	}
	if sampleSubject != "" && (ss.sampleAt.IsZero() || at.After(ss.sampleAt)) {
		ss.sampleAt = at
		ss.sampleSubject = sampleSubject
	}
	if at.After(s.lastEvent) {
		s.lastEvent = at
	}
}

func (w *perIPWindow) distinctScriptsSince(ip string, since time.Time) int {
	v, ok := w.states.Load(ip)
	if !ok {
		return 0
	}
	s := v.(*ipState)
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, ss := range s.scripts {
		if !ss.lastSeen.Before(since) {
			n++
		}
	}
	return n
}

// maxRecipientsPerIP bounds the recipient set tracked per source IP. A genuine
// high-diversity relay blows far past the gate threshold before this cap, so
// evicting the oldest entry here never pulls the distinct count back under the
// threshold; it only protects memory under sustained churn.
const maxRecipientsPerIP = 256

// recordRecipients accumulates the distinct envelope recipients seen from a
// source IP. Called from the spool pipeline with the parsed -H recipients; an
// empty list marks a recipient parse gap so Path 4 fails open for that window.
func (w *perIPWindow) recordRecipients(ip string, recipients []string, at time.Time) {
	if ip == "" {
		return
	}
	v, _ := w.states.LoadOrStore(ip, &ipState{scripts: make(map[scriptKey]*ipScriptState, 8)})
	s := v.(*ipState)
	s.mu.Lock()
	defer s.mu.Unlock()
	recorded := false
	if len(recipients) > 0 {
		if s.recipients == nil {
			s.recipients = make(map[string]time.Time, 8)
		}
		for _, raw := range recipients {
			r := normalizeRecipient(raw)
			if r == "" {
				continue
			}
			if _, exists := s.recipients[r]; !exists && len(s.recipients) >= maxRecipientsPerIP {
				evictOldestRecipient(s.recipients)
			}
			if at.After(s.recipients[r]) {
				s.recipients[r] = at
			}
			recorded = true
		}
	}
	if recorded && at.After(s.lastRecipientAt) {
		s.lastRecipientAt = at
	}
	if !recorded && at.After(s.lastRecipientUnknownAt) {
		s.lastRecipientUnknownAt = at
	}
	if at.After(s.lastEvent) {
		s.lastEvent = at
	}
}

// distinctRecipientsSince returns the number of distinct recipients seen from
// ip no earlier than since, and whether any recipient data was recorded within
// that window. known=false means recipients are unknown; callers must fail open.
func (w *perIPWindow) distinctRecipientsSince(ip string, since time.Time) (count int, known bool) {
	v, ok := w.states.Load(ip)
	if !ok {
		return 0, false
	}
	s := v.(*ipState)
	s.mu.Lock()
	defer s.mu.Unlock()
	known = seenAtOrAfter(s.lastRecipientAt, since) && !seenAtOrAfter(s.lastRecipientUnknownAt, since)
	for _, last := range s.recipients {
		if !last.Before(since) {
			count++
		}
	}
	return count, known
}

func seenAtOrAfter(t, since time.Time) bool {
	return !t.IsZero() && !t.Before(since)
}

func evictOldestRecipient(m map[string]time.Time) {
	var oldestK string
	var oldest time.Time
	first := true
	for k, t := range m {
		if first || t.Before(oldest) {
			oldestK, oldest, first = k, t, false
		}
	}
	if !first {
		delete(m, oldestK)
	}
}

func normalizeRecipient(r string) string {
	r = strings.TrimSpace(r)
	r = strings.TrimPrefix(r, "<")
	r = strings.TrimSuffix(r, ">")
	return strings.ToLower(strings.TrimSpace(r))
}

func (w *perIPWindow) relaySamplesSince(ip string, since time.Time) []alert.RelayScriptHit {
	v, ok := w.states.Load(ip)
	if !ok {
		return nil
	}
	s := v.(*ipState)
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]alert.RelayScriptHit, 0, len(s.scripts))
	for k, ss := range s.scripts {
		if ss.lastSeen.Before(since) {
			continue
		}
		sampleSubject := ""
		if !ss.sampleAt.Before(since) {
			sampleSubject = ss.sampleSubject
		}
		out = append(out, alert.RelayScriptHit{
			ScriptKey:     string(k),
			Hits:          1,
			LastSeen:      ss.lastSeen,
			SampleSubject: sampleSubject,
		})
	}
	return out
}

func (w *perIPWindow) SweepIdle(cutoff time.Time) int {
	n := 0
	w.states.Range(func(k, v any) bool {
		s := v.(*ipState)
		s.mu.Lock()
		idle := s.lastEvent.Before(cutoff)
		s.mu.Unlock()
		if idle {
			w.states.Delete(k)
			n++
		}
		return true
	})
	return n
}

type accountState struct {
	mu        sync.Mutex
	events    []time.Time
	firedAt   time.Time
	lastEvent time.Time
	maxEvents int
}

type perAccountWindow struct {
	states sync.Map
	cap    int
}

func newPerAccountWindow(capPerAccount int) *perAccountWindow {
	if capPerAccount <= 0 {
		capPerAccount = 5000
	}
	return &perAccountWindow{cap: capPerAccount}
}

func (w *perAccountWindow) append(user string, at time.Time) {
	if user == "" {
		return
	}
	v, _ := w.states.LoadOrStore(user, &accountState{maxEvents: w.cap})
	s := v.(*accountState)
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.events) >= s.maxEvents {
		s.events = s.events[1:]
	}
	s.events = append(s.events, at)
	if at.After(s.lastEvent) {
		s.lastEvent = at
	}
}

func (w *perAccountWindow) volumeSince(user string, since time.Time) int {
	v, ok := w.states.Load(user)
	if !ok {
		return 0
	}
	s := v.(*accountState)
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, t := range s.events {
		if !t.Before(since) {
			n++
		}
	}
	return n
}

func (w *perAccountWindow) shouldFire(user string, now time.Time, cooldown time.Duration) bool {
	v, ok := w.states.Load(user)
	if !ok {
		return false
	}
	s := v.(*accountState)
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.firedAt.IsZero() && now.Sub(s.firedAt) < cooldown {
		return false
	}
	s.firedAt = now
	return true
}

func (w *perAccountWindow) SweepIdle(cutoff time.Time) int {
	n := 0
	w.states.Range(func(k, v any) bool {
		s := v.(*accountState)
		s.mu.Lock()
		idle := s.lastEvent.Before(cutoff)
		s.mu.Unlock()
		if idle {
			w.states.Delete(k)
			n++
		}
		return true
	})
	return n
}

// signals is the per-event boolean fingerprint Flow A appends to
// scriptState. The numeric scriptKey lookup happens against the same
// emailspool helpers used elsewhere so subdomain handling is consistent.
type signals struct {
	ScriptKey        scriptKey
	SourceIP         string
	FromMismatch     bool
	AdditionalSignal bool
	XMailer          string
}

// computeSignals resolves the per-event flags for an accepted message.
// authDomains is the cPanel user's authorised domain set (empty on
// resolver error -- caller treats that as "skip From-mismatch contribution"
// by passing isAuthDomainsKnown=false).
func computeSignals(h emailspool.Headers, authDomains map[string]struct{}, pol *emailspool.Policies) signals {
	sk, sourceIP := parseXPHPScript(h.XPHPScript)
	s := signals{
		ScriptKey: sk,
		SourceIP:  sourceIP,
		XMailer:   h.XMailer,
	}
	if len(authDomains) > 0 {
		fromDomain := emailspool.ExtractDomain(h.From)
		if fromDomain != "" && !IsAuthorisedFromDomain(fromDomain, authDomains) {
			s.FromMismatch = true
		}
	}
	// Reply-To external mismatch contribution.
	var replyToDomainMismatch bool
	if h.ReplyTo != "" && h.From != "" {
		rd := emailspool.ExtractDomain(h.ReplyTo)
		fd := emailspool.ExtractDomain(h.From)
		if rd != "" && fd != "" && rd != fd {
			replyToDomainMismatch = true
		}
	}
	// X-Mailer suspicious contribution.
	var mailerSuspicious bool
	if pol != nil {
		if pol.MailerSuspicious(h.XMailer) && !pol.MailerSafe(h.XMailer) {
			mailerSuspicious = true
		}
	}
	s.AdditionalSignal = replyToDomainMismatch || mailerSuspicious
	return s
}

// parseXPHPScript splits an X-PHP-Script header value into (scriptKey, sourceIP).
// Format: "<host>/<path> for <ip>". Returns ("", "") on parse failure.
func parseXPHPScript(v string) (scriptKey, string) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", ""
	}
	forIdx := strings.LastIndex(v, " for ")
	var url, ip string
	if forIdx > 0 {
		url = strings.TrimSpace(v[:forIdx])
		ip = strings.TrimSpace(v[forIdx+5:])
	} else {
		url = v
	}
	// Strip any query string.
	if q := strings.IndexByte(url, '?'); q > 0 {
		url = url[:q]
	}
	slash := strings.IndexByte(url, '/')
	if slash < 0 {
		// Bare host with no path.
		return scriptKey(url + ":/"), ip
	}
	host := url[:slash]
	path := url[slash:]
	return scriptKey(host + ":" + path), ip
}

const (
	phpRelayPathCooldown        = 30 * time.Minute
	phpRelayBreakdownSubjectMax = 160
)

// evaluator combines windows + config + alerter in one object so the
// detector code path is callable from inotify watcher, retro scan, and
// startup spool walker without rebuilding the dependency graph each time.
type evaluator struct {
	scripts               *perScriptWindow
	ips                   *perIPWindow
	accounts              *perAccountWindow
	cfg                   *config.Config
	metrics               *phpRelayMetrics // optional; nil in unit tests
	policies              *emailspool.Policies
	msgIndex              *msgIDIndex // optional; nil in unit tests
	effectiveAccountLimit int
}

func newEvaluator(s *perScriptWindow, i *perIPWindow, a *perAccountWindow, cfg *config.Config, m *phpRelayMetrics) *evaluator {
	return &evaluator{scripts: s, ips: i, accounts: a, cfg: cfg, metrics: m}
}

// SetPolicies is called by daemon wiring once the policies file has loaded.
func (e *evaluator) SetPolicies(p *emailspool.Policies) { e.policies = p }

// maxDetectionWindow returns the widest window any php_relay path evaluates
// over. The startup spool walker skips -H files older than this: such mail can
// no longer contribute to any current detection and only costs parse time.
func (e *evaluator) maxDetectionWindow() time.Duration {
	maxMin := 60 // Path 2 absolute-volume window is hardcoded at 60 min
	if v := e.cfg.EmailProtection.PHPRelay.RateWindowMin; v > maxMin {
		maxMin = v
	}
	if v := e.cfg.EmailProtection.PHPRelay.FanoutWindowMin; v > maxMin {
		maxMin = v
	}
	return time.Duration(maxMin) * time.Minute
}

// evaluatePaths inspects the script's window state (and IP window) and
// returns the set of findings that fire at this moment. Cooldowns prevent
// duplicate emissions per (script, path).
func (e *evaluator) evaluatePaths(k scriptKey, sourceIP, cpuser string, now time.Time) []alert.Finding {
	if !e.cfg.EmailProtection.PHPRelay.Enabled {
		return nil
	}
	var findings []alert.Finding
	s := e.scripts.getOrCreate(k)

	// Path 1: sustained qualifying events.
	win := time.Duration(e.cfg.EmailProtection.PHPRelay.RateWindowMin) * time.Minute
	qualifying := s.qualifyingCount(now.Add(-win), func(ev scriptEvent) bool {
		return ev.FromMismatch && ev.AdditionalSignal
	})
	if qualifying >= e.cfg.EmailProtection.PHPRelay.HeaderScoreVolumeMin {
		if s.shouldFire("header", now, phpRelayPathCooldown) {
			f := e.makeFinding(k, "header", sourceIP, cpuser, s, fmtHeaderMessage(qualifying, win), now)
			f.RelayTotal = qualifying
			f.RelayBreakdown = e.scriptRelayBreakdown(k, now.Add(-win), func(ev scriptEvent) bool {
				return ev.FromMismatch && ev.AdditionalSignal
			})
			if e.metrics != nil {
				e.metrics.Findings.With("header").Inc()
			}
			findings = append(findings, f)
		}
	}

	// Path 2: absolute volume per script in the last 60 min.
	absVol := s.volumeCount(now.Add(-60 * time.Minute))
	if absVol >= e.cfg.EmailProtection.PHPRelay.AbsoluteVolumePerHour {
		if s.shouldFire("volume", now, phpRelayPathCooldown) {
			f := e.makeFinding(k, "volume", sourceIP, cpuser, s,
				fmt.Sprintf("Path 2: %d outbound mails from one script in last 60 min", absVol), now)
			f.RelayTotal = absVol
			f.RelayBreakdown = e.scriptRelayBreakdown(k, now.Add(-60*time.Minute), func(scriptEvent) bool {
				return true
			})
			if e.metrics != nil {
				e.metrics.Findings.With("volume").Inc()
			}
			findings = append(findings, f)
		}
	}

	// Path 4: HTTP-IP fanout. Skipped silently for proxy IPs.
	if sourceIP != "" {
		if e.policies == nil || !e.policies.IsProxyIP(sourceIP) {
			fwin := time.Duration(e.cfg.EmailProtection.PHPRelay.FanoutWindowMin) * time.Minute
			distinct := e.ips.distinctScriptsSince(sourceIP, now.Add(-fwin))
			if distinct >= e.cfg.EmailProtection.PHPRelay.FanoutDistinctScripts &&
				!e.fanoutIsLowDiversityNotification(sourceIP, now.Add(-fwin)) {
				if s.shouldFire("fanout", now, phpRelayPathCooldown) {
					f := e.makeFinding(k, "fanout", sourceIP, cpuser, s,
						fmt.Sprintf("Path 4: HTTP source IP %s triggered %d distinct scripts in last %s", sourceIP, distinct, fwin), now)
					f.RelayTotal = distinct
					f.RelayBreakdown = e.fanoutRelayBreakdown(sourceIP, now.Add(-fwin))
					if e.metrics != nil {
						e.metrics.Findings.With("fanout").Inc()
					}
					findings = append(findings, f)
				}
			}
		}
	}

	return findings
}

// fanoutIsLowDiversityNotification reports whether a script fanout from this
// source IP looks like WordPress notification mail (comment moderation, contact
// forms): many distinct scripts but a small fixed recipient set. It returns
// true only when recipient data is known AND the distinct recipient count is
// below the configured minimum, so Path 4 still fires whenever recipients are
// diverse (real relay) or unknown (recipient parsing gap -- fail open). A
// non-positive threshold disables the gate and preserves the original behavior.
func (e *evaluator) fanoutIsLowDiversityNotification(sourceIP string, since time.Time) bool {
	minRcpt := e.cfg.EmailProtection.PHPRelay.FanoutDistinctRecipients
	if minRcpt <= 0 || e.ips == nil {
		return false
	}
	count, known := e.ips.distinctRecipientsSince(sourceIP, since)
	return known && count < minRcpt
}

// makeFinding builds a Critical Finding for the given path.
func (e *evaluator) makeFinding(k scriptKey, path, sourceIP, cpuser string, s *scriptState, message string, now time.Time) alert.Finding {
	msgIDs, _ := s.snapshotActiveMsgs()
	// Cap the sample shown in the finding so the alert payload stays bounded;
	// AutoFreezePHPRelayQueue takes its own complete snapshot.
	if len(msgIDs) > 10 {
		msgIDs = msgIDs[:10]
	}
	return alert.Finding{
		Severity:  alert.Critical,
		Check:     "email_php_relay_abuse",
		Path:      path,
		Message:   message,
		ScriptKey: string(k),
		SourceIP:  sourceIP,
		CPUser:    cpuser,
		MsgIDs:    msgIDs,
		Timestamp: now,
	}
}

func (e *evaluator) scriptRelayBreakdown(k scriptKey, since time.Time, match func(scriptEvent) bool) []alert.RelayScriptHit {
	hit, ok := e.scripts.getOrCreate(k).relayHit(k, since, match)
	if !ok {
		return nil
	}
	return []alert.RelayScriptHit{hit}
}

func (e *evaluator) fanoutRelayBreakdown(sourceIP string, since time.Time) []alert.RelayScriptHit {
	if e.ips == nil || sourceIP == "" {
		return nil
	}
	samples := e.ips.relaySamplesSince(sourceIP, since)
	if len(samples) == 0 {
		return nil
	}
	out := make([]alert.RelayScriptHit, 0, len(samples))
	for _, sample := range samples {
		hit := sample
		if e.scripts != nil {
			if v, ok := e.scripts.states.Load(scriptKey(sample.ScriptKey)); ok {
				if counted, ok := v.(*scriptState).relayHit(scriptKey(sample.ScriptKey), since, func(ev scriptEvent) bool {
					return ev.SourceIP == sourceIP
				}); ok {
					hit = counted
				}
			}
		}
		out = append(out, hit)
	}
	sortRelayScriptHits(out)
	return out
}

func sortRelayScriptHits(out []alert.RelayScriptHit) {
	sort.Slice(out, func(i, j int) bool {
		if out[i].Hits != out[j].Hits {
			return out[i].Hits > out[j].Hits
		}
		if !out[i].LastSeen.Equal(out[j].LastSeen) {
			return out[i].LastSeen.After(out[j].LastSeen)
		}
		return out[i].ScriptKey < out[j].ScriptKey
	})
}

func fmtHeaderMessage(qualifying int, win time.Duration) string {
	return fmt.Sprintf("Path 1: %d qualifying outbound mails (From-mismatch AND suspicious header) in last %s", qualifying, win)
}

type cpanelLimitStatus int

const (
	cpanelLimitOK cpanelLimitStatus = iota
	cpanelLimitMissing
	cpanelLimitUnparsable
	cpanelLimitDisabled
)

// readCpanelHourlyLimit returns (parsed-value, status). The key in
// /var/cpanel/cpanel.config is `maxemailsperhour` (no underscores, matches
// internal/checks/hardening_audit.go usage).
//
//	OK         -> integer > 0; the cap is in force.
//	Missing    -> file or key absent; caller assumes default 100 + Warning.
//	Unparsable -> key present but not a number; caller assumes default 100 + Warning.
//	Disabled   -> key present and == 0; cpanel hourly limit explicitly off.
func readCpanelHourlyLimit(path string) (int, cpanelLimitStatus) {
	// #nosec G304 -- path is the cPanel config path (default /var/cpanel/cpanel.config); operator-controlled, root-owned.
	f, err := os.Open(path)
	if err != nil {
		return 0, cpanelLimitMissing
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		if strings.TrimSpace(line[:eq]) != "maxemailsperhour" {
			continue
		}
		val := strings.TrimSpace(line[eq+1:])
		n, err := strconv.Atoi(val)
		if err != nil {
			return 0, cpanelLimitUnparsable
		}
		if n == 0 {
			return 0, cpanelLimitDisabled
		}
		return n, cpanelLimitOK
	}
	return 0, cpanelLimitMissing
}

// deriveEffectiveAccountLimit implements spec section 6.1's three-step
// derivation. Returns (effective, enabled, cappedFromOperator).
//   - cpanelLimit/status come from readCpanelHourlyLimit.
//   - missing/unparsable callers should also emit a Warning startup finding.
//   - returned enabled=false means Path 2b should not run this session.
func deriveEffectiveAccountLimit(cfg *config.Config, cpanelLimit int, status cpanelLimitStatus) (effective int, enabled bool, capped bool) {
	op := cfg.EmailProtection.PHPRelay.AccountVolumePerHour

	// Step 1: classify the cPanel limit.
	var assumed int
	var known bool
	switch status {
	case cpanelLimitOK:
		assumed = cpanelLimit
		known = true
	case cpanelLimitMissing, cpanelLimitUnparsable:
		// Caller emits Warning; we use the cPanel default 100.
		assumed = 100
		known = true
	case cpanelLimitDisabled:
		known = false
	}

	// Step 2: derive effective.
	if known {
		cap := assumed * 95 / 100
		if cap < 1 {
			cap = 1
		}
		if op == 0 {
			target := assumed * 60 / 100
			if target < 20 {
				target = 20
			}
			if target > 60 {
				target = 60
			}
			effective = target
			if effective > cap {
				effective = cap
			}
		} else {
			effective = op
			if effective > cap {
				effective = cap
				capped = true
			}
		}
		if effective <= 0 {
			return 0, false, false
		}
		return effective, true, capped
	}
	// Cpanel limit explicitly disabled.
	if op > 0 {
		return op, true, false
	}
	return 0, false, false
}

const (
	phpRelayAccountWindowDur    = 60 * time.Minute
	phpRelayAccountFireCooldown = 30 * time.Minute
)

// SetEffectiveAccountLimit is called by daemon wiring after derivation.
// Tests may also call it directly. A non-positive value disables Path 2b.
func (e *evaluator) SetEffectiveAccountLimit(n int) {
	e.effectiveAccountLimit = n
}

// SetMsgIndex wires the msgID->script index so exim queue-completion log lines
// can reap the corresponding activeMsgs entry.
func (e *evaluator) SetMsgIndex(idx *msgIDIndex) { e.msgIndex = idx }

// reapCompletedMsg drops an activeMsgs entry when exim logs that its message
// completed delivery and left the queue, so a delivered message is not later
// frozen as if still queued nor counted against the freeze rate-limit budget.
func (e *evaluator) reapCompletedMsg(line string) {
	if e.msgIndex == nil || e.scripts == nil {
		return
	}
	msgID, ok := eximCompletedMsgID(line)
	if !ok {
		return
	}
	entry, found := e.msgIndex.Get(msgID)
	if !found {
		return
	}
	if v, loaded := e.scripts.states.Load(scriptKey(entry.ScriptKey)); loaded {
		v.(*scriptState).removeActive(msgID)
	}
}

// eximCompletedMsgID returns the message id from an exim queue-completion line
// ("YYYY-MM-DD HH:MM:SS <msgid> Completed[ ...]") and true, or ("", false) for
// any other line. Requiring the "Completed" verb to immediately follow the id
// keeps an attacker-controlled Subject that merely contains the word from
// reaping a live message.
func eximCompletedMsgID(line string) (string, bool) {
	const tsLen = 19 // "2006-01-02 15:04:05"
	if len(line) < tsLen+2 {
		return "", false
	}
	rest := line[tsLen+1:] // skip timestamp and the following space
	end := strings.IndexByte(rest, ' ')
	if end < 0 {
		return "", false
	}
	id := rest[:end]
	if !msgIDPattern.MatchString(id) {
		return "", false
	}
	verb := rest[end+1:]
	if verb != "Completed" && !strings.HasPrefix(verb, "Completed ") {
		return "", false
	}
	return id, true
}

// parsePHPRelayAccountVolume processes one outbound `<= ` exim_mainlog line
// seen live. Returns zero or one finding (per cooldown).
func (e *evaluator) parsePHPRelayAccountVolume(line string, now time.Time) []alert.Finding {
	// Reap on the live path only: queue-completion lines free the msgID from
	// activeMsgs. The retro history replay never sees the live index.
	e.reapCompletedMsg(line)
	return e.parsePHPRelayAccountVolumeAt(line, now, now)
}

// parsePHPRelayAccountVolumeAt records the account event at eventTime and
// evaluates the volume window relative to now. The live watcher passes
// eventTime == now; the startup history replay passes the line's real exim
// timestamp so days-old log entries are not all stamped "now" and miscounted as
// a single last-hour burst (a false Path 2b Critical on every restart).
func (e *evaluator) parsePHPRelayAccountVolumeAt(line string, eventTime, now time.Time) []alert.Finding {
	if e.effectiveAccountLimit <= 0 || e.accounts == nil {
		return nil
	}
	if !strings.Contains(line, " <= ") {
		return nil
	}
	if !strings.Contains(line, " B=redirect_resolver") {
		return nil
	}
	user := extractUField(line)
	if user == "" {
		return nil
	}
	e.accounts.append(user, eventTime)
	volume := e.accounts.volumeSince(user, now.Add(-phpRelayAccountWindowDur))
	if volume < e.effectiveAccountLimit {
		return nil
	}
	if !e.accounts.shouldFire(user, now, phpRelayAccountFireCooldown) {
		return nil
	}
	if e.metrics != nil {
		e.metrics.Findings.With("volume_account").Inc()
	}
	return []alert.Finding{{
		Severity:   alert.Critical,
		Check:      "email_php_relay_abuse",
		Path:       "volume_account",
		Message:    fmt.Sprintf("Path 2b: account %s sent >= %d outbound mails in last hour", user, e.effectiveAccountLimit),
		CPUser:     user,
		RelayTotal: volume,
		Timestamp:  now,
	}}
}

// extractUField returns the cpuser from "U=<name>" in an exim log line.
// Returns "" if absent.
func extractUField(line string) string {
	idx := strings.Index(line, " U=")
	if idx < 0 {
		return ""
	}
	rest := line[idx+3:]
	end := len(rest)
	for i := 0; i < len(rest); i++ {
		c := rest[i]
		if c == ' ' || c == '\t' {
			end = i
			break
		}
	}
	return rest[:end]
}

// ignoreEntry records an operator-issued ignore on a script. A zero
// ExpiresAt means "never expires"; otherwise Has/List/SweepExpired drop
// the entry once now > ExpiresAt.
type ignoreEntry struct {
	ScriptKey string
	AddedAt   time.Time
	ExpiresAt time.Time
	AddedBy   string
	Reason    string
}

// ignoreList is the in-memory operator allowlist for php_relay scripts.
// L2 (bbolt persistence) wraps this with --persist semantics; Flow E
// (O2) calls SweepExpired periodically.
type ignoreList struct {
	mu      sync.Mutex
	entries map[string]ignoreEntry
	db      *store.DB
}

func newIgnoreList() *ignoreList {
	return &ignoreList{entries: make(map[string]ignoreEntry)}
}

func (il *ignoreList) Add(k scriptKey, expiresAt time.Time, by, reason string) {
	il.mu.Lock()
	defer il.mu.Unlock()
	il.entries[string(k)] = ignoreEntry{
		ScriptKey: string(k),
		AddedAt:   time.Now(),
		ExpiresAt: expiresAt,
		AddedBy:   by,
		Reason:    reason,
	}
}

func (il *ignoreList) Remove(k scriptKey) {
	il.mu.Lock()
	delete(il.entries, string(k))
	il.mu.Unlock()
}

func (il *ignoreList) Has(k scriptKey) bool {
	il.mu.Lock()
	defer il.mu.Unlock()
	e, ok := il.entries[string(k)]
	if !ok {
		return false
	}
	if !e.ExpiresAt.IsZero() && time.Now().After(e.ExpiresAt) {
		delete(il.entries, string(k))
		return false
	}
	return true
}

func (il *ignoreList) List() []ignoreEntry {
	il.mu.Lock()
	defer il.mu.Unlock()
	out := make([]ignoreEntry, 0, len(il.entries))
	now := time.Now()
	for k, e := range il.entries {
		if !e.ExpiresAt.IsZero() && now.After(e.ExpiresAt) {
			delete(il.entries, k)
			continue
		}
		out = append(out, e)
	}
	return out
}

// SweepExpired drops expired entries. Called by Flow E ticker.
//
//nolint:unused // wired in O2 Flow E ticker
func (il *ignoreList) SweepExpired(now time.Time) int {
	il.mu.Lock()
	defer il.mu.Unlock()
	n := 0
	for k, e := range il.entries {
		if !e.ExpiresAt.IsZero() && now.After(e.ExpiresAt) {
			delete(il.entries, k)
			n++
		}
	}
	return n
}

const ignoreBucket = "phprelay:ignore"

func (il *ignoreList) SetStore(db *store.DB) { il.db = db }

func (il *ignoreList) AddPersist(k scriptKey, expiresAt time.Time, by, reason string) error {
	il.Add(k, expiresAt, by, reason)
	if il.db == nil {
		return nil
	}
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(ignoreEntry{
		ScriptKey: string(k), AddedAt: time.Now(),
		ExpiresAt: expiresAt, AddedBy: by, Reason: reason,
	}); err != nil {
		return err
	}
	return il.db.PHPRelayPut(ignoreBucket, string(k), buf.Bytes())
}

//nolint:unused // wired in M2/O2
func (il *ignoreList) RemovePersist(k scriptKey) error {
	il.Remove(k)
	if il.db == nil {
		return nil
	}
	return il.db.PHPRelayDelete(ignoreBucket, string(k))
}

// Restore re-populates the in-memory list from bbolt at daemon start.
// Corrupt rows are skipped silently; expired rows are skipped (the bbolt
// row stays put until SweepBolt prunes it on the next Flow E tick).
func (il *ignoreList) Restore() error {
	if il.db == nil {
		return nil
	}
	rows, err := il.db.PHPRelayList(ignoreBucket)
	if err != nil {
		return err
	}
	now := time.Now()
	for _, raw := range rows {
		var e ignoreEntry
		if err := gob.NewDecoder(bytes.NewReader(raw)).Decode(&e); err != nil {
			continue
		}
		if !e.ExpiresAt.IsZero() && now.After(e.ExpiresAt) {
			continue
		}
		il.Add(scriptKey(e.ScriptKey), e.ExpiresAt, e.AddedBy, e.Reason)
	}
	return nil
}

// SweepBolt drops expired bbolt entries on the Flow E ticker. Corrupt
// rows are also dropped so the bucket stays healthy.
//
//nolint:unused // wired in M2/O2
func (il *ignoreList) SweepBolt(now time.Time) (int, error) {
	if il.db == nil {
		return 0, nil
	}
	return il.db.PHPRelaySweep(ignoreBucket, func(_, value []byte) bool {
		var e ignoreEntry
		if err := gob.NewDecoder(bytes.NewReader(value)).Decode(&e); err != nil {
			return true // drop corrupt rows
		}
		return !e.ExpiresAt.IsZero() && now.After(e.ExpiresAt)
	})
}
