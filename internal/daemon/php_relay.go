package daemon

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/emailspool"
)

// scriptKey = host(X-PHP-Script) + ":" + path(X-PHP-Script)
type scriptKey = string

// scriptEvent is one accepted outbound mail from a PHP script. The booleans
// are computed at acceptance time (Flow A); evaluatePaths counts them in
// the sliding window.
type scriptEvent struct {
	At               time.Time
	MsgID            string
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
	mu        sync.Mutex
	scripts   map[scriptKey]time.Time
	lastEvent time.Time
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

func (w *perIPWindow) append(ip string, k scriptKey, at time.Time) {
	if ip == "" {
		return
	}
	v, _ := w.states.LoadOrStore(ip, &ipState{scripts: make(map[scriptKey]time.Time, 8)})
	s := v.(*ipState)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.scripts[k]; !exists && len(s.scripts) >= w.capPerIP {
		var oldestK scriptKey
		var oldest time.Time
		first := true
		for kk, tt := range s.scripts {
			if first || tt.Before(oldest) {
				oldestK = kk
				oldest = tt
				first = false
			}
		}
		delete(s.scripts, oldestK)
	}
	s.scripts[k] = at
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
	for _, t := range s.scripts {
		if !t.Before(since) {
			n++
		}
	}
	return n
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
	phpRelayPathCooldown = 30 * time.Minute
)

// evaluator combines windows + config + alerter in one object so the
// detector code path is callable from inotify watcher, retro scan, and
// startup spool walker without rebuilding the dependency graph each time.
type evaluator struct {
	scripts  *perScriptWindow
	ips      *perIPWindow
	accounts *perAccountWindow
	cfg      *config.Config
	metrics  *phpRelayMetrics // optional; nil in unit tests
	policies *emailspool.Policies
}

func newEvaluator(s *perScriptWindow, i *perIPWindow, a *perAccountWindow, cfg *config.Config, m *phpRelayMetrics) *evaluator {
	return &evaluator{scripts: s, ips: i, accounts: a, cfg: cfg, metrics: m}
}

// SetPolicies is called by daemon wiring once the policies file has loaded.
func (e *evaluator) SetPolicies(p *emailspool.Policies) { e.policies = p }

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
			f := e.makeFinding(k, "header", sourceIP, cpuser, s, fmtHeaderMessage(qualifying, win))
			findings = append(findings, f)
		}
	}

	// Path 2: absolute volume per script in the last 60 min.
	absVol := s.volumeCount(now.Add(-60 * time.Minute))
	if absVol >= e.cfg.EmailProtection.PHPRelay.AbsoluteVolumePerHour {
		if s.shouldFire("volume", now, phpRelayPathCooldown) {
			f := e.makeFinding(k, "volume", sourceIP, cpuser, s,
				fmt.Sprintf("Path 2: %d outbound mails from one script in last 60 min", absVol))
			findings = append(findings, f)
		}
	}

	// Path 4: HTTP-IP fanout. Skipped silently for proxy IPs.
	if sourceIP != "" {
		if e.policies == nil || !e.policies.IsProxyIP(sourceIP) {
			fwin := time.Duration(e.cfg.EmailProtection.PHPRelay.FanoutWindowMin) * time.Minute
			distinct := e.ips.distinctScriptsSince(sourceIP, now.Add(-fwin))
			if distinct >= e.cfg.EmailProtection.PHPRelay.FanoutDistinctScripts {
				if s.shouldFire("fanout", now, phpRelayPathCooldown) {
					f := e.makeFinding(k, "fanout", sourceIP, cpuser, s,
						fmt.Sprintf("Path 4: HTTP source IP %s triggered %d distinct scripts in last %s", sourceIP, distinct, fwin))
					findings = append(findings, f)
				}
			}
		}
	}

	return findings
}

// makeFinding builds a Critical Finding for the given path.
func (e *evaluator) makeFinding(k scriptKey, path, sourceIP, cpuser string, s *scriptState, message string) alert.Finding {
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
		Timestamp: time.Now(),
	}
}

func fmtHeaderMessage(qualifying int, win time.Duration) string {
	return fmt.Sprintf("Path 1: %d qualifying outbound mails (From-mismatch AND suspicious header) in last %s", qualifying, win)
}

// phpRelayMetrics is implemented in Phase N. Unit tests pass nil.
type phpRelayMetrics struct{}

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
