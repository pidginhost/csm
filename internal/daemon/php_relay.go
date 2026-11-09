package daemon

import (
	"bufio"
	"bytes"
	"encoding/gob"
	"fmt"
	"io"
	"net"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/contenttype"
	"github.com/pidginhost/csm/internal/crawlid"
	"github.com/pidginhost/csm/internal/emailspool"
	"github.com/pidginhost/csm/internal/eximlog"
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

// recipientTracker records the distinct envelope recipients seen in some
// window and whether that window is safe to gate on. A window is only safe
// when at least one recipient parse succeeded and no parse gap was seen in
// that same window, so a caller reading it can fail open. Callers hold their
// own lock; the tracker has none.
type recipientTracker struct {
	recipients    map[string]time.Time
	lastAt        time.Time
	lastUnknownAt time.Time
}

// record folds one message's recipients in. An empty list or any invalid
// address marks a parse gap. A domain skipped by skipDomain still counts as
// parsed, but its recipients are left out of the distinct count.
func (t *recipientTracker) record(recipients []string, at time.Time, max int, skipDomain func(string) bool) {
	recorded := false
	complete := len(recipients) > 0
	if len(recipients) > 0 {
		if t.recipients == nil {
			t.recipients = make(map[string]time.Time, 8)
		}
		for _, raw := range recipients {
			r, domain := parseRelayRecipient(raw)
			if r == "" {
				complete = false
				continue
			}
			recorded = true
			if skipDomain != nil && skipDomain(domain) {
				continue
			}
			if _, exists := t.recipients[r]; !exists && len(t.recipients) >= max {
				evictOldestRecipient(t.recipients)
			}
			if at.After(t.recipients[r]) {
				t.recipients[r] = at
			}
		}
	}
	if recorded && at.After(t.lastAt) {
		t.lastAt = at
	}
	if !complete && at.After(t.lastUnknownAt) {
		t.lastUnknownAt = at
	}
}

// distinctSince returns how many distinct recipients were seen no earlier than
// since, and whether that answer is trustworthy. known=false means fail open.
func (t *recipientTracker) distinctSince(since time.Time) (count int, known bool) {
	known = seenAtOrAfter(t.lastAt, since) && !seenAtOrAfter(t.lastUnknownAt, since)
	for _, last := range t.recipients {
		if !last.Before(since) {
			count++
		}
	}
	return count, known
}

// scriptState tracks one script's recent activity. All fields read or
// written through the embedded mutex.
type scriptState struct {
	mu sync.Mutex

	events     []scriptEvent
	rejections []rejectionEvent //nolint:unused // wired by Path 3 in Stage 2
	firedAt    map[string]time.Time
	rcpts      recipientTracker

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
	s.appendLocked(e)
}

func (s *scriptState) appendLocked(e scriptEvent) {
	if len(s.events) >= s.maxEvents {
		s.events = s.events[1:]
	}
	s.events = append(s.events, e)
	if e.At.After(s.lastEvent) {
		s.lastEvent = e.At
	}
}

// appendMessage records an event and its recipient parse result as one state
// transition. This prevents a concurrent evaluator from counting the event
// while still trusting recipient data from only the preceding messages.
func (s *scriptState) appendMessage(e scriptEvent, recipients []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.appendLocked(e)
	s.rcpts.record(recipients, e.At, maxTrackedRecipients, nil)
}

// distinctRecipientsSince reports the distinct recipients this script reached
// no earlier than since. known=false means callers must fail open.
func (s *scriptState) distinctRecipientsSince(since time.Time) (count int, known bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rcpts.distinctSince(since)
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
	mu        sync.Mutex
	scripts   map[scriptKey]*ipScriptState
	rcpts     recipientTracker
	lastEvent time.Time
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
	s.appendLocked(k, at, w.capPerIP, subject...)
}

func (s *ipState) appendLocked(k scriptKey, at time.Time, capPerIP int, subject ...string) {
	if _, exists := s.scripts[k]; !exists && len(s.scripts) >= capPerIP {
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

// appendMessage records a script hit and its recipient parse result while
// holding the same IP-state lock, keeping the Path 4 gate fail-open when
// evaluation runs concurrently with spool processing. Recipients in the
// sending account's listed domains are parsed but not counted. Subdomains
// need their own entry: they can belong to a different hosting account. An
// empty ownDomains set counts every recipient.
func (w *perIPWindow) appendMessage(ip string, k scriptKey, at time.Time, subject string, recipients []string, ownDomains map[string]struct{}) {
	if ip == "" {
		return
	}
	v, _ := w.states.LoadOrStore(ip, &ipState{scripts: make(map[scriptKey]*ipScriptState, 8)})
	s := v.(*ipState)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.appendLocked(k, at, w.capPerIP, subject)
	s.rcpts.record(recipients, at, maxTrackedRecipients, func(domain string) bool {
		_, own := ownDomains[domain]
		return own
	})
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

// maxTrackedRecipients bounds each script or source-IP recipient set. A
// genuine high-diversity relay crosses the gate threshold before this cap, so
// the bound protects memory without hiding the current high diversity.
const maxTrackedRecipients = 256

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
	return s.rcpts.distinctSince(since)
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

// Envelope recipients are mailboxes, not display-name headers. Wrapping the
// input forces addr-spec parsing, so angle brackets inside a quoted local
// part cannot substitute a different domain for the actual destination.
func parseRelayRecipient(r string) (recipient, domain string) {
	r = strings.TrimSpace(r)
	if strings.HasPrefix(r, "<") && strings.HasSuffix(r, ">") {
		r = strings.TrimSpace(r[1 : len(r)-1])
	}
	addr, err := mail.ParseAddress("<" + r + ">")
	if err != nil {
		return "", ""
	}
	at := strings.LastIndexByte(addr.Address, '@')
	if at < 0 {
		return "", ""
	}
	domain = strings.TrimSuffix(emailspool.ExtractDomain("recipient"+addr.Address[at:]), ".")
	return strings.ToLower(addr.Address[:at]) + "@" + domain, domain
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
// cPanel's EA-PHP header is `<SERVER_NAME><PHP_SELF> for <REMOTE_ADDR>`, or
// `... for <X-Forwarded-For>, <REMOTE_ADDR>` when the client sent
// X-Forwarded-For. Only the last element
// is server-observed; earlier ones are client-supplied. sourceIP is that
// element in canonical form, or "" when it is missing or not an IP.
// Returns ("", "") on an empty header.
func parseXPHPScript(v string) (scriptKey, string) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", ""
	}
	forIdx := strings.Index(v, " for ")
	var url, ip string
	if forIdx > 0 {
		// Forwarding text must never become part of the script key. The
		// header does not escape delimiters in PHP_SELF, so an ambiguous
		// path is grouped under its prefix before the first delimiter.
		url = strings.TrimSpace(v[:forIdx])
		// Parse the peer independently: PHP_SELF can contain PATH_INFO
		// with commas and " for ", even when there is no forwarding list.
		list := v[strings.LastIndex(v, " for ")+5:]
		last := strings.TrimSpace(list[strings.LastIndexByte(list, ',')+1:])
		if parsed := net.ParseIP(last); parsed != nil {
			ip = parsed.String()
		}
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
	cfgFn                 func() *config.Config // live config; see liveConfigFn
	metrics               *phpRelayMetrics      // optional; nil in unit tests
	policies              *emailspool.Policies
	msgIndex              *msgIDIndex // optional; nil in unit tests
	effectiveAccountLimit int
	accountLimitFn        func(*config.Config) int
	form                  *formRelayWindow // Path 6 state
}

func newEvaluator(s *perScriptWindow, i *perIPWindow, a *perAccountWindow, cfg *config.Config, m *phpRelayMetrics) *evaluator {
	form := newFormRelayWindow(formRelayMaxIPs)
	if m != nil {
		form.evictions = m.FormRelayEvictions
	}
	return &evaluator{scripts: s, ips: i, accounts: a, cfgFn: liveConfigFn(cfg), metrics: m, form: form}
}

// scriptPHPPath returns k's path lowercased and cut after its first PHP component,
// so PATH_INFO cannot change which script the key names.
func scriptPHPPath(k scriptKey) string {
	slash := strings.IndexByte(k, '/')
	if slash < 0 {
		return ""
	}
	p := strings.ToLower(k[slash:])
	for i := 1; i < len(p); i++ {
		if p[i] == '/' && contenttype.IsExecutablePHPName(p[:i]) {
			return p[:i]
		}
	}
	return p
}

// scriptID names k's script for Path 6 findings and ignores: the host
// lowercased plus scriptPHPPath. Host case and PATH_INFO come from the
// client, so they must neither split one form nor reach an operator hint.
func scriptID(k scriptKey) scriptKey {
	slash := strings.IndexByte(k, '/')
	if slash < 0 {
		return strings.ToLower(k)
	}
	return strings.ToLower(k[:slash]) + scriptPHPPath(k)
}

// isAuthenticatedAdminScript reports a WordPress admin page that needs a
// login, in any install directory. admin-ajax.php, admin-post.php,
// profile.php and index.php are left out: logged-out visitors or
// subscribers reach them.
func isAuthenticatedAdminScript(k scriptKey) bool {
	p := scriptPHPPath(k)
	slash := strings.LastIndexByte(p, '/')
	if !strings.HasSuffix(p[:slash+1], "/wp-admin/") {
		return false
	}
	file := p[slash+1:]
	switch name := strings.TrimSuffix(file, ".php"); name {
	case "", file, "admin-ajax", "admin-post", "profile", "index":
		return false
	}
	return true
}

// isWPCronScript reports WordPress's scheduled-job runner, which mails
// whatever its trigger request queued: the recipients are not that
// request's input. Cron services stay countable, so they cannot relay.
func isWPCronScript(k scriptKey) bool {
	return strings.HasSuffix(scriptPHPPath(k), "/wp-cron.php")
}

// formRelayDomlogRoot holds cPanel's per-account access logs, one file per
// vhost and scheme. A var so tests can point it at a temporary directory.
var formRelayDomlogRoot = "/usr/local/apache/domlogs"

// formRelayDomlogTail bounds how much of each access log a crossing reads,
// formRelayDomlogLine each line it parses.
const (
	formRelayDomlogTail = 4 << 20
	formRelayDomlogLine = 64 << 10
)

// formRelayStaffAccounts returns the accounts among shares whose current
// access logs show client key loading a WordPress admin page that needs a
// login: a GET answered 200. Order-list quick actions and other ajax admin
// work mail without passing such a page, so only this evidence spares the
// staff using them. A missing or unreadable log is no evidence.
func formRelayStaffAccounts(key string, shares map[scriptKey]formRelayShare, now time.Time) map[string]time.Time {
	found := make(map[string]time.Time)
	read := make(map[string]bool)
	for id, share := range shares {
		user := share.CPUser
		host, _, _ := strings.Cut(id, ":/")
		if !domlogName(user) || !domlogName(host) {
			continue
		}
		names := []string{host, host + "-ssl_log"}
		if bare, ok := strings.CutPrefix(host, "www."); ok && domlogName(bare) {
			names = append(names, bare, bare+"-ssl_log")
		}
		for _, name := range names {
			path := filepath.Join(formRelayDomlogRoot, user, name)
			if read[path] {
				continue
			}
			read[path] = true
			if at := domlogStaffSeenAt(path, key, now); at.After(found[user]) {
				found[user] = at
			}
		}
	}
	return found
}

// domlogName reports a single path element. The host comes from the
// client's Host header.
func domlogName(s string) bool {
	return s != "" && s != "." && s != ".." && !strings.ContainsAny(s, "/\x00")
}

// domlogStaffSeenAt scans the last formRelayDomlogTail bytes of path. The
// line the tail starts inside is skipped, and so is any line longer than
// formRelayDomlogLine: a piece of either may be client text shaped like a
// log line.
func domlogStaffSeenAt(path, key string, now time.Time) time.Time {
	fi, err := os.Stat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return time.Time{} // also keeps a FIFO from blocking the open
	}
	// #nosec G304 -- fixed cPanel log root; both names are checked by domlogName.
	f, err := os.Open(path)
	if err != nil {
		return time.Time{}
	}
	defer func() { _ = f.Close() }()
	off := max(fi.Size()-formRelayDomlogTail, 0)
	r := bufio.NewReaderSize(io.NewSectionReader(f, off, fi.Size()-off), formRelayDomlogLine)
	skip := off > 0
	var latest time.Time
	cutoff := now.Add(-formRelayStaffTTL)
	for {
		line, more, err := r.ReadLine()
		for more && err == nil {
			skip = true
			_, more, err = r.ReadLine()
		}
		if err == io.EOF {
			return latest
		}
		if err != nil {
			return time.Time{}
		}
		if !skip {
			ip, _, _ := strings.Cut(string(line), " ")
			if formRelayKey(ip) == key {
				rec, ok := checks.ParseCrawlLogLine(string(line), nil)
				if ok && rec.TimeOK && !rec.Time.Before(cutoff) && !rec.Time.After(now) &&
					rec.Time.After(latest) && isStaffAdminRequest(rec) {
					latest = rec.Time
				}
			}
		}
		skip = false
	}
}

// Log evidence needs a known staff page, not just an apparent admin script:
// public endpoints return 200 too, and servers may normalize the raw path.
// admin.php also serves subscribers; plugin capabilities are not in the log.
func isStaffAdminRequest(rec checks.CrawlLogRecord) bool {
	if rec.Method != "GET" || rec.Status != 200 || rec.Target == "" || rec.TargetInvalid || rec.TargetOverflow {
		return false
	}
	path, query, ok := crawlid.SplitTarget(rec.Target)
	if !ok || strings.ContainsAny(path, "%\\#") || scriptPHPPath(path) != strings.ToLower(path) {
		return false
	}
	for segment := range strings.SplitSeq(path, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	slash := strings.LastIndexByte(path, '/')
	if !strings.HasSuffix(path[:slash+1], "/wp-admin/") {
		return false
	}
	switch path[slash+1:] {
	case "edit.php", "post.php", "post-new.php", "upload.php",
		"edit-comments.php", "users.php", "options-general.php", "options-writing.php",
		"options-reading.php", "options-discussion.php", "options-media.php",
		"options-permalink.php", "options-privacy.php", "plugins.php", "themes.php",
		"edit-tags.php", "nav-menus.php", "tools.php", "import.php", "export.php", "site-health.php":
		return true
	case "admin.php":
		return isOrderListQuery(query)
	}
	return false
}

// isOrderListQuery reports admin.php's WooCommerce HPOS order list, which
// WooCommerce opens only to order managers; every other admin.php page may
// serve subscribers. PHP drops leading spaces and truncates names at NUL;
// the last duplicate wins, so any second name PHP would read as page voids it.
func isOrderListQuery(query string) bool {
	// A later page parameter may be discarded by PHP's site-specific input
	// limit, leaving a subscriber-accessible admin.php request instead.
	first, _, _ := strings.Cut(query, "&")
	firstName, _, _ := strings.Cut(first, "=")
	if name, err := url.QueryUnescape(firstName); err != nil || name != "page" {
		return false
	}
	q, err := url.ParseQuery(query)
	if err != nil {
		return false
	}
	pages := 0
	for name, values := range q {
		base := strings.TrimLeft(name, " ")
		if i := strings.IndexAny(base, "[\x00"); i >= 0 {
			base = base[:i]
		}
		if base == "page" {
			pages += len(values)
		}
	}
	page := q.Get("page")
	return pages == 1 && len(q["page"]) == 1 && (page == "wc-orders" || strings.HasPrefix(page, "wc-orders--"))
}

// config returns the live config so a reload that retunes or disables the
// relay detector reaches every evaluation; cfg was a startup snapshot before.
func (e *evaluator) config() *config.Config { return e.cfgFn() }

// SetPolicies is called by daemon wiring once the policies file has loaded.
func (e *evaluator) SetPolicies(p *emailspool.Policies) { e.policies = p }

// evaluatePaths inspects the script's window state (and IP window) and
// returns the set of findings that fire at this moment. Cooldowns prevent
// duplicate emissions per (script, path).
func (e *evaluator) evaluatePaths(k scriptKey, sourceIP, cpuser string, now time.Time) []alert.Finding {
	cfg := e.config()
	relayCfg := cfg.EmailProtection.PHPRelay
	if !relayCfg.Enabled {
		return nil
	}
	var findings []alert.Finding
	s := e.scripts.getOrCreate(k)

	// Path 1: sustained qualifying events.
	win := time.Duration(relayCfg.RateWindowMin) * time.Minute
	qualifying := s.qualifyingCount(now.Add(-win), func(ev scriptEvent) bool {
		return ev.FromMismatch && ev.AdditionalSignal
	})
	if qualifying >= relayCfg.HeaderScoreVolumeMin {
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
	if absVol >= relayCfg.AbsoluteVolumePerHour &&
		!e.scriptIsLowDiversityNotification(s, now.Add(-60*time.Minute), relayCfg.FanoutDistinctRecipients) {
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
			fwin := time.Duration(relayCfg.FanoutWindowMin) * time.Minute
			distinct := e.ips.distinctScriptsSince(sourceIP, now.Add(-fwin))
			if distinct >= relayCfg.FanoutDistinctScripts &&
				!e.fanoutIsLowDiversityNotification(sourceIP, now.Add(-fwin), relayCfg.FanoutDistinctRecipients) {
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

// formRelayFindings emits the client finding once per mode per window when ip's
// outside-recipient count reaches spread, plus one finding per script that
// reached at least two of them, for the operator to fix. Outside enforce
// mode the client finding uses a check that aims no response.
func (e *evaluator) formRelayFindings(k scriptKey, ip, cpuser string, spread int, window time.Duration, now time.Time, ignored func(scriptKey) bool) []alert.Finding {
	mode := e.config().EmailProtection.PHPRelay.IPRecipientMode
	key := formRelayKey(ip)
	since := now.Add(-window)
	hours := fmt.Sprintf("%dh", window/time.Hour)
	snapshot := e.form.evaluate(key, now, window, spread, ignored, mode, false)
	if snapshot.FireClient {
		// The logs are read outside the store lock; the claim comes after,
		// on what is left once staff accounts drop out.
		for user, at := range formRelayStaffAccounts(key, snapshot.Shares, now) {
			e.form.markStaff(user, key, at)
		}
		snapshot = e.form.evaluate(key, now, window, spread, ignored, mode, true)
	}
	if snapshot.Count < spread {
		return nil
	}
	shares := snapshot.Shares
	scripts := make([]scriptKey, 0, len(shares))
	for sk := range shares {
		scripts = append(scripts, sk)
	}
	sort.Slice(scripts, func(i, j int) bool {
		if a, b := shares[scripts[i]].Count, shares[scripts[j]].Count; a != b {
			return a > b
		}
		return scripts[i] < scripts[j]
	})

	var out []alert.Finding
	if snapshot.FireClient {
		var details strings.Builder
		details.WriteString("Outside recipients per script:")
		var subjects []string
		for _, sk := range scripts {
			fmt.Fprintf(&details, "\n  %s (account %s): %d", sk, shares[sk].CPUser, shares[sk].Count)
			if s := e.formRelaySubject(shares[sk].Raw, key, since); s != "" && len(subjects) < 3 && !slices.Contains(subjects, s) {
				subjects = append(subjects, s)
			}
		}
		if len(subjects) > 0 {
			details.WriteString("\nSample subjects:")
			for _, s := range subjects {
				fmt.Fprintf(&details, "\n  %s", s)
			}
		}
		if domains := snapshot.Domains; len(domains) > 0 {
			fmt.Fprintf(&details, "\nRecipient domains: %s", strings.Join(domains, ", "))
		}
		if e.metrics != nil {
			e.metrics.Findings.With("form_relay").Inc()
		}
		check := "email_php_form_relay"
		message := fmt.Sprintf("Path 6: client %s made hosted sites mail %d different outside addresses in %s", ip, snapshot.Count, hours)
		if mode != "enforce" {
			check = "email_php_form_relay_observed"
			message += " (observe mode, not challenged)"
		}
		out = append(out, alert.Finding{
			Severity:  alert.High,
			Check:     check,
			Path:      "form_relay",
			Message:   message,
			Details:   details.String(),
			ScriptKey: scriptID(k),
			SourceIP:  ip,
			CPUser:    cpuser,
			TenantID:  checks.HostingAccountForUser(cpuser),
			Timestamp: now,
		})
	}

	for _, sk := range scripts {
		share := shares[sk]
		if share.Count < 2 || !e.form.claimScript(sk, now, window) {
			continue
		}
		if e.metrics != nil {
			e.metrics.Findings.With("form_relay_script").Inc()
		}
		out = append(out, alert.Finding{
			Severity: alert.High,
			Check:    "email_php_form_relay_script",
			Path:     "form_relay_script",
			Message:  fmt.Sprintf("Bots use %s to mail outside addresses", sk),
			Details: fmt.Sprintf("Client %s reached %d outside addresses through this script in %s.\n"+
				"Add a captcha to the form or turn off its automatic reply to the submitter. "+
				"If this is a legitimate bulk sender: csm phprelay ignore-script %s", ip, share.Count, hours, shellQuote(sk)),
			// The details name the latest client; the script is the identity,
			// so later clients update this finding instead of adding one.
			DedupKey:  string(sk),
			ScriptKey: string(sk),
			CPUser:    share.CPUser,
			TenantID:  checks.HostingAccountForUser(share.CPUser),
			Timestamp: now,
		})
	}
	return out
}

// shellQuote single-quotes s for a POSIX shell, so a pasted hint runs no
// part of s.
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// formRelaySubject returns the latest subject script k sent for client key.
func (e *evaluator) formRelaySubject(k scriptKey, key string, since time.Time) string {
	v, ok := e.scripts.states.Load(k)
	if !ok {
		return ""
	}
	hit, _ := v.(*scriptState).relayHit(k, since, func(ev scriptEvent) bool {
		return formRelayKey(ev.SourceIP) == key
	})
	return hit.SampleSubject
}

// scriptIsLowDiversityNotification reports whether a script's hourly volume is
// notification mail rather than relay abuse. A security or e-commerce plugin
// can legitimately emit hundreds of mails an hour to the same one or two
// admin addresses; relay abuse reaches many distinct victims. Unknown or
// partially parsed recipients leave the gate failing open.
func (e *evaluator) scriptIsLowDiversityNotification(s *scriptState, since time.Time, minRcpt int) bool {
	if minRcpt <= 0 || s == nil {
		return false
	}
	count, known := s.distinctRecipientsSince(since)
	return known && count < minRcpt
}

// fanoutIsLowDiversityNotification reports whether a script fanout from this
// source IP looks like WordPress notification mail (comment moderation, contact
// forms): many distinct scripts but a small fixed recipient set. Mail to each
// sending site's own domains is not counted, so one client commenting on many
// hosted sites does not add up its owners into a relay. It returns true only
// when recipient data is known AND the distinct recipient count is below the
// configured minimum, so Path 4 still fires whenever recipients are diverse
// (real relay) or unknown (recipient parsing gap -- fail open). A non-positive
// threshold disables the gate and preserves the original behavior.
func (e *evaluator) fanoutIsLowDiversityNotification(sourceIP string, since time.Time, minRcpt int) bool {
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
		TenantID:  checks.HostingAccountForUser(cpuser),
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
	e.accountLimitFn = nil
}

// SetAccountLimitSource keeps the cPanel limit fixed while deriving the
// operator-controlled threshold from the live config on each evaluation.
func (e *evaluator) SetAccountLimitSource(cpanelLimit int, status cpanelLimitStatus) {
	e.accountLimitFn = func(cfg *config.Config) int {
		effective, enabled, _ := deriveEffectiveAccountLimit(cfg, cpanelLimit, status)
		if !enabled {
			return 0
		}
		return effective
	}
	e.effectiveAccountLimit = e.accountLimit(e.config())
}

func (e *evaluator) accountLimit(cfg *config.Config) int {
	if e.accountLimitFn != nil {
		return e.accountLimitFn(cfg)
	}
	return e.effectiveAccountLimit
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
	cfg := e.config()
	limit := e.accountLimit(cfg)
	if !cfg.EmailProtection.PHPRelay.Enabled || limit <= 0 || e.accounts == nil {
		return nil
	}
	// Only Exim's own submission metadata names the account: a message a
	// hosting account's process submitted locally, such as PHP mail().
	user := eximlog.LocalSubmitter(line)
	if user == "" {
		return nil
	}
	tenant := checks.HostingAccountForUser(user)
	if tenant == "" {
		return nil
	}
	if _, sender, ok := eximlog.Arrival(line); !ok || sender == "<>" {
		return nil
	}
	if !sendsOffHost(eximlog.Recipients(line)) {
		return nil
	}
	e.accounts.append(user, eventTime)
	volume := e.accounts.volumeSince(user, now.Add(-phpRelayAccountWindowDur))
	if volume < limit {
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
		Message:    fmt.Sprintf("Path 2b: account %s sent >= %d outbound mails in last hour", user, limit),
		CPUser:     user,
		TenantID:   tenant,
		RelayTotal: volume,
		Timestamp:  now,
	}}
}

// sendsOffHost reports whether any recipient is outside this host's mail
// domains. Mail to the host's own mailboxes is not outbound volume, and with
// the domain list unreadable nothing counts rather than everything.
func sendsOffHost(recipients []string) bool {
	for _, rcpt := range recipients {
		// Exim can cut the final address mid-domain when its log buffer
		// fills. That fragment cannot prove an off-host destination.
		if strings.HasSuffix(rcpt, "<trunc>") {
			continue
		}
		at := strings.LastIndexByte(rcpt, '@')
		if at < 0 || at == len(rcpt)-1 {
			continue
		}
		local, known := phpRelayIsLocalDomain(strings.ToLower(rcpt[at+1:]))
		if !known {
			return false
		}
		if !local {
			return true
		}
	}
	return false
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

// Covers reports whether k is ignored under its own key or its scriptID,
// so one ignore on the name a Path 6 finding prints covers every variant.
func (il *ignoreList) Covers(k scriptKey) bool { return il.Has(k) || il.Has(scriptID(k)) }

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
