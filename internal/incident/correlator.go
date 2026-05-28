package incident

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// ErrIncidentNotFound is returned when SetStatus or other lookups
// target an unknown incident id.
var ErrIncidentNotFound = errors.New("incident: not found")

// maxIncidentFindings and maxIncidentTimeline cap the per-incident
// fingerprint slice and operator-visible timeline so a long-running
// open incident with sustained low-severity traffic does not grow
// memory and persistence payloads without bound. Eviction keeps the
// first half (incident-opening context an operator needs to root-
// cause the incident) and the most recent half (so the timeline
// reflects current activity). Operators reading the timeline see a
// gap marker via the appended IncidentEvent that the cap fires.
const (
	maxIncidentFindings              = 5000
	maxIncidentTimeline              = 500
	incidentFingerprintTruncatedMark = "...truncated:"
	incidentTimelineTruncatedKind    = "truncated"
)

// incidentMergeWindow is the time gap inside which two findings with the
// same correlation key are considered the same incident. Named constant
// per project convention; config exposure deferred until operators ask.
const incidentMergeWindow = 15 * time.Minute

// CorrelatorConfig is reserved for future tunables and the persistence
// hook used by the daemon to write incidents to bbolt.
type CorrelatorConfig struct {
	// Persist is invoked after every create/update. Implementations
	// must be quick and idempotent. nil means "in-memory only".
	Persist func(Incident)

	// OpenThreshold is the number of correlated findings required before
	// a non-Critical finding opens an incident. Critical-severity
	// findings always open immediately so escalations page on first
	// hit. Values <= 0 default to 1 (open on first finding) for
	// backwards compatibility with callers that expect the original
	// behavior; the daemon explicitly configures 2 to suppress
	// one-shot scanner noise.
	OpenThreshold int

	// SpraySuppression turns on the credential-spray super-incident
	// path. When zero the detector is not constructed and OnFinding
	// follows the legacy per-mailbox correlation path. Default-off.
	SpraySuppression SpraySuppressionConfig

	// IsWhitelisted is consulted by the spray detector to skip IPs the
	// operator has marked as known-good (e.g. internal mail relays).
	// nil short-circuits to "no IPs whitelisted".
	IsWhitelisted func(ip string) bool

	// CanSprayBlock is consulted immediately before recording a
	// credential_spray block request. nil means "allowed" when
	// OnSprayBlock is present. Implementations must be quick and must
	// not call back into the correlator.
	CanSprayBlock func() bool

	// OnSprayBlock is invoked once per IP when the credential_spray
	// detector decides the IP should be hard-blocked, based on
	// SpraySuppression.BlockAtSeverity. The callback runs after the
	// correlator mutex is released so firewall or verdict latency does
	// not stall incident ingestion. nil disables the hand-off; the spray
	// super-incident still opens and escalates, but no firewall action
	// fires. The return value reports whether the firewall actually
	// recorded the block: false means dry-run, transient failure, or an
	// upstream gate refused, and the audit "credential_spray_block_requested"
	// action is not appended in that case so operators cannot mistake a
	// declined request for an enforced block.
	OnSprayBlock func(ip, reason string) bool

	// AutoBlock turns on the generic incident-driven firewall hand-off
	// for non-spray kinds. Independent of SpraySuppression; applies when
	// an incident has exactly one unambiguous remote IP and its kind is
	// allowed by AutoBlock.Kinds (empty = any). Default-zero means the
	// path is dormant.
	AutoBlock IncidentAutoBlockConfig

	// CanIncidentBlock is consulted immediately before recording a
	// generic incident block request. nil means "allowed" when
	// OnIncidentBlock is present. Lets the daemon recheck
	// auto_response.enabled / block_ips at decision time so SIGHUP
	// edits take effect without rebuilding the correlator.
	CanIncidentBlock func() bool

	// OnIncidentBlock fires when the generic auto-block gate trips. The
	// callback runs after the correlator mutex is released and returns
	// true only when a live block request was accepted. Dry-run,
	// disabled, and failed attempts must return false so the correlator
	// can retry on the next finding instead of permanently latching the
	// incident. nil disables the path even when AutoBlock is configured.
	OnIncidentBlock func(ip, reason string) bool
}

// IncidentAutoBlockConfig drives the generic incident-driven firewall
// hand-off independent of credential-spray suppression. Operators turn
// it on once they have validated that incident severity is trustworthy
// (the daemon does not promote a finding to High/Critical without
// either an explicit per-check signal or the correlator's threshold
// gate).
type IncidentAutoBlockConfig struct {
	Enabled bool
	// BlockAtSeverity is the minimum incident severity that triggers
	// a firewall hand-off. "" / "high" / "critical". Comparison is
	// case-insensitive. Any other value is ignored so operator typos
	// cannot accidentally engage blocking.
	BlockAtSeverity string
	// Kinds, when non-empty, restricts the auto-block path to the
	// listed incident kinds. Empty means "every kind that carries one
	// unambiguous remote IP". Credential_spray is implicitly excluded
	// since the dedicated spray hand-off owns it.
	Kinds map[Kind]bool
}

// IsZero reports whether the config is unset; the correlator treats a
// zero value as "generic auto-block disabled" without touching
// defaults.
func (c IncidentAutoBlockConfig) IsZero() bool {
	return !c.Enabled && c.BlockAtSeverity == "" && len(c.Kinds) == 0
}

// counters holds the atomic tallies exposed via RegisterMetrics. Kept
// on the Correlator so a single instance owns its own metric state and
// tests can build isolated correlators without touching globals.
type counters struct {
	createdTotal         atomic.Uint64
	severityChangedTotal atomic.Uint64
	statusChangedTotal   atomic.Uint64
	findingsMergedTotal  atomic.Uint64
	compactedTotal       atomic.Uint64
	autoClosedTotal      atomic.Uint64
	autoCloseDryRunTotal atomic.Uint64
	sprayOpenedTotal     atomic.Uint64
	spraySuppressedTotal atomic.Uint64
	sprayDryRunTotal     atomic.Uint64
}

// Correlator groups findings into incidents. In-memory state; the
// daemon is responsible for wiring it to a store via CorrelatorConfig.Persist.
type Correlator struct {
	mu sync.Mutex
	// persistMu protects persistTail. Persist callbacks wait on the
	// previously queued write instead of holding this lock, so re-entrant
	// callbacks can still take c.mu while later writers are queued.
	persistMu             sync.Mutex
	persistTail           chan struct{}
	cfg                   CorrelatorConfig
	incidents             map[string]*Incident
	byKey                 map[string]string
	pending               map[string]pendingFinding
	pendingIncidentBlocks map[string]struct{}
	openThreshold         int
	now                   func() time.Time
	counters              counters
	spray                 *sprayDetector
}

// pendingFinding is a finding seen for a key that has not yet met the
// open threshold. Stored only on the create path; merge into open
// incidents stays unconditional.
type pendingFinding struct {
	finding alert.Finding
	at      time.Time
}

// NewCorrelator returns a ready Correlator. Nothing to start; this type
// is purely callback-driven.
func NewCorrelator(cfg CorrelatorConfig) *Correlator {
	threshold := cfg.OpenThreshold
	if threshold < 1 {
		threshold = 1
	}
	c := &Correlator{
		cfg:                   cfg,
		persistTail:           closedPersistTail(),
		incidents:             map[string]*Incident{},
		byKey:                 map[string]string{},
		pending:               map[string]pendingFinding{},
		pendingIncidentBlocks: map[string]struct{}{},
		openThreshold:         threshold,
		now:                   time.Now,
	}
	c.spray = newSprayDetector(cfg.SpraySuppression, incidentMergeWindow, func() time.Time { return c.now() }, cfg.IsWhitelisted)
	return c
}

func closedPersistTail() chan struct{} {
	done := make(chan struct{})
	close(done)
	return done
}

// OnFinding ingests a Finding. Returns the incident id (if attributable)
// and whether a new incident was created. Unattributable findings yield
// ("", false, nil). Non-Critical findings whose key has fewer than
// OpenThreshold prior findings inside the merge window are stashed in
// the pending map and yield ("", false, nil) too; they will only open
// an incident if the threshold is met inside the window.
func (c *Correlator) OnFinding(f alert.Finding) (string, bool, error) {
	key := KeyFor(f)
	if key.IsEmpty() {
		return "", false, nil
	}
	var afterUnlock func()
	c.mu.Lock()
	defer func() {
		c.mu.Unlock()
		if afterUnlock != nil {
			afterUnlock()
		}
	}()

	keyStr := keyString(key)
	now := c.now()

	// Credential-spray super-incident path. When one source IP brute-forces
	// many distinct mailboxes/accounts inside the merge window, collapse
	// the per-mailbox fan-out into a single credential_spray incident
	// keyed on RemoteIP. The detector returns sprayDecisionNone for
	// non-spray traffic so the legacy correlation continues unchanged.
	if c.spray != nil {
		decision, hits := c.spray.Decide(f)
		switch decision {
		case sprayDecisionOpen:
			sprayKey := Key{RemoteIP: f.SourceIP}
			id := c.createSprayIncidentLocked(sprayKey, f, now, hits)
			c.spray.BindIncident(f.SourceIP, id)
			c.counters.sprayOpenedTotal.Add(1)
			if cb := c.maybeBlockSprayLocked(c.incidents[id], f.SourceIP, hits, now, "spray opened"); cb != nil {
				afterUnlock = cb
			}
			return id, true, nil
		case sprayDecisionSuppress:
			id := c.spray.IncidentForIP(f.SourceIP)
			inc, ok := c.incidents[id]
			if ok && incidentStatusActive(inc.Status) {
				c.mergeLocked(inc, f, now, true)
				if hits >= c.spray.cfg.SeverityEscalateAt && inc.Severity < alert.Critical {
					from := inc.Severity
					inc.Severity = alert.Critical
					c.counters.severityChangedTotal.Add(1)
					inc.Actions = append(inc.Actions, IncidentAction{
						Time:    now,
						Action:  "incident_severity_changed",
						Result:  "ok",
						Details: from.String() + " -> CRITICAL: spray sustained " + strconv.Itoa(hits) + " mailboxes",
					})
					c.persistLocked(*inc)
				}
				// Re-evaluate the block gate on every merged finding. The
				// configured BlockAtSeverity may have been armed AFTER the
				// incident was opened or escalated, in which case the
				// transition-time hook already fired without effect; the
				// helper is idempotent via triggerSprayBlockLocked's
				// action-presence check so a no-op call is harmless.
				if cb := c.maybeBlockSprayLocked(inc, f.SourceIP, hits, now, "spray ongoing"); cb != nil {
					afterUnlock = cb
				}
				c.counters.spraySuppressedTotal.Add(1)
				return id, false, nil
			}
			// Bound incident vanished (purged) or is no longer active
			// (operator resolved/dismissed). Clear the perIP binding so
			// subsequent findings don't keep falling into the same dead
			// lookup, then fall through to legacy so the finding still
			// produces an incident rather than silently disappearing.
			if id != "" {
				c.spray.UnbindIncident(id)
			}
		case sprayDecisionNone:
			if c.spray.cfg.DryRun && hits >= c.spray.cfg.DistinctMailboxes {
				c.counters.sprayDryRunTotal.Add(1)
			}
		}
	}

	if id, ok := c.byKey[keyStr]; ok {
		if inc, exists := c.incidents[id]; exists && now.Sub(inc.UpdatedAt) <= incidentMergeWindow {
			c.mergeLocked(inc, f, now, true)
			delete(c.pending, keyStr)
			if cb := c.maybeBlockIncidentLocked(inc, now, "merge"); cb != nil {
				afterUnlock = cb
			}
			return id, false, nil
		}
		// Stale binding -- the incident is older than the merge window.
		// Drop the binding and fall through to create so a fresh incident
		// owns the key going forward.
		delete(c.byKey, keyStr)
	}

	// Threshold gate. Non-Critical findings need OpenThreshold sightings
	// inside the merge window before opening an incident, except High
	// host-integrity findings. Those are not scanner noise and must
	// surface on the first sighting like Critical escalations.
	if c.openThreshold > 1 && !opensIncidentImmediately(f) {
		if pf, ok := c.pending[keyStr]; ok && now.Sub(pf.at) <= incidentMergeWindow {
			delete(c.pending, keyStr)
			id := c.createIncidentLocked(key, keyStr, pf.finding, pf.at)
			inc := c.incidents[id]
			c.mergeLocked(inc, f, now, true)
			if cb := c.maybeBlockIncidentLocked(inc, now, "threshold promote"); cb != nil {
				afterUnlock = cb
			}
			return id, true, nil
		}
		c.pending[keyStr] = pendingFinding{finding: f, at: now}
		return "", false, nil
	}

	id := c.createIncidentLocked(key, keyStr, f, now)
	delete(c.pending, keyStr)
	if cb := c.maybeBlockIncidentLocked(c.incidents[id], now, "incident opened"); cb != nil {
		afterUnlock = cb
	}
	return id, true, nil
}

// createSprayIncidentLocked builds a credential_spray incident keyed on
// the source IP. Caller must hold c.mu. Severity is HIGH at trip and
// escalates to CRITICAL once the merge path observes
// SpraySuppressionConfig.SeverityEscalateAt distinct mailboxes.
func (c *Correlator) createSprayIncidentLocked(key Key, f alert.Finding, now time.Time, hits int) string {
	id := newIncidentID()
	sev := f.Severity
	if sev < alert.High {
		sev = alert.High
	}
	inc := &Incident{
		ID:             id,
		Kind:           KindCredentialSpray,
		Status:         StatusOpen,
		Severity:       sev,
		CorrelationKey: cloneKey(key),
		Findings:       []string{},
		Timeline:       []IncidentEvent{},
		Actions: []IncidentAction{{
			Time:    now,
			Action:  "credential_spray_opened",
			Result:  "ok",
			Details: f.SourceIP + " hit " + strconv.Itoa(hits) + " distinct mailboxes inside window",
		}},
		CreatedAt: now,
		UpdatedAt: now,
	}
	c.incidents[id] = inc
	keyStr := keyString(key)
	c.byKey[keyStr] = id
	c.counters.createdTotal.Add(1)
	c.mergeLocked(inc, f, now, false)
	return id
}

// createIncidentLocked builds a new Incident, registers it in the maps,
// and seeds it with the given finding via mergeLocked. Caller must hold
// c.mu. mergeLocked is the single source of truth for Persist
// invocations, avoiding double-fire on create.
func (c *Correlator) createIncidentLocked(key Key, keyStr string, f alert.Finding, now time.Time) string {
	id := newIncidentID()
	displayMailbox, displayDomain := displayMailboxDomain(f.Mailbox, f.Domain)
	if displayMailbox == "" && displayDomain == "" {
		displayMailbox, displayDomain = key.Mailbox, key.Domain
	}
	inc := &Incident{
		ID:             id,
		Kind:           ClassifyKind(f),
		Status:         StatusOpen,
		Severity:       f.Severity,
		Account:        key.Account,
		Domain:         displayDomain,
		Mailbox:        displayMailbox,
		CorrelationKey: cloneKey(key),
		Findings:       []string{},
		Timeline:       []IncidentEvent{},
		Actions:        []IncidentAction{},
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	c.incidents[id] = inc
	c.byKey[keyStr] = id
	c.counters.createdTotal.Add(1)
	c.mergeLocked(inc, f, now, false)
	return id
}

// PendingCount returns the number of findings currently held in the
// threshold-gate pending map. Exposed for metrics and tests.
func (c *Correlator) PendingCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.pending)
}

// PruneStalePending removes pending findings whose age relative to now
// exceeds the merge window. Returns the number pruned. Called by the
// daemon's retention loop so a host with sustained one-shot scanner
// traffic does not grow the pending map without bound.
func (c *Correlator) PruneStalePending(now time.Time) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	cutoff := now.Add(-incidentMergeWindow)
	pruned := 0
	for k, pf := range c.pending {
		if pf.at.Before(cutoff) {
			delete(c.pending, k)
			pruned++
		}
	}
	return pruned
}

// PruneStaleSpray clears spray-detector state whose lastSeen is older
// than the merge window. Wired into the same retention sweep as
// PruneStalePending.
func (c *Correlator) PruneStaleSpray(now time.Time) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.spray.PruneStale(now)
}

// SprayTrackedIPs reports the count of source IPs currently held in
// the spray detector. Safe to call when the detector is disabled.
func (c *Correlator) SprayTrackedIPs() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.spray.TrackedIPs()
}

// OpenCount returns the number of incidents in Open or Contained
// status. Used by the csm_incidents_open gauge; computed at scrape
// time so the value never drifts from in-memory state.
func (c *Correlator) OpenCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, inc := range c.incidents {
		if inc.Status == StatusOpen || inc.Status == StatusContained {
			n++
		}
	}
	return n
}

// Get returns a snapshot of the incident by id.
func (c *Correlator) Get(id string) (Incident, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	inc, ok := c.incidents[id]
	if !ok {
		return Incident{}, false
	}
	return cloneIncident(*inc), true
}

// SnapshotPage returns a page of incidents matching status (empty
// string means all statuses), starting at offset, with at most limit
// items. The returned total is the number of records that match the
// filter regardless of the page bounds, so the caller can render an
// accurate "X of Y" header.
//
// limit <= 0 returns the rest of the filtered set after offset. The
// caller (web UI / phpanel) is expected to cap the page at a sane
// ceiling; this primitive only enforces correct slicing. Negative
// offset is clamped to zero.
//
// Items are deep-copied so callers may mutate the returned slice
// without affecting subsequent calls.
func (c *Correlator) SnapshotPage(status Status, offset, limit int) ([]Incident, int) {
	if status == "" {
		return c.SnapshotPageStatuses(nil, offset, limit)
	}
	return c.SnapshotPageStatuses([]Status{status}, offset, limit)
}

// SnapshotPageStatuses returns a page of incidents matching any status
// in statuses. An empty status list means all statuses. Sorting and
// slicing happen against internal pointers first; only the returned
// page is deep-copied.
func (c *Correlator) SnapshotPageStatuses(statuses []Status, offset, limit int) ([]Incident, int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	statusSet := make(map[Status]struct{}, len(statuses))
	for _, st := range statuses {
		if st != "" {
			statusSet[st] = struct{}{}
		}
	}

	matched := make([]*Incident, 0, len(c.incidents))
	for _, inc := range c.incidents {
		if len(statusSet) > 0 {
			if _, ok := statusSet[inc.Status]; !ok {
				continue
			}
		}
		matched = append(matched, inc)
	}
	sortIncidentRefs(matched)

	total := len(matched)
	if offset < 0 {
		offset = 0
	}
	if offset >= total {
		return []Incident{}, total
	}
	end := total
	if limit > 0 && offset+limit < end {
		end = offset + limit
	}

	out := make([]Incident, 0, end-offset)
	for _, inc := range matched[offset:end] {
		out = append(out, cloneIncident(*inc))
	}
	return out, total
}

func sortIncidentRefs(refs []*Incident) {
	sort.Slice(refs, func(i, j int) bool {
		return incidentRefLess(refs[i], refs[j])
	})
}

func incidentRefLess(a, b *Incident) bool {
	if !a.UpdatedAt.Equal(b.UpdatedAt) {
		return a.UpdatedAt.After(b.UpdatedAt)
	}
	return a.ID > b.ID
}

// Snapshot returns every incident sorted by UpdatedAt descending. Safe
// for concurrent callers; produces a deep-copy slice so the API layer
// can serialize it without coordinating with mutators.
func (c *Correlator) Snapshot() []Incident {
	c.mu.Lock()
	defer c.mu.Unlock()
	refs := make([]*Incident, 0, len(c.incidents))
	for _, inc := range c.incidents {
		refs = append(refs, inc)
	}
	sortIncidentRefs(refs)

	out := make([]Incident, 0, len(refs))
	for _, inc := range refs {
		out = append(out, cloneIncident(*inc))
	}
	return out
}

// mergeLocked folds f into inc. merged=true means this is a join into
// an existing incident (bumps findings_merged_total); merged=false means
// the caller already created the incident and is using mergeLocked only
// to seed the first finding -- in that case the create path owns the
// "did a new incident appear" tally.
func (c *Correlator) mergeLocked(inc *Incident, f alert.Finding, now time.Time, merged bool) {
	if merged {
		c.counters.findingsMergedTotal.Add(1)
	}
	// Re-classify before appending so timeline-aware compound rules
	// see the unchanged history; the new finding is passed in
	// explicitly so its Check participates in the compound check.
	priorKind := inc.Kind
	maybeReclassifyKind(inc, f)
	if inc.Kind != priorKind {
		inc.Actions = append(inc.Actions, IncidentAction{
			Time:    now,
			Action:  "incident_kind_changed",
			Result:  "ok",
			Details: string(priorKind) + " -> " + string(inc.Kind),
		})
	}
	inc.Findings = appendCappedFingerprint(inc.Findings, f.Fingerprint())
	ev := IncidentEvent{
		Time:    f.Timestamp,
		Kind:    "finding",
		Check:   f.Check,
		Message: f.Message,
	}
	if f.Process != nil {
		ev.PID = f.Process.PID
		ev.UID = f.Process.UID
		ev.Process = f.Process.Comm
	}
	if f.FilePath != "" {
		ev.Path = f.FilePath
	}
	if f.SourceIP != "" {
		ev.RemoteIP = f.SourceIP
	}
	inc.Timeline = appendCappedTimeline(inc.Timeline, ev)
	if f.Severity > inc.Severity {
		from := inc.Severity
		inc.Severity = f.Severity
		c.counters.severityChangedTotal.Add(1)
		inc.Actions = append(inc.Actions, IncidentAction{
			Time:    now,
			Action:  "incident_severity_changed",
			Result:  "ok",
			Details: from.String() + " -> " + f.Severity.String(),
		})
	}
	inc.UpdatedAt = now
	c.persistLocked(*inc)
}

// appendCappedFingerprint appends fp to fps and trims to
// maxIncidentFindings via first-half + last-half retention when the
// cap is crossed. Keeps the original opening signals plus the most
// recent traffic, dropping the middle.
func appendCappedFingerprint(fps []string, fp string) []string {
	fps = append(fps, fp)
	if len(fps) <= maxIncidentFindings {
		return fps
	}

	real := make([]string, 0, len(fps))
	elided := 0
	for _, existing := range fps {
		if n, ok := fingerprintTruncationCount(existing); ok {
			elided += n
			continue
		}
		real = append(real, existing)
	}
	if len(real) <= maxIncidentFindings {
		return fingerprintsWithTruncationMarker(real, elided)
	}

	half := maxIncidentFindings / 2
	tailLen := maxIncidentFindings - half
	elided += len(real) - half - tailLen
	head := append([]string(nil), real[:half]...)
	tail := append([]string(nil), real[len(real)-tailLen:]...)
	gap := []string{formatFingerprintTruncation(elided)}
	return append(append(head, gap...), tail...)
}

// appendCappedTimeline behaves the same as appendCappedFingerprint
// for the operator-visible IncidentEvent slice; the truncation marker
// is rendered as a synthetic "truncated" event so the UI can show a
// "X events elided" row.
func appendCappedTimeline(events []IncidentEvent, ev IncidentEvent) []IncidentEvent {
	events = append(events, ev)
	if len(events) <= maxIncidentTimeline {
		return events
	}

	real := make([]IncidentEvent, 0, len(events))
	elided := 0
	var markerTime time.Time
	for _, existing := range events {
		if n, ok := timelineTruncationCount(existing); ok {
			elided += n
			if markerTime.IsZero() || existing.Time.Before(markerTime) {
				markerTime = existing.Time
			}
			continue
		}
		real = append(real, existing)
	}
	if len(real) <= maxIncidentTimeline {
		return timelineWithTruncationMarker(real, elided, markerTime)
	}

	half := maxIncidentTimeline / 2
	tailLen := maxIncidentTimeline - half
	if markerTime.IsZero() {
		markerTime = real[half].Time
	}
	elided += len(real) - half - tailLen
	head := append([]IncidentEvent(nil), real[:half]...)
	tail := append([]IncidentEvent(nil), real[len(real)-tailLen:]...)
	gap := []IncidentEvent{timelineTruncationMarker(elided, markerTime)}
	return append(append(head, gap...), tail...)
}

func fingerprintsWithTruncationMarker(fps []string, elided int) []string {
	if elided == 0 {
		return fps
	}
	half := len(fps) / 2
	out := make([]string, 0, len(fps)+1)
	out = append(out, fps[:half]...)
	out = append(out, formatFingerprintTruncation(elided))
	out = append(out, fps[half:]...)
	return out
}

func fingerprintTruncationCount(fp string) (int, bool) {
	if !strings.HasPrefix(fp, incidentFingerprintTruncatedMark) {
		return 0, false
	}
	rest := strings.TrimPrefix(fp, incidentFingerprintTruncatedMark)
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return 1, true
	}
	n, err := strconv.Atoi(fields[0])
	if err != nil || n < 1 {
		return 1, true
	}
	return n, true
}

func formatFingerprintTruncation(count int) string {
	return incidentFingerprintTruncatedMark + strconv.Itoa(count) + " findings elided"
}

func timelineWithTruncationMarker(events []IncidentEvent, elided int, markerTime time.Time) []IncidentEvent {
	if elided == 0 {
		return events
	}
	if markerTime.IsZero() && len(events) > 0 {
		markerTime = events[len(events)/2].Time
	}
	half := len(events) / 2
	out := make([]IncidentEvent, 0, len(events)+1)
	out = append(out, events[:half]...)
	out = append(out, timelineTruncationMarker(elided, markerTime))
	out = append(out, events[half:]...)
	return out
}

func timelineTruncationCount(ev IncidentEvent) (int, bool) {
	if ev.Kind != incidentTimelineTruncatedKind {
		return 0, false
	}
	fields := strings.Fields(ev.Message)
	if len(fields) == 0 {
		return 1, true
	}
	n, err := strconv.Atoi(fields[0])
	if err != nil || n < 1 {
		return 1, true
	}
	return n, true
}

func timelineTruncationMarker(count int, at time.Time) IncidentEvent {
	return IncidentEvent{
		Time:    at,
		Kind:    incidentTimelineTruncatedKind,
		Message: strconv.Itoa(count) + " events elided to cap incident size",
	}
}

type queuedPersist struct {
	previous <-chan struct{}
	done     chan struct{}
	snap     Incident
	persist  func(Incident)
}

// queuePersistLocked reserves this write's place in mutation order while
// c.mu is still held. The returned callback must run after c.mu is released.
func (c *Correlator) queuePersistLocked(snap Incident) (queuedPersist, bool) {
	persist := c.cfg.Persist
	if persist == nil {
		return queuedPersist{}, false
	}
	snap = cloneIncident(snap)
	done := make(chan struct{})
	c.persistMu.Lock()
	previous := c.persistTail
	c.persistTail = done
	c.persistMu.Unlock()
	return queuedPersist{
		previous: previous,
		done:     done,
		snap:     snap,
		persist:  persist,
	}, true
}

func (c *Correlator) runQueuedPersist(req queuedPersist) {
	<-req.previous
	defer close(req.done)
	req.persist(req.snap)
}

// persistLocked invokes the Persist callback while temporarily releasing
// the correlator mutex so a re-entrant Persist that reads Correlator
// state does not deadlock. The caller MUST already hold c.mu; the
// deferred re-Lock keeps the "mu held on return" contract that
// mergeLocked's callers rely on.
func (c *Correlator) persistLocked(snap Incident) {
	req, ok := c.queuePersistLocked(snap)
	if !ok {
		return
	}
	c.mu.Unlock()
	defer c.mu.Lock()
	c.runQueuedPersist(req)
}

// SetStatus transitions an incident's status. On Resolved/Dismissed
// the incident is unbound from the active byKey index so future
// findings for the same correlation key start a fresh incident.
// Returns ErrIncidentNotFound if id is unknown.
func (c *Correlator) SetStatus(id string, status Status, details string) error {
	if !validStatus(status) {
		return fmt.Errorf("incident: invalid status %q", status)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	inc, ok := c.incidents[id]
	if !ok {
		return ErrIncidentNotFound
	}
	if inc.Status == status {
		return nil
	}
	now := c.now()
	from := inc.Status
	inc.Status = status
	inc.UpdatedAt = now
	inc.Actions = append(inc.Actions, IncidentAction{
		Time:    now,
		Action:  "incident_status_changed",
		Result:  "ok",
		Details: string(from) + " -> " + string(status) + ": " + details,
	})
	c.counters.statusChangedTotal.Add(1)
	if status == StatusResolved || status == StatusDismissed {
		// Operator close: record provenance so reporting can distinguish
		// from CloseStale's "auto:stale" attribution. Only set if the
		// caller has not already assigned a closed reason (e.g. CloseStale
		// reuses SetStatus internally and presets these fields).
		if inc.ClosedAt.IsZero() {
			inc.ClosedAt = now
			inc.ClosedBy = "operator"
		}
		c.unbindLocked(id)
		if c.spray != nil {
			c.spray.UnbindIncident(id)
		}
	} else {
		// Reverting from resolved/dismissed back to open or contained
		// clears the close attribution so future closes attribute correctly.
		inc.ClosedAt = time.Time{}
		inc.ClosedBy = ""
		c.bindLocked(inc)
	}
	c.persistLocked(*inc)
	return nil
}

// CloseStale auto-resolves Open / Contained incidents whose UpdatedAt is
// older than the per-kind threshold in `idleThresholds`. Kinds absent
// from the map are never closed (the caller decides which kinds expire).
// dryRun=true counts decisions without mutating state, so an operator
// can validate thresholds before flipping the live switch. Returns
// (closed, dryRun, total-scanned).
//
// Closing unbinds both the incident key and any spray detector state,
// so future findings are evaluated as new activity instead of merging
// into the closed incident.
func (c *Correlator) CloseStale(now time.Time, idleThresholds map[Kind]time.Duration, dryRun bool) (closed, dryRunCount, scanned int) {
	if len(idleThresholds) == 0 {
		return 0, 0, 0
	}
	var persist []queuedPersist
	c.mu.Lock()
	for id, inc := range c.incidents {
		if inc.Status != StatusOpen && inc.Status != StatusContained {
			continue
		}
		threshold, ok := idleThresholds[inc.Kind]
		if !ok || threshold <= 0 {
			continue
		}
		idle := now.Sub(inc.UpdatedAt)
		if idle <= threshold {
			continue
		}
		scanned++
		if dryRun {
			c.counters.autoCloseDryRunTotal.Add(1)
			dryRunCount++
			continue
		}
		from := inc.Status
		inc.Status = StatusResolved
		inc.UpdatedAt = now
		inc.ClosedAt = now
		inc.ClosedBy = "auto:stale"
		inc.Actions = append(inc.Actions, IncidentAction{
			Time:    now,
			Action:  "incident_auto_closed",
			Result:  "ok",
			Details: string(from) + " -> resolved: stale " + idle.Truncate(time.Second).String(),
		})
		c.counters.statusChangedTotal.Add(1)
		c.counters.autoClosedTotal.Add(1)
		c.unbindLocked(id)
		if c.spray != nil {
			c.spray.UnbindIncident(id)
		}
		if req, ok := c.queuePersistLocked(*inc); ok {
			persist = append(persist, req)
		}
		closed++
	}
	c.mu.Unlock()

	for _, req := range persist {
		c.runQueuedPersist(req)
	}
	return closed, dryRunCount, scanned
}

// validStatus reports whether s is one of the four spec-defined values.
// Guards SetStatus against arbitrary strings reaching the persisted
// timeline; control-socket and webui handlers also reject early but
// the correlator owns the type and must not trust callers.
func validStatus(s Status) bool {
	switch s {
	case StatusOpen, StatusContained, StatusResolved, StatusDismissed:
		return true
	}
	return false
}

func incidentStatusActive(s Status) bool {
	return s == StatusOpen || s == StatusContained
}

// IncrementCompactedTotal bumps the compaction counter by n. Called
// from the daemon-side retention scheduler after store.CompactIncidents
// removes records. Negative inputs are ignored so a buggy caller cannot
// underflow the monotonic counter.
func (c *Correlator) IncrementCompactedTotal(n int) {
	if n < 0 {
		return
	}
	c.counters.compactedTotal.Add(uint64(n))
}

// PruneClosedOlderThan removes resolved/dismissed incidents older than
// retention from the in-memory map. Store compaction removes the durable
// records; this keeps API/control snapshots from serving stale incidents
// until the next daemon restart.
func (c *Correlator) PruneClosedOlderThan(now time.Time, retention time.Duration) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	cutoff := now.Add(-retention)
	pruned := 0
	for id, inc := range c.incidents {
		if inc.Status != StatusResolved && inc.Status != StatusDismissed {
			continue
		}
		if !inc.UpdatedAt.Before(cutoff) {
			continue
		}
		delete(c.incidents, id)
		c.unbindLocked(id)
		pruned++
	}
	return pruned
}

// Restore re-hydrates correlator state from a list previously loaded
// from the store. Open and Contained incidents are bound to the
// byKey index so a finding arriving inside the merge window joins the
// existing incident; Resolved/Dismissed incidents are loaded into the
// id map only (Get still returns them) but do NOT claim their key, so
// future findings for the same key start a fresh incident.
func (c *Correlator) Restore(incidents []Incident) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range incidents {
		inc := incidents[i]
		c.incidents[inc.ID] = &inc
		if inc.Status != StatusOpen && inc.Status != StatusContained {
			continue
		}
		c.bindLocked(&inc)
		// credential_spray super-incidents persist in bbolt but the spray
		// detector's perIP map is in-memory only. Without this rehydration
		// step a daemon restart while an attacker is mid-spray causes the
		// detector to re-trip and open a duplicate super-incident even
		// though the original is still active.
		if c.spray != nil && inc.Kind == KindCredentialSpray && inc.CorrelationKey != nil {
			ip := inc.CorrelationKey.RemoteIP
			if ip != "" {
				c.spray.Rehydrate(ip, inc.ID, inc.UpdatedAt)
			}
		}
	}
}

func (c *Correlator) bindLocked(inc *Incident) {
	key, ok := incidentKey(*inc)
	if !ok {
		return
	}
	c.byKey[keyString(key)] = inc.ID
}

func (c *Correlator) unbindLocked(id string) {
	// Scan-and-delete by value rather than rebuilding the key: incidents
	// can be keyed by account, domain, mailbox, process, remote IP, or a
	// combination. byKey only holds active incidents so the scan is bounded.
	for k, v := range c.byKey {
		if v == id {
			delete(c.byKey, k)
		}
	}
}

func incidentKey(inc Incident) (Key, bool) {
	if inc.CorrelationKey != nil && !inc.CorrelationKey.IsEmpty() {
		return canonicalizeKey(*inc.CorrelationKey), true
	}
	key := Key{Account: inc.Account, Domain: inc.Domain, Mailbox: inc.Mailbox}
	key = canonicalizeKey(key)
	if key.IsEmpty() {
		return Key{}, false
	}
	return key, true
}

func cloneIncident(in Incident) Incident {
	out := in
	out.Findings = append([]string(nil), in.Findings...)
	out.Timeline = append([]IncidentEvent(nil), in.Timeline...)
	out.Actions = append([]IncidentAction(nil), in.Actions...)
	if in.CorrelationKey != nil {
		key := *in.CorrelationKey
		out.CorrelationKey = &key
	}
	return out
}

func cloneKey(k Key) *Key {
	if k.IsEmpty() {
		return nil
	}
	key := k
	return &key
}

// keyString serializes a Key into a stable string for the byKey map.
// All fields selected by KeyFor must be encoded so distinct findings
// (e.g. different PID-only processes or different remote IPs) do not
// collapse to the same bucket and falsely merge.
func keyString(k Key) string {
	return fmt.Sprintf("%d:%s|%d:%s|%d:%s|%d:%s|%d|%d|%d:%s",
		len(k.Host), k.Host,
		len(k.Account), k.Account,
		len(k.Mailbox), k.Mailbox,
		len(k.Domain), k.Domain,
		k.UID,
		k.PID,
		len(k.RemoteIP), k.RemoteIP,
	)
}

func opensIncidentImmediately(f alert.Finding) bool {
	if f.Severity >= alert.Critical {
		return true
	}
	return f.Severity >= alert.High && ClassifyKind(f) == KindHostIntegrityRisk
}

func newIncidentID() string {
	var buf [6]byte
	_, _ = rand.Read(buf[:])
	return "inc_" + hex.EncodeToString(buf[:])
}

// maybeBlockSprayLocked is the single decision point for the
// credential_spray firewall hand-off. Unlike a transition-only hook,
// this runs on every spray decision (open, merge, escalate) so an
// operator who arms BlockAtSeverity AFTER an incident has already
// reached the configured severity still gets a block on the next
// matching finding. Idempotency is provided by
// triggerSprayBlockLocked's existing action-presence guard, so calling
// this helper repeatedly against the same incident emits exactly one
// firewall call.
//
// Returns the callback that the caller must invoke after releasing
// c.mu (matches the existing sprayDecisionOpen contract), or nil when
// no block is owed.
func (c *Correlator) maybeBlockSprayLocked(inc *Incident, ip string, hits int, now time.Time, reason string) func() {
	if inc == nil || c.spray == nil || c.cfg.OnSprayBlock == nil {
		return nil
	}
	if !incidentStatusActive(inc.Status) {
		return nil
	}
	if !c.sprayBlockAllowed() {
		return nil
	}
	switch strings.ToLower(c.spray.cfg.BlockAtSeverity) {
	case "high":
		if inc.Severity < alert.High {
			return nil
		}
	case "critical":
		if inc.Severity < alert.Critical {
			return nil
		}
	default:
		return nil
	}
	return c.triggerSprayBlockLocked(inc, ip, hits, now, reason)
}

func (c *Correlator) sprayBlockAllowed() bool {
	return c.cfg.CanSprayBlock == nil || c.cfg.CanSprayBlock()
}

// maybeBlockIncidentLocked is the decision point for the generic
// incident-driven firewall hand-off. Runs on every create / merge so
// an operator who arms AutoBlock AFTER an incident has already crossed
// the gate still gets a block on the next finding. Idempotent via the
// action-presence and in-flight guards in triggerIncidentBlockLocked.
//
// Skips credential_spray incidents -- the dedicated spray hand-off owns
// those so we avoid double-firing.
//
// Returns the callback that the caller must invoke after releasing
// c.mu, or nil when no block is owed.
func (c *Correlator) maybeBlockIncidentLocked(inc *Incident, now time.Time, why string) func() {
	if inc == nil || c.cfg.OnIncidentBlock == nil || !c.cfg.AutoBlock.Enabled {
		return nil
	}
	if !incidentStatusActive(inc.Status) {
		return nil
	}
	if inc.Kind == KindCredentialSpray {
		return nil
	}
	if c.sprayOwnsIncident(inc) {
		return nil
	}
	if !c.incidentBlockAllowed() {
		return nil
	}
	ip := incidentBlockCandidate(inc)
	if ip == "" {
		return nil
	}
	if len(c.cfg.AutoBlock.Kinds) > 0 && !c.cfg.AutoBlock.Kinds[inc.Kind] {
		return nil
	}
	switch strings.ToLower(c.cfg.AutoBlock.BlockAtSeverity) {
	case "high":
		if inc.Severity < alert.High {
			return nil
		}
	case "critical":
		if inc.Severity < alert.Critical {
			return nil
		}
	default:
		return nil
	}
	return c.triggerIncidentBlockLocked(inc, ip, now, why)
}

func (c *Correlator) incidentBlockAllowed() bool {
	return c.cfg.CanIncidentBlock == nil || c.cfg.CanIncidentBlock()
}

// triggerIncidentBlockLocked is the per-incident emit point for the
// generic auto-block path. It marks the incident as in-flight, returns
// the deferred callback, then appends "incident_block_requested" only
// when the callback reports a live block request. Dry-run attempts are
// intentionally not latched so a later finding can retry after the
// operator disables dry-run.
func (c *Correlator) triggerIncidentBlockLocked(inc *Incident, ip string, now time.Time, why string) func() {
	if inc == nil || c.cfg.OnIncidentBlock == nil {
		return nil
	}
	if hasIncidentAction(inc.Actions, "incident_block_requested") {
		return nil
	}
	if _, ok := c.pendingIncidentBlocks[inc.ID]; ok {
		return nil
	}
	c.pendingIncidentBlocks[inc.ID] = struct{}{}
	incidentID := inc.ID
	reason := "incident " + string(inc.Kind) + " " + inc.Severity.String() + " (" + why + ")"
	onBlock := c.cfg.OnIncidentBlock
	return func() {
		live := onBlock(ip, reason)
		c.mu.Lock()
		defer c.mu.Unlock()
		delete(c.pendingIncidentBlocks, incidentID)
		if !live {
			return
		}
		current, ok := c.incidents[incidentID]
		if !ok || hasIncidentAction(current.Actions, "incident_block_requested") {
			return
		}
		current.Actions = append(current.Actions, IncidentAction{
			Time:    now,
			Action:  "incident_block_requested",
			Result:  "ok",
			Details: ip + " " + reason,
		})
		c.persistLocked(*current)
	}
}

func incidentBlockCandidate(inc *Incident) string {
	if inc == nil {
		return ""
	}
	if inc.CorrelationKey != nil {
		if ip := normalizeIncidentRemoteIP(inc.CorrelationKey.RemoteIP); ip != "" {
			return ip
		}
	}
	var candidate string
	for _, ev := range inc.Timeline {
		if ev.Kind == incidentTimelineTruncatedKind {
			return ""
		}
		ip := normalizeIncidentRemoteIP(ev.RemoteIP)
		if ip == "" {
			continue
		}
		if candidate == "" {
			candidate = ip
			continue
		}
		if candidate != ip {
			return ""
		}
	}
	return candidate
}

func (c *Correlator) sprayOwnsIncident(inc *Incident) bool {
	if c == nil || c.spray == nil || inc == nil {
		return false
	}
	owned := false
	for _, ev := range inc.Timeline {
		if ev.RemoteIP == "" {
			continue
		}
		if !c.spray.cfg.PerCheck[ev.Check] {
			return false
		}
		owned = true
	}
	return owned
}

func normalizeIncidentRemoteIP(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	}
	raw = strings.Trim(raw, "[]")
	ip := net.ParseIP(raw)
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
		return ""
	}
	return ip.String()
}

func hasIncidentAction(actions []IncidentAction, action string) bool {
	for _, a := range actions {
		if a.Action == action {
			return true
		}
	}
	return false
}

// triggerSprayBlockLocked invokes the operator-supplied OnSprayBlock
// callback at most once per spray incident and appends an audit action
// only when the callback reports the firewall actually applied the block.
// Caller holds c.mu. The returned callback must be invoked after
// unlocking. Idempotent: a second call against the same incident is a
// no-op so the open + escalate paths can both arm without producing
// duplicate firewall calls.
func (c *Correlator) triggerSprayBlockLocked(inc *Incident, ip string, hits int, now time.Time, why string) func() {
	if inc == nil || c.cfg.OnSprayBlock == nil {
		return nil
	}
	if hasIncidentAction(inc.Actions, "credential_spray_block_requested") {
		return nil
	}
	reason := "credential_spray: " + strconv.Itoa(hits) + " distinct mailboxes (" + why + ")"
	onSprayBlock := c.cfg.OnSprayBlock
	incidentID := inc.ID
	return func() {
		live := onSprayBlock(ip, reason)
		if !live {
			return
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		current, ok := c.incidents[incidentID]
		if !ok || hasIncidentAction(current.Actions, "credential_spray_block_requested") {
			return
		}
		current.Actions = append(current.Actions, IncidentAction{
			Time:    now,
			Action:  "credential_spray_block_requested",
			Result:  "ok",
			Details: ip + " " + reason,
		})
		c.persistLocked(*current)
	}
}
