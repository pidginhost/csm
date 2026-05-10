package incident

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// ErrIncidentNotFound is returned when SetStatus or other lookups
// target an unknown incident id.
var ErrIncidentNotFound = errors.New("incident: not found")

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
	mu            sync.Mutex
	cfg           CorrelatorConfig
	incidents     map[string]*Incident
	byKey         map[string]string
	pending       map[string]pendingFinding
	openThreshold int
	now           func() time.Time
	counters      counters
	spray         *sprayDetector
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
		cfg:           cfg,
		incidents:     map[string]*Incident{},
		byKey:         map[string]string{},
		pending:       map[string]pendingFinding{},
		openThreshold: threshold,
		now:           time.Now,
	}
	c.spray = newSprayDetector(cfg.SpraySuppression, incidentMergeWindow, func() time.Time { return c.now() }, cfg.IsWhitelisted)
	return c
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
	c.mu.Lock()
	defer c.mu.Unlock()

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
			return id, true, nil
		case sprayDecisionSuppress:
			id := c.spray.IncidentForIP(f.SourceIP)
			if inc, ok := c.incidents[id]; ok {
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
				c.counters.spraySuppressedTotal.Add(1)
				return id, false, nil
			}
			// Bound incident vanished (e.g. operator dismissed it). Fall
			// through to legacy path so the finding still produces an
			// incident rather than silently disappearing.
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
			return id, false, nil
		}
		// Stale binding -- the incident is older than the merge window.
		// Drop the binding and fall through to create so a fresh incident
		// owns the key going forward.
		delete(c.byKey, keyStr)
	}

	// Threshold gate. Non-Critical findings need OpenThreshold sightings
	// inside the merge window before opening an incident; Critical
	// findings always open immediately so escalations and known-bad
	// signals (account compromise, cloud-relay abuse, modsec
	// escalations) page on the first hit.
	if c.openThreshold > 1 && f.Severity < alert.Critical {
		if pf, ok := c.pending[keyStr]; ok && now.Sub(pf.at) <= incidentMergeWindow {
			delete(c.pending, keyStr)
			id := c.createIncidentLocked(key, keyStr, pf.finding, pf.at)
			inc := c.incidents[id]
			c.mergeLocked(inc, f, now, true)
			return id, true, nil
		}
		c.pending[keyStr] = pendingFinding{finding: f, at: now}
		return "", false, nil
	}

	id := c.createIncidentLocked(key, keyStr, f, now)
	delete(c.pending, keyStr)
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
	inc := &Incident{
		ID:             id,
		Kind:           ClassifyKind(f),
		Status:         StatusOpen,
		Severity:       f.Severity,
		Account:        key.Account,
		Domain:         key.Domain,
		Mailbox:        key.Mailbox,
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
	inc.Findings = append(inc.Findings, f.Fingerprint())
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
	inc.Timeline = append(inc.Timeline, ev)
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

// persistLocked invokes the Persist callback while temporarily releasing
// the correlator mutex so a re-entrant Persist (which may call Get or
// any other Correlator method that takes mu) does not deadlock. The
// caller MUST already hold c.mu; the deferred re-Lock keeps the
// "mu held on return" contract that mergeLocked's callers rely on.
func (c *Correlator) persistLocked(snap Incident) {
	if c.cfg.Persist == nil {
		return
	}
	snap = cloneIncident(snap)
	c.mu.Unlock()
	defer c.mu.Lock()
	c.cfg.Persist(snap)
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
// The merge window's stale-binding logic (see correlator.go OnFinding)
// already lets fresh findings open a new incident after the bound
// incident becomes stale, so closing here does not block re-detection.
func (c *Correlator) CloseStale(now time.Time, idleThresholds map[Kind]time.Duration, dryRun bool) (closed, dryRunCount, scanned int) {
	if len(idleThresholds) == 0 {
		return 0, 0, 0
	}
	var persist []Incident
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
		if c.cfg.Persist != nil {
			persist = append(persist, cloneIncident(*inc))
		}
		closed++
	}
	c.mu.Unlock()

	for _, snap := range persist {
		c.cfg.Persist(snap)
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
		if inc.Status == StatusOpen || inc.Status == StatusContained {
			c.bindLocked(&inc)
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
		return *inc.CorrelationKey, true
	}
	key := Key{Account: inc.Account, Domain: inc.Domain, Mailbox: inc.Mailbox}
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
// All identifying fields must be encoded so distinct findings (e.g.
// different PIDs with no Account, or different remote IPs) do not
// collapse to the same bucket and falsely merge.
func keyString(k Key) string {
	return fmt.Sprintf("%d:%s|%d:%s|%d:%s|%d|%d|%d:%s",
		len(k.Account), k.Account,
		len(k.Mailbox), k.Mailbox,
		len(k.Domain), k.Domain,
		k.UID,
		k.PID,
		len(k.RemoteIP), k.RemoteIP,
	)
}

func newIncidentID() string {
	var buf [6]byte
	_, _ = rand.Read(buf[:])
	return "inc_" + hex.EncodeToString(buf[:])
}
