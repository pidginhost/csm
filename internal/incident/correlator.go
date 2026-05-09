package incident

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
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
	return &Correlator{
		cfg:           cfg,
		incidents:     map[string]*Incident{},
		byKey:         map[string]string{},
		pending:       map[string]pendingFinding{},
		openThreshold: threshold,
		now:           time.Now,
	}
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
	c.mu.Lock()
	defer c.mu.Unlock()

	matched := make([]Incident, 0, len(c.incidents))
	for _, inc := range c.incidents {
		if status != "" && inc.Status != status {
			continue
		}
		matched = append(matched, cloneIncident(*inc))
	}
	sort.Slice(matched, func(i, j int) bool {
		return matched[i].UpdatedAt.After(matched[j].UpdatedAt)
	})

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
	return matched[offset:end], total
}

// Snapshot returns every incident sorted by UpdatedAt descending. Safe
// for concurrent callers; produces a deep-copy slice so the API layer
// can serialize it without coordinating with mutators.
func (c *Correlator) Snapshot() []Incident {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Incident, 0, len(c.incidents))
	for _, inc := range c.incidents {
		out = append(out, cloneIncident(*inc))
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].UpdatedAt.After(out[j].UpdatedAt)
	})
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
		c.unbindLocked(id)
	} else {
		c.bindLocked(inc)
	}
	c.persistLocked(*inc)
	return nil
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
