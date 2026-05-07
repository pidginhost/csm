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
	mu        sync.Mutex
	cfg       CorrelatorConfig
	incidents map[string]*Incident
	byKey     map[string]string
	now       func() time.Time
	counters  counters
}

// NewCorrelator returns a ready Correlator. Nothing to start; this type
// is purely callback-driven.
func NewCorrelator(cfg CorrelatorConfig) *Correlator {
	return &Correlator{
		cfg:       cfg,
		incidents: map[string]*Incident{},
		byKey:     map[string]string{},
		now:       time.Now,
	}
}

// OnFinding ingests a Finding. Returns the incident id (if attributable)
// and whether a new incident was created. Unattributable findings yield
// ("", false, nil).
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
			return id, false, nil
		}
		// Stale binding -- the incident is older than the merge window.
		// Drop the binding and fall through to create so a fresh incident
		// owns the key going forward.
		delete(c.byKey, keyStr)
	}

	id := newIncidentID()
	inc := &Incident{
		ID:        id,
		Kind:      ClassifyKind(f),
		Status:    StatusOpen,
		Severity:  f.Severity,
		Account:   key.Account,
		Domain:    key.Domain,
		Mailbox:   key.Mailbox,
		Findings:  []string{},
		Timeline:  []IncidentEvent{},
		Actions:   []IncidentAction{},
		CreatedAt: now,
		UpdatedAt: now,
	}
	// Populate maps before mergeLocked so a re-entrant Persist that
	// calls Get(id) (or any lookup) sees the freshly-created incident.
	// mergeLocked is the single source of truth for Persist invocations,
	// avoiding the previous double-fire on create.
	c.incidents[id] = inc
	c.byKey[keyStr] = id
	c.counters.createdTotal.Add(1)
	c.mergeLocked(inc, f, now, false)
	return id, true, nil
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
	return *inc, true
}

// Snapshot returns every incident sorted by UpdatedAt descending. Safe
// for concurrent callers; produces a value-copy slice so the API layer
// can serialize it without coordinating with mutators.
func (c *Correlator) Snapshot() []Incident {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Incident, 0, len(c.incidents))
	for _, inc := range c.incidents {
		out = append(out, *inc)
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
	c.mu.Unlock()
	defer c.mu.Lock()
	c.cfg.Persist(snap)
}

// SetStatus transitions an incident's status. On Resolved/Dismissed
// the incident is unbound from the active byKey index so future
// findings for the same correlation key start a fresh incident.
// Returns ErrIncidentNotFound if id is unknown.
func (c *Correlator) SetStatus(id string, status Status, details string) error {
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
	// Scan-and-delete by value rather than rebuilding the key: SetStatus
	// fires on incidents created with the broader KeyFor (UID/PID/RemoteIP)
	// while a narrow Key{Account,Domain,Mailbox} would miss those entries.
	// byKey only holds active incidents so the O(n) scan is bounded.
	if status == StatusResolved || status == StatusDismissed {
		for k, v := range c.byKey {
			if v == id {
				delete(c.byKey, k)
				break
			}
		}
	}
	c.persistLocked(*inc)
	return nil
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
			key := Key{Account: inc.Account, Domain: inc.Domain, Mailbox: inc.Mailbox}
			c.byKey[keyString(key)] = inc.ID
		}
	}
}

// keyString serializes a Key into a stable string for the byKey map.
// All identifying fields must be encoded so distinct findings (e.g.
// different PIDs with no Account, or different remote IPs) do not
// collapse to the same bucket and falsely merge.
func keyString(k Key) string {
	return fmt.Sprintf("%s|%s|%s|%d|%d|%s", k.Account, k.Mailbox, k.Domain, k.UID, k.PID, k.RemoteIP)
}

func newIncidentID() string {
	var buf [6]byte
	_, _ = rand.Read(buf[:])
	return "inc_" + hex.EncodeToString(buf[:])
}
