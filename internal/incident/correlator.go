package incident

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
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
}

// Correlator groups findings into incidents. In-memory state; the
// daemon is responsible for wiring it to a store via CorrelatorConfig.Persist.
type Correlator struct {
	mu        sync.Mutex
	cfg       CorrelatorConfig
	incidents map[string]*Incident
	byKey     map[string]string
	now       func() time.Time
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
			c.mergeLocked(inc, f, now)
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
		Kind:      KindWebAccountCompromise, // refined in T5
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
	c.mergeLocked(inc, f, now)
	return id, true, nil
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

func (c *Correlator) mergeLocked(inc *Incident, f alert.Finding, now time.Time) {
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
