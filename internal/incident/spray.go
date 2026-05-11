package incident

import (
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// SpraySuppressionConfig is the operator-tunable knob set for the
// credential-spray detector. Defaults are conservative: enabled=false and
// dry_run=true so the detector ships dark, increments counters, and only
// changes incident routing once an operator opts in.
type SpraySuppressionConfig struct {
	Enabled            bool
	DryRun             bool
	DistinctMailboxes  int
	SeverityEscalateAt int
	PerCheck           map[string]bool
	MaxTrackedIPs      int
	// BlockAtSeverity gates the firewall hand-off. Values:
	//   "" / unset  - detection-only (legacy behavior).
	//   "high"      - block on incident open (DistinctMailboxes trip).
	//   "critical"  - block on severity escalation (SeverityEscalateAt).
	// Comparison is case-insensitive. Any other value is ignored so an
	// operator typo cannot accidentally engage blocking.
	BlockAtSeverity string
}

// IsZero reports whether the config is unset; the correlator treats a
// zero value as "spray detection disabled" without touching defaults.
func (c SpraySuppressionConfig) IsZero() bool {
	return !c.Enabled && !c.DryRun && c.DistinctMailboxes == 0 && c.SeverityEscalateAt == 0 && len(c.PerCheck) == 0 && c.MaxTrackedIPs == 0 && c.BlockAtSeverity == ""
}

// sprayDecision is the verdict the detector returns to OnFinding for a
// candidate spray-class finding.
type sprayDecision int

const (
	// sprayDecisionNone means the finding is not spray traffic; the
	// caller should run the normal per-mailbox correlation path.
	sprayDecisionNone sprayDecision = iota
	// sprayDecisionOpen means this finding tipped the IP over the
	// distinct-mailbox threshold; the caller must open a new
	// credential_spray incident keyed on RemoteIP and report the id back
	// to the detector via BindIncident.
	sprayDecisionOpen
	// sprayDecisionSuppress means an active spray incident already
	// exists for the IP and the finding should be attached to it
	// instead of opening a per-mailbox incident.
	sprayDecisionSuppress
)

// ipSprayState tracks the distinct-mailbox set hit by a single source IP
// inside the merge window, plus the bound spray incident id once the
// threshold trips.
type ipSprayState struct {
	mailboxes map[string]struct{}
	firstSeen time.Time
	lastSeen  time.Time
	// incident is the bound credential_spray incident id once the
	// threshold has tripped. Empty until then.
	incident string
}

// sprayDetector keeps a per-IP sliding window of distinct mailboxes hit
// by spray-class checks and decides whether a finding should open a new
// credential_spray super-incident, attach to an existing one, or fall
// through to the normal per-mailbox correlator path.
//
// Concurrency: the correlator's mutex serializes all calls into the
// detector. The detector itself does not take a separate lock so the
// "single mutex protects all correlator state" invariant holds.
type sprayDetector struct {
	cfg           SpraySuppressionConfig
	window        time.Duration
	now           func() time.Time
	isWhitelisted func(string) bool

	// perIP is the live state map. Bounded by cfg.MaxTrackedIPs; entries
	// that fall outside the window during Decide are pruned in place,
	// and once the map exceeds the cap the oldest-by-lastSeen entry is
	// evicted before insert.
	perIP map[string]*ipSprayState
}

// newSprayDetector returns a detector wired to the supplied config.
// Returns nil when cfg is zero-valued so the correlator can no-op the
// fast path on hosts that have not opted in.
func newSprayDetector(cfg SpraySuppressionConfig, window time.Duration, now func() time.Time, isWhitelisted func(string) bool) *sprayDetector {
	if cfg.IsZero() {
		return nil
	}
	if cfg.MaxTrackedIPs <= 0 {
		cfg.MaxTrackedIPs = 10000
	}
	if cfg.DistinctMailboxes <= 0 {
		cfg.DistinctMailboxes = 10
	}
	if cfg.SeverityEscalateAt <= cfg.DistinctMailboxes {
		// Default to 5x threshold so a CRITICAL bump only fires on
		// genuinely sustained sprays, not on the immediate trip.
		cfg.SeverityEscalateAt = cfg.DistinctMailboxes * 5
	}
	if isWhitelisted == nil {
		isWhitelisted = func(string) bool { return false }
	}
	if now == nil {
		now = time.Now
	}
	return &sprayDetector{
		cfg:           cfg,
		window:        window,
		now:           now,
		isWhitelisted: isWhitelisted,
		perIP:         make(map[string]*ipSprayState),
	}
}

// Decide consumes a spray-candidate finding and returns the decision
// the correlator should apply. The detector mutates internal state
// (records the mailbox, tracks the lastSeen timestamp) regardless of
// the dry_run flag so counters and audit logs reflect what the live
// path would have done; only the returned decision is gated by
// dry_run. Caller must hold the correlator mutex.
//
// hitCount is the number of distinct mailboxes the IP has hit inside
// the window after this finding is recorded. The caller uses it to
// decide severity for sprayDecisionOpen and to escalate severity on
// merge-into-existing-spray.
func (d *sprayDetector) Decide(f alert.Finding) (decision sprayDecision, hitCount int) {
	if d == nil || !d.cfg.Enabled && !d.cfg.DryRun {
		return sprayDecisionNone, 0
	}
	if f.SourceIP == "" {
		return sprayDecisionNone, 0
	}
	if !d.cfg.PerCheck[f.Check] {
		return sprayDecisionNone, 0
	}
	if d.isWhitelisted(f.SourceIP) {
		return sprayDecisionNone, 0
	}

	// Identity dimension for the distinct-set: prefer mailbox; fall back
	// to tenant id (per-account brute force); fall back to cPanel user
	// (php-relay attribution); fall back to message text so two findings
	// without any structured identity still count as distinct attempts.
	target := f.Mailbox
	if target == "" {
		target = f.TenantID
	}
	if target == "" {
		target = f.CPUser
	}
	if target == "" {
		target = f.Message
	}
	if target == "" {
		return sprayDecisionNone, 0
	}

	now := d.now()
	state, ok := d.perIP[f.SourceIP]
	if ok {
		// Window expiration: a state whose lastSeen fell outside the
		// window is stale; reset before recording the new hit so a
		// fresh attack does not inherit a tripped-but-cold binding.
		if now.Sub(state.lastSeen) > d.window {
			state = nil
			delete(d.perIP, f.SourceIP)
		}
	}
	if state == nil {
		// Eviction: keep the live set bounded. Drop the oldest-by-lastSeen
		// entry before inserting if we are at the cap. O(N) scan; cheap
		// at the configured cap (10k) and only runs at insert time.
		if len(d.perIP) >= d.cfg.MaxTrackedIPs {
			d.evictOldestLocked()
		}
		state = &ipSprayState{
			mailboxes: make(map[string]struct{}),
			firstSeen: now,
		}
		d.perIP[f.SourceIP] = state
	}
	state.mailboxes[target] = struct{}{}
	state.lastSeen = now
	hitCount = len(state.mailboxes)

	// Bound to existing spray incident? Continue suppressing.
	if state.incident != "" {
		if d.cfg.DryRun {
			return sprayDecisionNone, hitCount
		}
		return sprayDecisionSuppress, hitCount
	}

	if hitCount < d.cfg.DistinctMailboxes {
		return sprayDecisionNone, hitCount
	}

	// Threshold tripped. Live mode opens a new spray incident; dry_run
	// only counts the decision so the operator can observe the workload
	// without changing routing.
	if d.cfg.DryRun {
		return sprayDecisionNone, hitCount
	}
	return sprayDecisionOpen, hitCount
}

// BindIncident records the spray incident id the correlator just
// created in response to sprayDecisionOpen. Subsequent findings from
// the same IP return sprayDecisionSuppress until the window expires.
// Caller holds the correlator mutex.
func (d *sprayDetector) BindIncident(ip, id string) {
	if d == nil {
		return
	}
	if state, ok := d.perIP[ip]; ok {
		state.incident = id
	}
}

// Rehydrate seeds the perIP map at daemon startup so an open
// credential_spray incident restored from bbolt continues to suppress
// new per-mailbox fan-out instead of allowing a duplicate super-incident
// to open. The seeded state carries no per-mailbox set: the operator
// already saw the trip on the open incident, and the suppress path only
// reads state.incident. lastSeen is set so the existing window-expiry
// check can age this entry out naturally once the attacker quiets down.
// Caller holds the correlator mutex.
func (d *sprayDetector) Rehydrate(ip, id string, lastSeen time.Time) {
	if d == nil || ip == "" || id == "" {
		return
	}
	d.perIP[ip] = &ipSprayState{
		mailboxes: make(map[string]struct{}),
		firstSeen: lastSeen,
		lastSeen:  lastSeen,
		incident:  id,
	}
}

// IncidentForIP returns the bound spray incident id for ip, or "" if no
// spray is currently bound. Used by Decide's suppress path to tell the
// caller which incident to merge the finding into.
func (d *sprayDetector) IncidentForIP(ip string) string {
	if d == nil {
		return ""
	}
	if state, ok := d.perIP[ip]; ok {
		return state.incident
	}
	return ""
}

// PruneStale clears entries whose lastSeen is older than the window.
// Called by the daemon retention loop alongside PruneStalePending so
// the detector does not grow without bound on hosts with churning
// attacker IPs.
func (d *sprayDetector) PruneStale(now time.Time) int {
	if d == nil {
		return 0
	}
	pruned := 0
	for ip, state := range d.perIP {
		if now.Sub(state.lastSeen) > d.window {
			delete(d.perIP, ip)
			pruned++
		}
	}
	return pruned
}

// TrackedIPs returns the count of source IPs currently held in the
// detector. Surfaced via the csm_credential_spray_tracked_ips gauge.
func (d *sprayDetector) TrackedIPs() int {
	if d == nil {
		return 0
	}
	return len(d.perIP)
}

// evictOldestLocked drops the perIP entry with the smallest lastSeen.
// Caller holds the correlator mutex. Linear scan over MaxTrackedIPs.
func (d *sprayDetector) evictOldestLocked() {
	var oldestIP string
	var oldestAt time.Time
	first := true
	for ip, state := range d.perIP {
		if first || state.lastSeen.Before(oldestAt) {
			oldestIP = ip
			oldestAt = state.lastSeen
			first = false
		}
	}
	if oldestIP != "" {
		delete(d.perIP, oldestIP)
	}
}

// Counters for the credential-spray decisions live on the Correlator's
// existing `counters` struct (see correlator.go). Keeping them there
// means there is exactly one place that owns counter mutations, which
// keeps the metrics story coherent and avoids surprising operators
// who already grep for `csm_incidents_*`.
