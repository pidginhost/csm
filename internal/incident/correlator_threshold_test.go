package incident

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// newThresholdCorrelator builds a correlator that requires two findings
// before an incident opens. Default Critical severity stays exempt from
// the threshold so high-severity findings still page operators on the
// first hit.
func newThresholdCorrelator(threshold int) *Correlator {
	c := NewCorrelator(CorrelatorConfig{OpenThreshold: threshold})
	c.now = func() time.Time { return time.Unix(1_700_000_000, 0) }
	return c
}

// First non-Critical finding must NOT open an incident; second finding
// against the same key inside the merge window opens with both events
// present in the timeline. This is the headline behavior change: an
// isolated probe (one modsec hit, one mistyped password) is no longer
// enough to open an incident.
func TestCorrelatorThresholdDefersIncidentUntilSecondFinding(t *testing.T) {
	c := newThresholdCorrelator(2)
	f := alert.Finding{
		Check:     "email_auth_failure_realtime",
		Severity:  alert.High,
		Mailbox:   "alice@example.com",
		Domain:    "example.com",
		Timestamp: time.Unix(1_700_000_000, 0),
	}

	id, created, err := c.OnFinding(f)
	if err != nil {
		t.Fatalf("OnFinding: %v", err)
	}
	if created || id != "" {
		t.Errorf("first finding under threshold opened incident: id=%q created=%v", id, created)
	}
	if got := len(c.Snapshot()); got != 0 {
		t.Errorf("Snapshot after first finding: got %d incidents, want 0", got)
	}

	c.now = func() time.Time { return time.Unix(1_700_000_000+60, 0) }
	f.Timestamp = time.Unix(1_700_000_000+60, 0)
	id2, created2, err := c.OnFinding(f)
	if err != nil {
		t.Fatalf("second OnFinding: %v", err)
	}
	if !created2 || id2 == "" {
		t.Errorf("second finding must open incident: id=%q created=%v", id2, created2)
	}
	inc, ok := c.Get(id2)
	if !ok {
		t.Fatal("Get on freshly created incident returned not-found")
	}
	if len(inc.Timeline) != 2 {
		t.Errorf("timeline length = %d, want 2 (pending + new)", len(inc.Timeline))
	}
}

// Critical-severity findings must bypass the threshold so escalations
// (modsec_csm_block_escalation, account compromise, cloud-relay abuse)
// page on the first hit.
func TestCorrelatorThresholdBypassedForCriticalSeverity(t *testing.T) {
	c := newThresholdCorrelator(2)
	f := alert.Finding{
		Check:     "email_compromised_account",
		Severity:  alert.Critical,
		Mailbox:   "alice@example.com",
		Domain:    "example.com",
		Timestamp: time.Unix(1_700_000_000, 0),
	}
	id, created, err := c.OnFinding(f)
	if err != nil {
		t.Fatalf("OnFinding: %v", err)
	}
	if !created || id == "" {
		t.Errorf("Critical finding must open incident on first hit: id=%q created=%v", id, created)
	}
}

func TestCorrelatorThresholdBypassedForHighHostIntegrity(t *testing.T) {
	c := newThresholdCorrelator(2)
	f := alert.Finding{
		Check:     "kernel_module",
		Severity:  alert.High,
		Message:   "New kernel module loaded after baseline: x",
		Timestamp: time.Unix(1_700_000_000, 0),
	}
	id, created, err := c.OnFinding(f)
	if err != nil {
		t.Fatalf("OnFinding: %v", err)
	}
	if !created || id == "" {
		t.Fatalf("High host-integrity finding must open incident on first hit: id=%q created=%v", id, created)
	}
	inc, ok := c.Get(id)
	if !ok {
		t.Fatal("Get on freshly created incident returned not-found")
	}
	if inc.Kind != KindHostIntegrityRisk {
		t.Fatalf("Kind = %s, want host_integrity_risk", inc.Kind)
	}
	if inc.CorrelationKey == nil || inc.CorrelationKey.Host != "host" {
		t.Fatalf("CorrelationKey = %+v, want Host=host", inc.CorrelationKey)
	}
}

// A pending finding that ages past the merge window must NOT promote
// when a much-later second finding arrives. The later finding becomes
// the new pending entry; otherwise stale half-hour-old probes would
// merge with current activity and contaminate the incident timeline.
func TestCorrelatorThresholdDropsPendingPastMergeWindow(t *testing.T) {
	c := newThresholdCorrelator(2)
	f := alert.Finding{
		Check:     "modsec_block_realtime",
		Severity:  alert.Warning,
		Domain:    "example.com",
		Timestamp: time.Unix(1_700_000_000, 0),
	}
	if _, created, _ := c.OnFinding(f); created {
		t.Fatal("first finding must not create incident")
	}

	// Advance past the merge window before the second finding.
	c.now = func() time.Time { return time.Unix(1_700_000_000+int64(2*incidentMergeWindow.Seconds()), 0) }
	f.Timestamp = time.Unix(1_700_000_000+int64(2*incidentMergeWindow.Seconds()), 0)
	id, created, _ := c.OnFinding(f)
	if created || id != "" {
		t.Errorf("second finding outside window must not promote stale pending: id=%q created=%v", id, created)
	}
	if got := len(c.Snapshot()); got != 0 {
		t.Errorf("Snapshot: got %d incidents, want 0 (both findings still pending)", got)
	}
}

// Threshold-1 (or zero, defaulted to 1) preserves legacy behavior:
// the first finding opens immediately. Existing correlator tests that
// pass a single non-Critical finding rely on this.
func TestCorrelatorThresholdOneOpensOnFirstFinding(t *testing.T) {
	c := newThresholdCorrelator(1)
	f := alert.Finding{
		Check:     "wp_login_bruteforce",
		Severity:  alert.High,
		TenantID:  "alice",
		Timestamp: time.Unix(1_700_000_000, 0),
	}
	id, created, _ := c.OnFinding(f)
	if !created || id == "" {
		t.Errorf("threshold=1: first finding must open incident: id=%q created=%v", id, created)
	}
}

// Findings against different keys must not satisfy each other's
// threshold. Two unrelated probes against different mailboxes both
// stay pending; neither opens an incident.
func TestCorrelatorThresholdIsPerKey(t *testing.T) {
	c := newThresholdCorrelator(2)
	a := alert.Finding{
		Check: "email_auth_failure_realtime", Severity: alert.High,
		Mailbox: "alice@example.com", Domain: "example.com",
		Timestamp: time.Unix(1_700_000_000, 0),
	}
	b := alert.Finding{
		Check: "email_auth_failure_realtime", Severity: alert.High,
		Mailbox: "bob@example.com", Domain: "example.com",
		Timestamp: time.Unix(1_700_000_000, 0),
	}
	if _, _, err := c.OnFinding(a); err != nil {
		t.Fatalf("OnFinding a: %v", err)
	}
	if _, _, err := c.OnFinding(b); err != nil {
		t.Fatalf("OnFinding b: %v", err)
	}
	if got := len(c.Snapshot()); got != 0 {
		t.Errorf("two findings against different mailboxes opened %d incidents, want 0", got)
	}
}

// Once an incident is open, subsequent findings against the same key
// merge into it as before. The threshold is consumed on the create
// path only; the merge path stays unconditional so a sustained burst
// keeps growing the timeline.
func TestCorrelatorThresholdSubsequentFindingsMergeIntoOpenIncident(t *testing.T) {
	c := newThresholdCorrelator(2)
	f := alert.Finding{
		Check: "email_auth_failure_realtime", Severity: alert.High,
		Mailbox: "alice@example.com", Domain: "example.com",
		Timestamp: time.Unix(1_700_000_000, 0),
	}
	if _, _, err := c.OnFinding(f); err != nil {
		t.Fatalf("OnFinding: %v", err)
	}
	c.now = func() time.Time { return time.Unix(1_700_000_000+60, 0) }
	id, _, _ := c.OnFinding(f)
	c.now = func() time.Time { return time.Unix(1_700_000_000+120, 0) }
	id2, created2, _ := c.OnFinding(f)
	if created2 {
		t.Errorf("third finding into open incident must merge, not create")
	}
	if id != id2 {
		t.Errorf("third finding bound to %q, want existing %q", id2, id)
	}
	inc, _ := c.Get(id)
	if len(inc.Timeline) != 3 {
		t.Errorf("timeline length = %d, want 3", len(inc.Timeline))
	}
}

// Stale pending entries are pruned by PruneStalePending so the map
// cannot grow without bound on a host that never crosses the
// threshold for some keys (one-shot scanners).
func TestCorrelatorThresholdPrunesStalePending(t *testing.T) {
	c := newThresholdCorrelator(2)
	f := alert.Finding{
		Check: "modsec_block_realtime", Severity: alert.Warning,
		Domain:    "example.com",
		Timestamp: time.Unix(1_700_000_000, 0),
	}
	if _, _, err := c.OnFinding(f); err != nil {
		t.Fatalf("OnFinding: %v", err)
	}
	if got := c.PendingCount(); got != 1 {
		t.Fatalf("PendingCount after first finding: got %d, want 1", got)
	}
	pruned := c.PruneStalePending(time.Unix(1_700_000_000+int64(2*incidentMergeWindow.Seconds()), 0))
	if pruned != 1 {
		t.Errorf("PruneStalePending returned %d, want 1", pruned)
	}
	if got := c.PendingCount(); got != 0 {
		t.Errorf("PendingCount after prune: got %d, want 0", got)
	}
}
