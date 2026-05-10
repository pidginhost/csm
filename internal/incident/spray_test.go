package incident

import (
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// sprayTestConfig returns a small spray config tuned for unit tests.
// Threshold is low (3) so test cases can drive a trip without seeding
// dozens of findings; production callers configure 10.
func sprayTestConfig(enabled, dryRun bool) SpraySuppressionConfig {
	return SpraySuppressionConfig{
		Enabled:            enabled,
		DryRun:             dryRun,
		DistinctMailboxes:  3,
		SeverityEscalateAt: 6,
		PerCheck: map[string]bool{
			"email_auth_failure_realtime": true,
		},
		MaxTrackedIPs: 100,
	}
}

func newSprayCorrelator(t *testing.T, enabled, dryRun bool) *Correlator {
	t.Helper()
	c := NewCorrelator(CorrelatorConfig{
		SpraySuppression: sprayTestConfig(enabled, dryRun),
	})
	c.openThreshold = 1
	c.now = func() time.Time { return time.Unix(1_700_000_000, 0) }
	if c.spray != nil {
		c.spray.now = c.now
	}
	return c
}

func sprayFinding(mailbox, ip string, ts time.Time) alert.Finding {
	return alert.Finding{
		Check:     "email_auth_failure_realtime",
		Severity:  alert.High,
		Mailbox:   mailbox,
		SourceIP:  ip,
		Timestamp: ts,
		Message:   "auth fail for " + mailbox + " from " + ip,
	}
}

func TestSprayBelowThresholdDoesNotOpenSpray(t *testing.T) {
	c := newSprayCorrelator(t, true, false)
	now := time.Unix(1_700_000_000, 0)

	for i := 0; i < 2; i++ { // threshold=3 in tests, drive 2 hits
		mb := "user" + strconv.Itoa(i) + "@example.com"
		_, _, err := c.OnFinding(sprayFinding(mb, "192.0.2.1", now))
		if err != nil {
			t.Fatalf("OnFinding: %v", err)
		}
	}

	if got := c.counters.sprayOpenedTotal.Load(); got != 0 {
		t.Errorf("sprayOpenedTotal = %d, want 0 below threshold", got)
	}
	for _, inc := range c.Snapshot() {
		if inc.Kind == KindCredentialSpray {
			t.Errorf("unexpected credential_spray incident below threshold: %+v", inc)
		}
	}
}

func TestSprayAtThresholdOpensSprayIncident(t *testing.T) {
	c := newSprayCorrelator(t, true, false)
	now := time.Unix(1_700_000_000, 0)

	for i := 0; i < 3; i++ {
		mb := "user" + strconv.Itoa(i) + "@example.com"
		_, _, err := c.OnFinding(sprayFinding(mb, "192.0.2.1", now.Add(time.Duration(i)*time.Minute)))
		if err != nil {
			t.Fatalf("OnFinding: %v", err)
		}
	}

	if got := c.counters.sprayOpenedTotal.Load(); got != 1 {
		t.Errorf("sprayOpenedTotal = %d, want 1", got)
	}
	var spray *Incident
	for _, inc := range c.Snapshot() {
		if inc.Kind == KindCredentialSpray {
			cp := inc
			spray = &cp
			break
		}
	}
	if spray == nil {
		t.Fatal("expected one credential_spray incident, got none")
	}
	if spray.CorrelationKey == nil || spray.CorrelationKey.RemoteIP != "192.0.2.1" {
		t.Errorf("spray correlation key = %+v, want RemoteIP=192.0.2.1", spray.CorrelationKey)
	}
}

func TestSprayAtThresholdSuppressesSubsequentMailboxTakeover(t *testing.T) {
	c := newSprayCorrelator(t, true, false)
	now := time.Unix(1_700_000_000, 0)

	// Trip the threshold.
	for i := 0; i < 3; i++ {
		mb := "user" + strconv.Itoa(i) + "@example.com"
		_, _, _ = c.OnFinding(sprayFinding(mb, "192.0.2.1", now.Add(time.Duration(i)*time.Minute)))
	}
	preSnapshot := len(c.Snapshot())

	// Two more mailboxes from the same IP. These should attach to the
	// existing spray incident, not open new mailbox_takeover incidents.
	for i := 3; i < 5; i++ {
		mb := "user" + strconv.Itoa(i) + "@example.com"
		_, _, _ = c.OnFinding(sprayFinding(mb, "192.0.2.1", now.Add(time.Duration(i)*time.Minute)))
	}
	postSnapshot := len(c.Snapshot())
	if postSnapshot != preSnapshot {
		t.Errorf("snapshot grew from %d to %d; suppress path should not create new incidents", preSnapshot, postSnapshot)
	}
	if got := c.counters.spraySuppressedTotal.Load(); got != 2 {
		t.Errorf("spraySuppressedTotal = %d, want 2", got)
	}
}

func TestSprayWhitelistedIPNeverOpensSpray(t *testing.T) {
	c := NewCorrelator(CorrelatorConfig{
		SpraySuppression: sprayTestConfig(true, false),
		IsWhitelisted: func(ip string) bool {
			return ip == "192.0.2.7"
		},
	})
	c.openThreshold = 1
	now := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return now }
	if c.spray != nil {
		c.spray.now = c.now
	}

	for i := 0; i < 5; i++ {
		mb := "victim" + strconv.Itoa(i) + "@example.com"
		_, _, _ = c.OnFinding(sprayFinding(mb, "192.0.2.7", now.Add(time.Duration(i)*time.Minute)))
	}

	if got := c.counters.sprayOpenedTotal.Load(); got != 0 {
		t.Errorf("whitelisted IP must not open spray (sprayOpenedTotal=%d)", got)
	}
	for _, inc := range c.Snapshot() {
		if inc.Kind == KindCredentialSpray {
			t.Errorf("whitelisted IP produced credential_spray: %+v", inc)
		}
	}
}

func TestSprayWindowExpirationClearsState(t *testing.T) {
	c := newSprayCorrelator(t, true, false)
	now := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return now }
	if c.spray != nil {
		c.spray.now = c.now
	}

	// 2 hits, then leap past the merge window so state is stale.
	_, _, _ = c.OnFinding(sprayFinding("a@example.com", "192.0.2.9", now))
	_, _, _ = c.OnFinding(sprayFinding("b@example.com", "192.0.2.9", now.Add(time.Minute)))

	// Advance well past incidentMergeWindow (15 min).
	later := now.Add(20 * time.Minute)
	c.now = func() time.Time { return later }
	if c.spray != nil {
		c.spray.now = c.now
	}

	// Three more hits -- since the prior state is stale the detector
	// resets and the threshold tracks fresh.
	_, _, _ = c.OnFinding(sprayFinding("c@example.com", "192.0.2.9", later))
	_, _, _ = c.OnFinding(sprayFinding("d@example.com", "192.0.2.9", later.Add(time.Minute)))
	_, _, _ = c.OnFinding(sprayFinding("e@example.com", "192.0.2.9", later.Add(2*time.Minute)))

	if got := c.counters.sprayOpenedTotal.Load(); got != 1 {
		t.Errorf("expected one spray after stale-window reset, got sprayOpenedTotal=%d", got)
	}
}

func TestSprayDryRunIncrementsCountersWithoutRoutingChange(t *testing.T) {
	c := newSprayCorrelator(t, false, true) // dry-run only
	now := time.Unix(1_700_000_000, 0)

	for i := 0; i < 4; i++ { // > threshold
		mb := "user" + strconv.Itoa(i) + "@example.com"
		_, _, _ = c.OnFinding(sprayFinding(mb, "192.0.2.1", now.Add(time.Duration(i)*time.Minute)))
	}
	if got := c.counters.sprayOpenedTotal.Load(); got != 0 {
		t.Errorf("dry_run must not open spray (sprayOpenedTotal=%d)", got)
	}
	if got := c.counters.sprayDryRunTotal.Load(); got < 1 {
		t.Errorf("sprayDryRunTotal must increment past threshold, got %d", got)
	}
	// Per-mailbox incidents still open under dry_run.
	mailboxIncidents := 0
	for _, inc := range c.Snapshot() {
		if inc.Kind == KindMailboxTakeover {
			mailboxIncidents++
		}
		if inc.Kind == KindCredentialSpray {
			t.Errorf("dry_run produced credential_spray incident: %+v", inc)
		}
	}
	if mailboxIncidents == 0 {
		t.Errorf("expected mailbox_takeover incidents under dry_run, got 0")
	}
}

func TestSprayDoesNotAffectNonAuthFailureChecks(t *testing.T) {
	c := newSprayCorrelator(t, true, false)
	now := time.Unix(1_700_000_000, 0)
	// Drive 5 wp_login_bruteforce findings from one IP across many TenantIDs.
	for i := 0; i < 5; i++ {
		_, _, _ = c.OnFinding(alert.Finding{
			Check:     "wp_login_bruteforce",
			Severity:  alert.High,
			TenantID:  "site" + strconv.Itoa(i),
			SourceIP:  "192.0.2.1",
			Timestamp: now.Add(time.Duration(i) * time.Minute),
			Message:   "wp brute",
		})
	}
	if got := c.counters.sprayOpenedTotal.Load(); got != 0 {
		t.Errorf("non-spray check must not open spray, got %d", got)
	}
}

func TestSpraySeverityEscalatesAtConfiguredThreshold(t *testing.T) {
	c := newSprayCorrelator(t, true, false)
	// Tighten the escalate threshold so the test does not need many hits.
	c.spray.cfg.SeverityEscalateAt = 5
	now := time.Unix(1_700_000_000, 0)

	for i := 0; i < 6; i++ { // 3 trips, then 3 more to push past escalate
		mb := "user" + strconv.Itoa(i) + "@example.com"
		_, _, _ = c.OnFinding(sprayFinding(mb, "192.0.2.1", now.Add(time.Duration(i)*time.Minute)))
	}

	var spray Incident
	for _, inc := range c.Snapshot() {
		if inc.Kind == KindCredentialSpray {
			spray = inc
			break
		}
	}
	if spray.Severity != alert.Critical {
		t.Errorf("severity = %s, want CRITICAL after escalate threshold", spray.Severity)
	}
}

func TestSprayConcurrentOnFindingNoRace(t *testing.T) {
	c := newSprayCorrelator(t, true, false)
	now := time.Unix(1_700_000_000, 0)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _, _ = c.OnFinding(sprayFinding(
				"user"+strconv.Itoa(i)+"@example.com",
				"192.0.2.1",
				now.Add(time.Duration(i)*time.Millisecond),
			))
		}(i)
	}
	wg.Wait()
	// Spray must have opened exactly once even with 100 concurrent
	// findings; the merge path covers the rest.
	if got := c.counters.sprayOpenedTotal.Load(); got != 1 {
		t.Errorf("sprayOpenedTotal = %d, want exactly 1 under concurrent load", got)
	}
}

func TestPruneStaleSprayClearsExpiredEntries(t *testing.T) {
	c := newSprayCorrelator(t, true, false)
	now := time.Unix(1_700_000_000, 0)
	_, _, _ = c.OnFinding(sprayFinding("a@example.com", "192.0.2.5", now))
	if c.SprayTrackedIPs() != 1 {
		t.Fatalf("setup: expected 1 tracked IP, got %d", c.SprayTrackedIPs())
	}
	pruned := c.PruneStaleSpray(now.Add(20 * time.Minute))
	if pruned != 1 {
		t.Errorf("PruneStaleSpray = %d, want 1", pruned)
	}
	if c.SprayTrackedIPs() != 0 {
		t.Errorf("post-prune tracked IPs = %d, want 0", c.SprayTrackedIPs())
	}
}

func TestSprayLRUEvictsOldestIPs(t *testing.T) {
	cfg := sprayTestConfig(true, false)
	cfg.MaxTrackedIPs = 3
	c := NewCorrelator(CorrelatorConfig{SpraySuppression: cfg})
	c.openThreshold = 1
	base := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return base }
	if c.spray != nil {
		c.spray.now = c.now
	}

	// Insert four IPs with monotonically increasing lastSeen so the
	// first-inserted is the oldest. The eviction path must drop it.
	for i := 0; i < 4; i++ {
		ip := "192.0.2." + strconv.Itoa(i)
		ts := base.Add(time.Duration(i) * time.Second)
		c.now = func() time.Time { return ts }
		if c.spray != nil {
			c.spray.now = c.now
		}
		_, _, _ = c.OnFinding(sprayFinding("user@example.com", ip, ts))
	}
	if got := c.SprayTrackedIPs(); got != 3 {
		t.Errorf("tracked IPs after eviction = %d, want 3 (cap)", got)
	}
}
