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

func TestSprayCanonicalizesMailboxDomainForDistinctSet(t *testing.T) {
	c := newSprayCorrelator(t, true, false)
	now := time.Unix(1_700_000_000, 0)
	ip := "192.0.2.1"

	findings := []alert.Finding{
		sprayFinding("alice@example.com", ip, now),
		sprayFinding("alice", ip, now.Add(time.Minute)),
		sprayFinding("bob@example.com", ip, now.Add(2*time.Minute)),
	}
	findings[0].Domain = "Example.COM"
	findings[1].Domain = "example.com"
	findings[2].Domain = "example.com"

	for _, f := range findings {
		if _, _, err := c.OnFinding(f); err != nil {
			t.Fatalf("OnFinding: %v", err)
		}
	}

	if got := c.counters.sprayOpenedTotal.Load(); got != 0 {
		t.Fatalf("sprayOpenedTotal = %d, want 0 when full and split forms name the same mailbox", got)
	}
	for _, inc := range c.Snapshot() {
		if inc.Kind == KindCredentialSpray {
			t.Fatalf("duplicate mailbox forms opened credential_spray incident: %+v", inc)
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

// blockCapture captures the (ip, reason) tuple from OnSprayBlock so a
// test can assert the callback fired exactly when expected.
type blockCapture struct {
	mu    sync.Mutex
	calls []struct{ IP, Reason string }
}

func (b *blockCapture) record(ip, reason string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls = append(b.calls, struct{ IP, Reason string }{ip, reason})
}

func (b *blockCapture) len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.calls)
}

func TestSprayBlockAtHighFiresOnOpen(t *testing.T) {
	cfg := sprayTestConfig(true, false)
	cfg.BlockAtSeverity = "high"
	var cap blockCapture
	c := NewCorrelator(CorrelatorConfig{
		SpraySuppression: cfg,
		OnSprayBlock:     cap.record,
	})
	c.openThreshold = 1
	now := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return now }
	if c.spray != nil {
		c.spray.now = c.now
	}

	for i := 0; i < 3; i++ { // threshold=3
		mb := "user" + strconv.Itoa(i) + "@example.com"
		_, _, _ = c.OnFinding(sprayFinding(mb, "192.0.2.10", now.Add(time.Duration(i)*time.Minute)))
	}

	if got := cap.len(); got != 1 {
		t.Fatalf("OnSprayBlock called %d times, want 1 at open", got)
	}
	if cap.calls[0].IP != "192.0.2.10" {
		t.Errorf("block IP = %q, want 192.0.2.10", cap.calls[0].IP)
	}

	// A spray incident must record the block request as an action.
	var found bool
	for _, inc := range c.Snapshot() {
		if inc.Kind != KindCredentialSpray {
			continue
		}
		for _, a := range inc.Actions {
			if a.Action == "credential_spray_block_requested" {
				found = true
			}
		}
	}
	if !found {
		t.Error("incident missing credential_spray_block_requested action")
	}
}

func TestSprayBlockCallbackRunsAfterCorrelatorUnlock(t *testing.T) {
	cfg := sprayTestConfig(true, false)
	cfg.BlockAtSeverity = "high"
	cfg.DistinctMailboxes = 1
	cfg.SeverityEscalateAt = 2
	called := make(chan struct{})
	var c *Correlator
	c = NewCorrelator(CorrelatorConfig{
		SpraySuppression: cfg,
		OnSprayBlock: func(_, _ string) {
			if got := c.OpenCount(); got != 1 {
				t.Errorf("OpenCount from block callback = %d, want 1", got)
			}
			close(called)
		},
	})
	c.openThreshold = 1
	now := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return now }

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 1; i++ {
			mb := "user" + strconv.Itoa(i) + "@example.com"
			_, _, _ = c.OnFinding(sprayFinding(mb, "192.0.2.11", now.Add(time.Duration(i)*time.Minute)))
		}
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("OnFinding deadlocked; block callback likely ran under correlator lock")
	}
	select {
	case <-called:
	default:
		t.Fatal("OnSprayBlock was not called")
	}
}

func TestSprayBlockAtCriticalSkipsOpenFiresOnEscalation(t *testing.T) {
	cfg := sprayTestConfig(true, false)
	cfg.BlockAtSeverity = "critical"
	var cap blockCapture
	c := NewCorrelator(CorrelatorConfig{
		SpraySuppression: cfg,
		OnSprayBlock:     cap.record,
	})
	c.openThreshold = 1
	base := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return base }
	if c.spray != nil {
		c.spray.now = c.now
	}

	// Open the spray incident (3 mailboxes). BlockAtSeverity=critical must
	// NOT fire here because escalation has not happened yet.
	for i := 0; i < 3; i++ {
		mb := "user" + strconv.Itoa(i) + "@example.com"
		_, _, _ = c.OnFinding(sprayFinding(mb, "192.0.2.20", base.Add(time.Duration(i)*time.Minute)))
	}
	if got := cap.len(); got != 0 {
		t.Fatalf("OnSprayBlock fired %d times before escalation; want 0", got)
	}

	// Push past SeverityEscalateAt (6) so the suppress path flips
	// severity to CRITICAL.
	for i := 3; i < 6; i++ {
		mb := "user" + strconv.Itoa(i) + "@example.com"
		_, _, _ = c.OnFinding(sprayFinding(mb, "192.0.2.20", base.Add(time.Duration(i)*time.Minute)))
	}
	if got := cap.len(); got != 1 {
		t.Fatalf("OnSprayBlock fired %d times after escalation; want 1", got)
	}

	// One more finding from the same IP must NOT re-fire (idempotent).
	_, _, _ = c.OnFinding(sprayFinding("user99@example.com", "192.0.2.20", base.Add(10*time.Minute)))
	if got := cap.len(); got != 1 {
		t.Errorf("OnSprayBlock fired %d times after second escalation event; want 1 (idempotent)", got)
	}
}

func TestSprayBlockEmptyConfigStaysDetectionOnly(t *testing.T) {
	cfg := sprayTestConfig(true, false)
	// BlockAtSeverity intentionally left empty.
	var cap blockCapture
	c := NewCorrelator(CorrelatorConfig{
		SpraySuppression: cfg,
		OnSprayBlock:     cap.record,
	})
	c.openThreshold = 1
	base := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return base }
	if c.spray != nil {
		c.spray.now = c.now
	}

	for i := 0; i < 6; i++ { // drive past both threshold and escalate
		mb := "user" + strconv.Itoa(i) + "@example.com"
		_, _, _ = c.OnFinding(sprayFinding(mb, "192.0.2.30", base.Add(time.Duration(i)*time.Minute)))
	}
	if got := cap.len(); got != 0 {
		t.Errorf("OnSprayBlock fired %d times with BlockAtSeverity unset; want 0", got)
	}
}

func TestSprayBlockUnknownSeverityIsNoop(t *testing.T) {
	cfg := sprayTestConfig(true, false)
	cfg.BlockAtSeverity = "garbage"
	var cap blockCapture
	c := NewCorrelator(CorrelatorConfig{
		SpraySuppression: cfg,
		OnSprayBlock:     cap.record,
	})
	c.openThreshold = 1
	base := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return base }
	if c.spray != nil {
		c.spray.now = c.now
	}

	for i := 0; i < 6; i++ {
		mb := "user" + strconv.Itoa(i) + "@example.com"
		_, _, _ = c.OnFinding(sprayFinding(mb, "192.0.2.40", base.Add(time.Duration(i)*time.Minute)))
	}
	if got := cap.len(); got != 0 {
		t.Errorf("OnSprayBlock fired %d times with unknown severity; want 0", got)
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

// TestRestoreRebindsOpenSprayIncident proves the daemon-restart regression
// where the in-memory spray state was lost while the open credential_spray
// incident remained in bbolt. After Restore() the detector must already
// know the IP is bound to the open incident so the next finding routes via
// suppress instead of opening a duplicate incident.
//
// Reproducer for the field scenario where the same attacker IP produced
// two open credential_spray incidents bracketing a daemon restart.
func TestRestoreRebindsOpenSprayIncident(t *testing.T) {
	c1 := newSprayCorrelator(t, true, false)
	base := time.Unix(1_700_000_000, 0)
	attackerIP := "203.0.113.7"

	// Drive enough findings on c1 to trip the spray detector and open
	// an incident.
	for i := 0; i < 3; i++ {
		mb := "user" + strconv.Itoa(i) + "@example.com"
		_, _, err := c1.OnFinding(sprayFinding(mb, attackerIP, base.Add(time.Duration(i)*time.Second)))
		if err != nil {
			t.Fatalf("OnFinding %d: %v", i, err)
		}
	}

	var sprayID string
	for _, inc := range c1.Snapshot() {
		if inc.Kind == KindCredentialSpray {
			sprayID = inc.ID
		}
	}
	if sprayID == "" {
		t.Fatal("setup failed: no credential_spray incident opened on c1")
	}
	snapshot := c1.Snapshot()

	// Simulate a daemon restart: brand new correlator, brand new spray
	// detector (perIP empty), then Restore the persisted incidents.
	c2 := newSprayCorrelator(t, true, false)
	// Advance the clock past the c1 activity but still inside the spray
	// window so the rehydration must keep the binding alive.
	postRestart := base.Add(2 * time.Minute)
	c2.now = func() time.Time { return postRestart }
	if c2.spray != nil {
		c2.spray.now = c2.now
	}
	c2.Restore(snapshot)

	// One new spray-class finding from the same attacker, different mailbox.
	_, opened, err := c2.OnFinding(sprayFinding("victim@example.com", attackerIP, postRestart))
	if err != nil {
		t.Fatalf("OnFinding after restart: %v", err)
	}
	if opened {
		t.Error("post-restart finding opened a NEW incident; expected merge into restored spray incident")
	}

	sprayCount := 0
	for _, inc := range c2.Snapshot() {
		if inc.Kind == KindCredentialSpray {
			sprayCount++
			if inc.ID != sprayID {
				t.Errorf("unexpected credential_spray incident id %q after restart (want %q)", inc.ID, sprayID)
			}
		}
	}
	if sprayCount != 1 {
		t.Errorf("credential_spray incident count after restart = %d, want 1", sprayCount)
	}

	// The detector must report the IP as still bound so subsequent
	// suppression decisions short-circuit without re-counting mailboxes.
	if got := c2.spray.IncidentForIP(attackerIP); got != sprayID {
		t.Errorf("spray.IncidentForIP(%s) = %q, want %q", attackerIP, got, sprayID)
	}
}

// TestSprayBlockFiresOnSuppressAfterCriticalArmedLater reproduces the
// second half of the bug: an operator enables block_at_severity=critical
// AFTER an open spray incident has already escalated to CRITICAL.
// Previously the firewall hand-off fired only at the moment of severity
// transition, so the existing CRITICAL incident kept ingesting findings
// without ever triggering a block. The fix re-evaluates on every
// suppressed merge; idempotency is provided by triggerSprayBlockLocked's
// existing action-presence check.
func TestSprayBlockFiresOnSuppressAfterCriticalArmedLater(t *testing.T) {
	cfg := sprayTestConfig(true, false)
	cfg.BlockAtSeverity = "critical"
	var cap blockCapture
	c := NewCorrelator(CorrelatorConfig{
		SpraySuppression: cfg,
		OnSprayBlock:     cap.record,
	})
	c.openThreshold = 1
	base := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return base }
	if c.spray != nil {
		c.spray.now = c.now
	}

	// Seed a pre-existing CRITICAL spray incident with no block action,
	// matching the field state at the moment an operator adds
	// block_at_severity to csm.yaml after the incident has already
	// escalated.
	attackerIP := "203.0.113.42"
	existing := Incident{
		ID:             "inc_preexisting01",
		Kind:           KindCredentialSpray,
		Status:         StatusOpen,
		Severity:       alert.Critical,
		CorrelationKey: &Key{RemoteIP: attackerIP},
		CreatedAt:      base.Add(-10 * time.Minute),
		UpdatedAt:      base.Add(-1 * time.Minute),
		Actions: []IncidentAction{
			{Time: base.Add(-9 * time.Minute), Action: "credential_spray_opened", Result: "ok"},
			{Time: base.Add(-5 * time.Minute), Action: "incident_severity_changed", Result: "ok"},
		},
	}
	c.Restore([]Incident{existing})

	// One more spray finding arrives after the config change. Should
	// fire the block exactly once and stamp the audit action on the
	// existing incident, not open a new one.
	_, opened, err := c.OnFinding(sprayFinding("victim@example.com", attackerIP, base))
	if err != nil {
		t.Fatalf("OnFinding: %v", err)
	}
	if opened {
		t.Fatal("new incident opened; expected merge into preexisting CRITICAL spray")
	}
	if got := cap.len(); got != 1 {
		t.Fatalf("OnSprayBlock called %d times, want 1 after first post-arm finding", got)
	}
	if cap.calls[0].IP != attackerIP {
		t.Errorf("block IP = %q, want %q", cap.calls[0].IP, attackerIP)
	}

	// A second finding must not re-trigger the block: the existing
	// credential_spray_block_requested action gates re-entry.
	_, _, _ = c.OnFinding(sprayFinding("victim2@example.com", attackerIP, base.Add(time.Second)))
	if got := cap.len(); got != 1 {
		t.Errorf("OnSprayBlock fired %d times after second post-arm finding; want 1 (idempotent)", got)
	}
}

// Closing a spray incident must release its per-IP binding so a later
// finding from the same IP cannot reopen the resolved incident through
// the suppress merge path.
func TestSpraySetStatusUnbindsClosedIncident(t *testing.T) {
	c := newSprayCorrelator(t, true, false)
	now := time.Unix(1_700_000_000, 0)
	attackerIP := "192.0.2.55"

	// Trip the threshold to open a spray incident.
	for i := 0; i < 3; i++ {
		mb := "user" + strconv.Itoa(i) + "@example.com"
		_, _, _ = c.OnFinding(sprayFinding(mb, attackerIP, now.Add(time.Duration(i)*time.Second)))
	}
	var sprayID string
	for _, inc := range c.Snapshot() {
		if inc.Kind == KindCredentialSpray {
			sprayID = inc.ID
		}
	}
	if sprayID == "" {
		t.Fatal("setup: no spray incident opened")
	}

	// Operator resolves the incident.
	if err := c.SetStatus(sprayID, StatusResolved, "manual"); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}

	// New spray-class finding from the same IP, inside the window, after
	// resolution. The detector must NOT report the closed incident as
	// still bound; the spray pipeline must treat this as the start of a
	// fresh attack rather than reopening the closed one.
	if bound := c.spray.IncidentForIP(attackerIP); bound == sprayID {
		t.Fatalf("spray binding still points at resolved incident %q", sprayID)
	}

	// And the finding itself must not mutate the resolved incident.
	preEvents := 0
	preSev := alert.Severity(0)
	preSprayCount := 0
	for _, inc := range c.Snapshot() {
		if inc.Kind == KindCredentialSpray {
			preSprayCount++
		}
		if inc.ID == sprayID {
			preEvents = len(inc.Timeline)
			preSev = inc.Severity
		}
	}
	_, _, _ = c.OnFinding(sprayFinding("post@example.com", attackerIP, now.Add(4*time.Second)))
	for _, inc := range c.Snapshot() {
		if inc.ID == sprayID {
			if inc.Status != StatusResolved {
				t.Errorf("incident status flipped to %q after post-close finding", inc.Status)
			}
			if len(inc.Timeline) != preEvents {
				t.Errorf("resolved incident timeline grew from %d to %d", preEvents, len(inc.Timeline))
			}
			if inc.Severity > preSev {
				t.Errorf("resolved incident severity escalated %v -> %v", preSev, inc.Severity)
			}
		}
	}
	postSprayCount := 0
	for _, inc := range c.Snapshot() {
		if inc.Kind == KindCredentialSpray {
			postSprayCount++
		}
	}
	if postSprayCount != preSprayCount {
		t.Errorf("post-close single finding opened %d spray incidents, want %d", postSprayCount, preSprayCount)
	}
}

// PruneStale must skip entries that still carry an incident binding.
func TestSprayPruneStaleKeepsBoundEntries(t *testing.T) {
	c := newSprayCorrelator(t, true, false)
	now := time.Unix(1_700_000_000, 0)
	attackerIP := "192.0.2.77"

	for i := 0; i < 3; i++ {
		mb := "user" + strconv.Itoa(i) + "@example.com"
		_, _, _ = c.OnFinding(sprayFinding(mb, attackerIP, now.Add(time.Duration(i)*time.Second)))
	}
	var sprayID string
	for _, inc := range c.Snapshot() {
		if inc.Kind == KindCredentialSpray {
			sprayID = inc.ID
		}
	}
	if sprayID == "" {
		t.Fatal("setup: no spray incident opened")
	}

	// Advance past the spray window; binding remains because incident is open.
	far := now.Add(48 * time.Hour)
	if pruned := c.spray.PruneStale(far); pruned != 0 {
		t.Errorf("PruneStale evicted %d entries; bound entry must survive", pruned)
	}
	if got := c.spray.IncidentForIP(attackerIP); got != sprayID {
		t.Errorf("binding lost after PruneStale: got %q, want %q", got, sprayID)
	}
}

func TestSprayDecideKeepsBoundEntryAfterWindowUntilClosed(t *testing.T) {
	c := newSprayCorrelator(t, true, false)
	now := time.Unix(1_700_000_000, 0)
	attackerIP := "192.0.2.78"

	for i := 0; i < 3; i++ {
		mb := "user" + strconv.Itoa(i) + "@example.com"
		_, _, _ = c.OnFinding(sprayFinding(mb, attackerIP, now.Add(time.Duration(i)*time.Second)))
	}
	var sprayID string
	for _, inc := range c.Snapshot() {
		if inc.Kind == KindCredentialSpray {
			sprayID = inc.ID
		}
	}
	if sprayID == "" {
		t.Fatal("setup: no spray incident opened")
	}

	later := now.Add(incidentMergeWindow + time.Minute)
	c.now = func() time.Time { return later }
	if c.spray != nil {
		c.spray.now = c.now
	}

	id, opened, err := c.OnFinding(sprayFinding("late@example.com", attackerIP, later))
	if err != nil {
		t.Fatalf("OnFinding after window: %v", err)
	}
	if opened || id != sprayID {
		t.Fatalf("post-window finding id=%q opened=%v, want suppress merge into %q", id, opened, sprayID)
	}

	sprayCount := 0
	for _, inc := range c.Snapshot() {
		if inc.Kind == KindCredentialSpray {
			sprayCount++
		}
	}
	if sprayCount != 1 {
		t.Fatalf("credential_spray count = %d, want 1 after post-window merge", sprayCount)
	}
}

func TestSprayUnbindIncidentClearsTrackingState(t *testing.T) {
	c := newSprayCorrelator(t, true, false)
	now := time.Unix(1_700_000_000, 0)
	attackerIP := "192.0.2.88"

	for i := 0; i < 3; i++ {
		mb := "user" + strconv.Itoa(i) + "@example.com"
		_, _, _ = c.OnFinding(sprayFinding(mb, attackerIP, now.Add(time.Duration(i)*time.Second)))
	}
	var sprayID string
	for _, inc := range c.Snapshot() {
		if inc.Kind == KindCredentialSpray {
			sprayID = inc.ID
		}
	}
	if sprayID == "" {
		t.Fatal("setup: no spray incident opened")
	}

	c.spray.UnbindIncident(sprayID)

	if got := c.spray.IncidentForIP(attackerIP); got != "" {
		t.Errorf("IncidentForIP after UnbindIncident = %q, want empty", got)
	}
	if got := c.spray.TrackedIPs(); got != 0 {
		t.Errorf("TrackedIPs after UnbindIncident = %d, want 0", got)
	}
}
