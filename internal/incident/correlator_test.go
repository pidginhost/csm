package incident

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/processctx"
)

func newTestCorrelator() *Correlator {
	c := NewCorrelator(CorrelatorConfig{})
	c.now = func() time.Time { return time.Unix(1_700_000_000, 0) }
	return c
}

func TestCorrelatorOnFindingCreatesIncidentForAttributableFinding(t *testing.T) {
	c := newTestCorrelator()
	f := alert.Finding{
		Check:     "wp_login_bruteforce",
		Message:   "burst",
		Severity:  alert.High,
		TenantID:  "alice",
		Timestamp: time.Unix(1_700_000_000, 0),
	}
	id, created, err := c.OnFinding(f)
	if err != nil {
		t.Fatalf("OnFinding: %v", err)
	}
	if !created {
		t.Errorf("expected first call to create an incident")
	}
	if id == "" {
		t.Errorf("expected non-empty incident id")
	}
}

func TestCorrelatorOnFindingReturnsZeroForUnattributable(t *testing.T) {
	c := newTestCorrelator()
	f := alert.Finding{Check: "system_load", Message: "system load high", Timestamp: time.Unix(1_700_000_000, 0)}
	id, created, err := c.OnFinding(f)
	if err != nil {
		t.Fatalf("OnFinding: %v", err)
	}
	if created {
		t.Errorf("unattributable finding must not create incident")
	}
	if id != "" {
		t.Errorf("expected empty id, got %q", id)
	}
}

func TestCorrelatorMergesSameAccountInWindow(t *testing.T) {
	c := newTestCorrelator()
	f1 := alert.Finding{Check: "wp_login_bruteforce", Message: "1", Severity: alert.High, TenantID: "alice", Timestamp: time.Unix(1_700_000_000, 0)}
	id1, created1, _ := c.OnFinding(f1)
	if !created1 {
		t.Fatal("setup")
	}

	c.now = func() time.Time { return time.Unix(1_700_000_000+5*60, 0) }
	f2 := alert.Finding{Check: "outbound_connection", Message: "2", Severity: alert.High, TenantID: "alice", Timestamp: time.Unix(1_700_000_000+5*60, 0)}
	id2, created2, _ := c.OnFinding(f2)

	if created2 {
		t.Errorf("second finding within window must merge, not create")
	}
	if id1 != id2 {
		t.Errorf("ids must match: %q vs %q", id1, id2)
	}
}

func TestCorrelatorDoesNotMergeAcrossAccounts(t *testing.T) {
	c := newTestCorrelator()
	f1 := alert.Finding{Check: "x", Severity: alert.High, TenantID: "alice", Timestamp: time.Unix(1_700_000_000, 0)}
	id1, _, _ := c.OnFinding(f1)

	f2 := alert.Finding{Check: "x", Severity: alert.High, TenantID: "bob", Timestamp: time.Unix(1_700_000_000, 0)}
	id2, created2, _ := c.OnFinding(f2)

	if !created2 {
		t.Errorf("different account must create new incident")
	}
	if id1 == id2 {
		t.Errorf("ids must differ across accounts")
	}
}

func TestCorrelatorDoesNotMergeOutsideWindow(t *testing.T) {
	c := newTestCorrelator()
	f1 := alert.Finding{Check: "x", Severity: alert.High, TenantID: "alice", Timestamp: time.Unix(1_700_000_000, 0)}
	_, _, _ = c.OnFinding(f1)

	c.now = func() time.Time { return time.Unix(1_700_000_000+16*60, 0) }
	f2 := alert.Finding{Check: "y", Severity: alert.High, TenantID: "alice", Timestamp: time.Unix(1_700_000_000+16*60, 0)}
	_, created2, _ := c.OnFinding(f2)

	if !created2 {
		t.Errorf("finding 16 min later must create new incident (window is 15 min)")
	}
}

func TestCorrelatorAppendsTimeline(t *testing.T) {
	c := newTestCorrelator()
	f := alert.Finding{Check: "wp_login_bruteforce", Message: "first", Severity: alert.High, TenantID: "alice", Timestamp: time.Unix(1_700_000_000, 0)}
	id, _, _ := c.OnFinding(f)

	inc, ok := c.Get(id)
	if !ok {
		t.Fatal("incident not found by id")
	}
	if len(inc.Timeline) != 1 {
		t.Fatalf("Timeline len: want 1, got %d", len(inc.Timeline))
	}
	if inc.Timeline[0].Check != "wp_login_bruteforce" {
		t.Errorf("Timeline[0].Check: %q", inc.Timeline[0].Check)
	}
}

func TestCorrelatorProcessOnlyFindingsDoNotCollide(t *testing.T) {
	c := newTestCorrelator()
	f1 := alert.Finding{
		Check:     "outbound_connection",
		Severity:  alert.High,
		Process:   &processctx.ProcessContext{PID: 4242, UID: 1001},
		Timestamp: time.Unix(1_700_000_000, 0),
	}
	id1, created1, _ := c.OnFinding(f1)
	if !created1 {
		t.Fatal("setup")
	}

	f2 := alert.Finding{
		Check:     "outbound_connection",
		Severity:  alert.High,
		Process:   &processctx.ProcessContext{PID: 5555, UID: 1002},
		Timestamp: time.Unix(1_700_000_000, 0),
	}
	id2, created2, _ := c.OnFinding(f2)
	if !created2 {
		t.Errorf("distinct process must produce a new incident, not merge")
	}
	if id1 == id2 {
		t.Errorf("process-only ids must differ")
	}
}

func TestCorrelatorMergesSameUIDAcrossRotatingProcessPID(t *testing.T) {
	c := newTestCorrelator()
	f1 := alert.Finding{
		Check:     "php_suspicious_execution",
		Severity:  alert.Critical,
		Process:   &processctx.ProcessContext{PID: 4242, UID: 1001},
		Timestamp: time.Unix(1_700_000_000, 0),
	}
	id1, created1, _ := c.OnFinding(f1)
	if !created1 {
		t.Fatal("setup")
	}

	f2 := alert.Finding{
		Check:     "php_suspicious_execution",
		Severity:  alert.Critical,
		Process:   &processctx.ProcessContext{PID: 5555, UID: 1001},
		Timestamp: time.Unix(1_700_000_000+60, 0),
	}
	id2, created2, _ := c.OnFinding(f2)
	if created2 {
		t.Errorf("same UID with a new PID must merge, not create")
	}
	if id1 != id2 {
		t.Errorf("ids must match for same UID across PIDs: %q vs %q", id1, id2)
	}
}

func TestCorrelatorRemoteIPOnlyFindingsDoNotCollide(t *testing.T) {
	c := newTestCorrelator()
	f1 := alert.Finding{
		Check:     "ssh_bruteforce",
		Severity:  alert.High,
		SourceIP:  "203.0.113.10",
		Timestamp: time.Unix(1_700_000_000, 0),
	}
	id1, _, _ := c.OnFinding(f1)
	f2 := alert.Finding{
		Check:     "ssh_bruteforce",
		Severity:  alert.High,
		SourceIP:  "203.0.113.20",
		Timestamp: time.Unix(1_700_000_000, 0),
	}
	id2, created2, _ := c.OnFinding(f2)
	if !created2 || id1 == id2 {
		t.Errorf("distinct remote IPs must not merge; id1=%s id2=%s created2=%v", id1, id2, created2)
	}
}

func TestCorrelatorSkipsWhitelistedRemoteIPOnlyFinding(t *testing.T) {
	c := NewCorrelator(CorrelatorConfig{
		IsWhitelisted: func(ip string) bool {
			return ip == "203.0.113.10"
		},
	})
	c.now = func() time.Time { return time.Unix(1_700_000_000, 0) }

	id, created, err := c.OnFinding(alert.Finding{
		Check:     "ssh_bruteforce",
		Severity:  alert.High,
		SourceIP:  "203.0.113.10",
		Timestamp: time.Unix(1_700_000_000, 0),
	})
	if err != nil {
		t.Fatalf("OnFinding: %v", err)
	}
	if created {
		t.Fatal("whitelisted remote-IP-only finding created an incident")
	}
	if id != "" {
		t.Fatalf("id = %q, want empty", id)
	}
	if got := c.OpenCount(); got != 0 {
		t.Fatalf("OpenCount = %d, want 0", got)
	}
	if got := c.PendingCount(); got != 0 {
		t.Fatalf("PendingCount = %d, want 0", got)
	}
}

func TestCorrelatorSkipsWhitelistedSourceIPWithStableActor(t *testing.T) {
	c := NewCorrelator(CorrelatorConfig{
		IsWhitelisted: func(ip string) bool {
			return ip == "203.0.113.10"
		},
	})
	c.now = func() time.Time { return time.Unix(1_700_000_000, 0) }

	id, created, err := c.OnFinding(alert.Finding{
		Check:     "wp_login_bruteforce",
		Severity:  alert.High,
		TenantID:  "alice",
		SourceIP:  "203.0.113.10",
		Timestamp: time.Unix(1_700_000_000, 0),
	})
	if err != nil {
		t.Fatalf("OnFinding: %v", err)
	}
	if created {
		t.Fatal("stable-actor finding with whitelisted SourceIP created an incident")
	}
	if id != "" {
		t.Fatalf("id = %q, want empty", id)
	}
	if got := c.OpenCount(); got != 0 {
		t.Fatalf("OpenCount = %d, want 0", got)
	}
}

func TestCorrelatorWhitelistedSourceIPDoesNotSuppressHostIntegrity(t *testing.T) {
	c := NewCorrelator(CorrelatorConfig{
		IsWhitelisted: func(ip string) bool {
			return ip == "203.0.113.10"
		},
	})
	c.now = func() time.Time { return time.Unix(1_700_000_000, 0) }

	id, created, err := c.OnFinding(alert.Finding{
		Check:     "suid_binary",
		Severity:  alert.Critical,
		SourceIP:  "203.0.113.10",
		Timestamp: time.Unix(1_700_000_000, 0),
	})
	if err != nil {
		t.Fatalf("OnFinding: %v", err)
	}
	if !created {
		t.Fatal("host-integrity finding with whitelisted SourceIP did not create an incident")
	}
	inc, ok := c.Get(id)
	if !ok {
		t.Fatal("created incident not found")
	}
	if inc.CorrelationKey == nil || inc.CorrelationKey.Host != "host" {
		t.Fatalf("CorrelationKey = %+v, want host key", inc.CorrelationKey)
	}
}

func TestCorrelatorMergesSameMailboxAcrossSourceIPs(t *testing.T) {
	c := newTestCorrelator()
	f1 := alert.Finding{
		Check:     "email_auth_failure_realtime",
		Severity:  alert.High,
		Mailbox:   "alice@example.com",
		Domain:    "example.com",
		SourceIP:  "203.0.113.10",
		Timestamp: time.Unix(1_700_000_000, 0),
	}
	id1, created1, _ := c.OnFinding(f1)
	if !created1 {
		t.Fatal("setup")
	}

	f2 := alert.Finding{
		Check:     "email_auth_failure_realtime",
		Severity:  alert.High,
		Mailbox:   "alice@example.com",
		Domain:    "example.com",
		SourceIP:  "203.0.113.20",
		Timestamp: time.Unix(1_700_000_000+60, 0),
	}
	id2, created2, _ := c.OnFinding(f2)
	if created2 || id1 != id2 {
		t.Errorf("same mailbox must merge across source IPs; id1=%s id2=%s created2=%v", id1, id2, created2)
	}
}

func TestCorrelatorPreservesMailboxDomainMetadata(t *testing.T) {
	c := newTestCorrelator()
	id, created, err := c.OnFinding(alert.Finding{
		Check:     "email_auth_failure_realtime",
		Severity:  alert.High,
		Mailbox:   "alice@example.com",
		Domain:    "example.com",
		SourceIP:  "203.0.113.10",
		Timestamp: time.Unix(1_700_000_000, 0),
	})
	if err != nil {
		t.Fatalf("OnFinding: %v", err)
	}
	if !created {
		t.Fatal("setup did not create incident")
	}

	inc, ok := c.Get(id)
	if !ok {
		t.Fatal("incident not found")
	}
	if inc.Mailbox != "alice@example.com" {
		t.Errorf("Mailbox = %q, want alice@example.com", inc.Mailbox)
	}
	if inc.Domain != "example.com" {
		t.Errorf("Domain = %q, want example.com", inc.Domain)
	}
	if inc.CorrelationKey == nil {
		t.Fatal("CorrelationKey missing")
	}
	if inc.CorrelationKey.Mailbox != "alice@example.com" || inc.CorrelationKey.Domain != "" {
		t.Errorf("CorrelationKey = %+v, want mailbox-only canonical key", inc.CorrelationKey)
	}
}

func TestCorrelatorRestoreCanonicalizesLegacyMailboxDomainKeys(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	cases := []struct {
		name  string
		prior Incident
	}{
		{
			name: "legacy full mailbox plus domain key",
			prior: Incident{
				ID:             "inc_legacy_full",
				Kind:           KindMailboxTakeover,
				Status:         StatusOpen,
				Severity:       alert.High,
				Domain:         "example.com",
				Mailbox:        "alice@example.com",
				CorrelationKey: &Key{Domain: "example.com", Mailbox: "alice@example.com"},
				CreatedAt:      base,
				UpdatedAt:      base,
			},
		},
		{
			name: "legacy split mailbox key",
			prior: Incident{
				ID:             "inc_legacy_split",
				Kind:           KindMailboxTakeover,
				Status:         StatusOpen,
				Severity:       alert.High,
				Domain:         "example.com",
				Mailbox:        "alice",
				CorrelationKey: &Key{Domain: "example.com", Mailbox: "alice"},
				CreatedAt:      base,
				UpdatedAt:      base,
			},
		},
		{
			name: "legacy top-level fields without correlation key",
			prior: Incident{
				ID:        "inc_legacy_fields",
				Kind:      KindMailboxTakeover,
				Status:    StatusOpen,
				Severity:  alert.High,
				Domain:    "example.com",
				Mailbox:   "alice",
				CreatedAt: base,
				UpdatedAt: base,
			},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestCorrelator()
			c.Restore([]Incident{tt.prior})
			c.now = func() time.Time { return base.Add(5 * time.Minute) }

			id, created, err := c.OnFinding(alert.Finding{
				Check:     "email_auth_failure_realtime",
				Severity:  alert.High,
				Mailbox:   "alice@example.com",
				Domain:    "example.com",
				Timestamp: base.Add(5 * time.Minute),
			})
			if err != nil {
				t.Fatalf("OnFinding: %v", err)
			}
			if created {
				t.Fatal("restored legacy mailbox key was not rebound")
			}
			if id != tt.prior.ID {
				t.Fatalf("id after restore = %q, want %q", id, tt.prior.ID)
			}
		})
	}
}

func TestCorrelatorMergesCPUserAcrossSourceIPs(t *testing.T) {
	c := newTestCorrelator()
	f1 := alert.Finding{
		Check:     "email_php_relay_abuse",
		Severity:  alert.Critical,
		CPUser:    "alice",
		SourceIP:  "203.0.113.10",
		Timestamp: time.Unix(1_700_000_000, 0),
	}
	id1, created1, _ := c.OnFinding(f1)
	if !created1 {
		t.Fatal("setup")
	}

	f2 := alert.Finding{
		Check:     "email_php_relay_abuse",
		Severity:  alert.Critical,
		CPUser:    "alice",
		SourceIP:  "203.0.113.20",
		Timestamp: time.Unix(1_700_000_000+60, 0),
	}
	id2, created2, _ := c.OnFinding(f2)
	if created2 || id1 != id2 {
		t.Errorf("same CPUser must merge across source IPs; id1=%s id2=%s created2=%v", id1, id2, created2)
	}
}

func TestKeyStringDoesNotCollideOnDelimiters(t *testing.T) {
	a := Key{Account: "a|b", Mailbox: "c", Domain: "d", UID: 1, PID: 2, RemoteIP: "203.0.113.10"}
	b := Key{Account: "a", Mailbox: "b|c", Domain: "d", UID: 1, PID: 2, RemoteIP: "203.0.113.10"}
	if keyString(a) == keyString(b) {
		t.Fatal("keyString collided when field values contained separators")
	}
	if keyString(Key{Host: "host"}) == keyString(Key{Account: "host"}) {
		t.Fatal("keyString collided between host and account keys")
	}
}

func TestCorrelatorPersistFiresExactlyOncePerCreateAndMerge(t *testing.T) {
	var calls int
	c := NewCorrelator(CorrelatorConfig{
		Persist: func(_ Incident) { calls++ },
	})
	c.now = func() time.Time { return time.Unix(1_700_000_000, 0) }

	_, _, _ = c.OnFinding(alert.Finding{Check: "x", Severity: alert.High, TenantID: "alice", Timestamp: time.Unix(1_700_000_000, 0)})
	if calls != 1 {
		t.Errorf("after create: want 1 Persist call, got %d", calls)
	}

	_, _, _ = c.OnFinding(alert.Finding{Check: "y", Severity: alert.High, TenantID: "alice", Timestamp: time.Unix(1_700_000_000, 0)})
	if calls != 2 {
		t.Errorf("after merge: want 2 Persist calls total, got %d", calls)
	}
}

func TestCorrelatorIncidentSeverityEscalates(t *testing.T) {
	c := newTestCorrelator()
	f1 := alert.Finding{Check: "wp_login_bruteforce", Severity: alert.Warning, TenantID: "alice", Timestamp: time.Unix(1_700_000_000, 0)}
	id, _, _ := c.OnFinding(f1)
	f2 := alert.Finding{Check: "outbound_connection", Severity: alert.Critical, TenantID: "alice", Timestamp: time.Unix(1_700_000_000+30, 0)}
	_, _, _ = c.OnFinding(f2)

	inc, _ := c.Get(id)
	if inc.Severity != alert.Critical {
		t.Errorf("Incident severity: want Critical, got %v", inc.Severity)
	}
}

func TestCorrelatorEscalationAppendsAction(t *testing.T) {
	c := newTestCorrelator()
	f1 := alert.Finding{Check: "x", Severity: alert.Warning, TenantID: "alice", Timestamp: time.Unix(1_700_000_000, 0)}
	id, _, _ := c.OnFinding(f1)
	f2 := alert.Finding{Check: "y", Severity: alert.High, TenantID: "alice", Timestamp: time.Unix(1_700_000_000+30, 0)}
	_, _, _ = c.OnFinding(f2)

	inc, _ := c.Get(id)
	if len(inc.Actions) != 1 {
		t.Fatalf("Actions len: want 1 escalation action, got %d", len(inc.Actions))
	}
	if inc.Actions[0].Action != "incident_severity_changed" {
		t.Errorf("Action: %q", inc.Actions[0].Action)
	}
}

func TestCorrelatorDoesNotDowngradeSeverity(t *testing.T) {
	c := newTestCorrelator()
	f1 := alert.Finding{Check: "x", Severity: alert.Critical, TenantID: "alice", Timestamp: time.Unix(1_700_000_000, 0)}
	id, _, _ := c.OnFinding(f1)
	f2 := alert.Finding{Check: "y", Severity: alert.Warning, TenantID: "alice", Timestamp: time.Unix(1_700_000_000+30, 0)}
	_, _, _ = c.OnFinding(f2)

	inc, _ := c.Get(id)
	if inc.Severity != alert.Critical {
		t.Errorf("Severity must not downgrade: got %v", inc.Severity)
	}
	if len(inc.Actions) != 0 {
		t.Errorf("No-downgrade must not append action; got %d", len(inc.Actions))
	}
}

func TestCorrelatorPersistRunsOutsideLock(t *testing.T) {
	// A Persist callback that re-enters Correlator must not deadlock.
	c := NewCorrelator(CorrelatorConfig{})
	c.now = func() time.Time { return time.Unix(1_700_000_000, 0) }

	// Install Persist after construction so we have the *Correlator.
	c.cfg.Persist = func(inc Incident) {
		// Re-enter; if mu were held this would deadlock the test.
		_, _ = c.Get(inc.ID)
	}

	done := make(chan struct{})
	go func() {
		_, _, _ = c.OnFinding(alert.Finding{Check: "x", Severity: alert.High, TenantID: "alice", Timestamp: time.Unix(1_700_000_000, 0)})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("OnFinding deadlocked under reentrant Persist")
	}
}

func TestCorrelatorPersistReentrantReadDoesNotDeadlockBehindQueuedWriter(t *testing.T) {
	c := NewCorrelator(CorrelatorConfig{})
	base := time.Unix(1_700_000_000, 0)
	var nowCalls atomic.Int32
	secondHoldingMu := make(chan struct{})
	releaseSecond := make(chan struct{})
	c.now = func() time.Time {
		n := nowCalls.Add(1)
		if n == 2 {
			close(secondHoldingMu)
			<-releaseSecond
		}
		return base.Add(time.Duration(n) * time.Second)
	}

	firstPersist := make(chan struct{})
	allowFirstRead := make(chan struct{})
	var persistCalls atomic.Int32
	c.cfg.Persist = func(inc Incident) {
		if persistCalls.Add(1) != 1 {
			return
		}
		close(firstPersist)
		<-allowFirstRead
		if _, ok := c.Get(inc.ID); !ok {
			t.Errorf("Persist re-entry could not read incident %q", inc.ID)
		}
	}

	firstDone := make(chan struct{})
	go func() {
		_, _, _ = c.OnFinding(alert.Finding{Check: "first", Severity: alert.High, TenantID: "alice", Timestamp: base})
		close(firstDone)
	}()
	waitForTestSignal(t, firstPersist, "first Persist did not start")

	secondDone := make(chan struct{})
	go func() {
		_, _, _ = c.OnFinding(alert.Finding{Check: "second", Severity: alert.High, TenantID: "alice", Timestamp: base.Add(time.Second)})
		close(secondDone)
	}()
	waitForTestSignal(t, secondHoldingMu, "second finding did not enter correlator")

	close(releaseSecond)
	close(allowFirstRead)
	waitForTestSignal(t, firstDone, "first finding deadlocked in Persist")
	waitForTestSignal(t, secondDone, "second finding deadlocked behind Persist")
}

func TestCorrelatorDeferredStatusPersistenceWaitsForEarlierWrites(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(*testing.T, *Correlator)
	}{
		{
			name: "bulk status",
			run: func(t *testing.T, c *Correlator) {
				_, err := c.BulkSetStatus(BulkStatusFilter{
					FromStatuses: []Status{StatusOpen},
					To:           StatusResolved,
					OlderThan:    time.Second,
					Limit:        1,
					Now:          time.Unix(1_700_000_060, 0),
					Details:      "test close",
				})
				if err != nil {
					t.Errorf("BulkSetStatus returned error: %v", err)
				}
			},
		},
		{
			name: "stale close",
			run: func(t *testing.T, c *Correlator) {
				c.CloseStale(
					time.Unix(1_700_000_060, 0),
					map[Kind]time.Duration{KindWebAccountCompromise: time.Second},
					false,
				)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := NewCorrelator(CorrelatorConfig{})
			c.now = func() time.Time { return time.Unix(1_700_000_000, 0) }

			firstPersist := make(chan struct{})
			releaseFirst := make(chan struct{})
			laterPersist := make(chan struct{}, 1)
			var calls atomic.Int32
			c.cfg.Persist = func(_ Incident) {
				if calls.Add(1) == 1 {
					close(firstPersist)
					<-releaseFirst
					return
				}
				select {
				case laterPersist <- struct{}{}:
				default:
				}
			}

			createDone := make(chan struct{})
			go func() {
				_, _, _ = c.OnFinding(alert.Finding{
					Check:     "x",
					Severity:  alert.High,
					TenantID:  "alice",
					Timestamp: time.Unix(1_700_000_000, 0),
				})
				close(createDone)
			}()
			waitForTestSignal(t, firstPersist, "initial Persist did not start")

			opDone := make(chan struct{})
			go func() {
				tc.run(t, c)
				close(opDone)
			}()

			waitForTestCondition(t, func() bool {
				snap := c.Snapshot()
				return len(snap) == 1 && snap[0].Status == StatusResolved
			}, "status operation did not update incident")

			select {
			case <-opDone:
				close(releaseFirst)
				t.Fatal("status operation returned before the earlier Persist completed")
			case <-laterPersist:
				close(releaseFirst)
				t.Fatal("later Persist ran before the earlier Persist completed")
			case <-time.After(50 * time.Millisecond):
			}

			close(releaseFirst)
			waitForTestSignal(t, createDone, "initial finding did not finish")
			waitForTestSignal(t, opDone, "status operation did not finish")
			waitForTestSignal(t, laterPersist, "status operation did not persist")
		})
	}
}

func waitForTestCondition(t *testing.T, ok func() bool, message string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal(message)
}

func waitForTestSignal(t *testing.T, ch <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal(message)
	}
}

func TestCorrelatorPersistReceivesDeepCopy(t *testing.T) {
	c := NewCorrelator(CorrelatorConfig{})
	c.now = func() time.Time { return time.Unix(1_700_000_000, 0) }
	c.cfg.Persist = func(inc Incident) {
		inc.Findings[0] = "mutated-finding"
		inc.Timeline[0].Message = "mutated-message"
		if inc.CorrelationKey != nil {
			inc.CorrelationKey.Account = "mallory"
		}
	}

	id, _, _ := c.OnFinding(alert.Finding{
		Check:     "x",
		Message:   "original-message",
		Severity:  alert.High,
		TenantID:  "alice",
		Timestamp: time.Unix(1_700_000_000, 0),
	})

	inc, ok := c.Get(id)
	if !ok {
		t.Fatal("incident not found")
	}
	if inc.Findings[0] == "mutated-finding" {
		t.Error("Persist mutation leaked into internal Findings")
	}
	if inc.Timeline[0].Message != "original-message" {
		t.Errorf("Timeline[0].Message = %q", inc.Timeline[0].Message)
	}
	if inc.CorrelationKey == nil || inc.CorrelationKey.Account != "alice" {
		t.Fatalf("CorrelationKey.Account = %#v", inc.CorrelationKey)
	}
}

func TestCorrelatorSnapshotsAreDeepCopies(t *testing.T) {
	c := newTestCorrelator()
	id, _, _ := c.OnFinding(alert.Finding{
		Check:     "x",
		Message:   "first",
		Severity:  alert.Warning,
		TenantID:  "alice",
		Timestamp: time.Unix(1_700_000_000, 0),
	})
	_, _, _ = c.OnFinding(alert.Finding{
		Check:     "y",
		Message:   "second",
		Severity:  alert.Critical,
		TenantID:  "alice",
		Timestamp: time.Unix(1_700_000_030, 0),
	})

	snap := c.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("Snapshot len: want 1, got %d", len(snap))
	}
	snap[0].Findings[0] = "snapshot-mutated"
	snap[0].Timeline[0].Message = "snapshot-mutated"
	snap[0].Actions[0].Details = "snapshot-mutated"
	snap[0].CorrelationKey.Account = "mallory"

	got, ok := c.Get(id)
	if !ok {
		t.Fatal("incident not found")
	}
	got.Findings[0] = "get-mutated"
	got.Timeline[0].Message = "get-mutated"
	got.Actions[0].Details = "get-mutated"
	got.CorrelationKey.Account = "eve"

	again, ok := c.Get(id)
	if !ok {
		t.Fatal("incident not found on second get")
	}
	if again.Findings[0] == "snapshot-mutated" || again.Findings[0] == "get-mutated" {
		t.Errorf("Findings mutation leaked: %q", again.Findings[0])
	}
	if again.Timeline[0].Message != "first" {
		t.Errorf("Timeline[0].Message = %q", again.Timeline[0].Message)
	}
	if again.Actions[0].Details != "WARNING -> CRITICAL" {
		t.Errorf("Actions[0].Details = %q", again.Actions[0].Details)
	}
	if again.CorrelationKey == nil || again.CorrelationKey.Account != "alice" {
		t.Fatalf("CorrelationKey.Account = %#v", again.CorrelationKey)
	}
}

func TestCorrelatorRestoreRehydratesFromList(t *testing.T) {
	c := newTestCorrelator()
	prior := Incident{
		ID: "inc_resumed", Kind: KindWebAccountCompromise, Status: StatusOpen,
		Severity: alert.High, Account: "alice",
		CreatedAt: time.Unix(1_700_000_000, 0), UpdatedAt: time.Unix(1_700_000_000, 0),
	}
	c.Restore([]Incident{prior})

	c.now = func() time.Time { return time.Unix(1_700_000_000+5*60, 0) }
	id, created, _ := c.OnFinding(alert.Finding{
		Check: "x", Severity: alert.High, TenantID: "alice",
		Timestamp: time.Unix(1_700_000_000+5*60, 0),
	})
	if created {
		t.Errorf("post-restart finding for same account in window must merge, not create")
	}
	if id != "inc_resumed" {
		t.Errorf("expected merge into restored incident; got %q", id)
	}
}

func TestCorrelatorRestoreRehydratesFullCorrelationKey(t *testing.T) {
	cases := []struct {
		name   string
		first  alert.Finding
		second alert.Finding
	}{
		{
			name: "process",
			first: alert.Finding{
				Check:     "outbound_connection",
				Severity:  alert.High,
				Process:   &processctx.ProcessContext{PID: 4242, UID: 1001},
				Timestamp: time.Unix(1_700_000_000, 0),
			},
			second: alert.Finding{
				Check:     "suspicious_process",
				Severity:  alert.High,
				Process:   &processctx.ProcessContext{PID: 4242, UID: 1001},
				Timestamp: time.Unix(1_700_000_300, 0),
			},
		},
		{
			name: "remote_ip",
			first: alert.Finding{
				Check:     "ssh_bruteforce",
				Severity:  alert.High,
				SourceIP:  "203.0.113.10",
				Timestamp: time.Unix(1_700_000_000, 0),
			},
			second: alert.Finding{
				Check:     "smtp_probe_abuse",
				Severity:  alert.High,
				SourceIP:  "203.0.113.10",
				Timestamp: time.Unix(1_700_000_300, 0),
			},
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			c1 := newTestCorrelator()
			id1, created1, err := c1.OnFinding(tt.first)
			if err != nil {
				t.Fatalf("OnFinding first: %v", err)
			}
			if !created1 {
				t.Fatal("setup did not create incident")
			}
			prior, ok := c1.Get(id1)
			if !ok {
				t.Fatal("created incident not found")
			}

			c2 := newTestCorrelator()
			c2.Restore([]Incident{prior})
			c2.now = func() time.Time { return time.Unix(1_700_000_300, 0) }
			id2, created2, err := c2.OnFinding(tt.second)
			if err != nil {
				t.Fatalf("OnFinding second: %v", err)
			}
			if created2 {
				t.Fatal("restored incident key was not rebound")
			}
			if id2 != id1 {
				t.Fatalf("id after restore = %q, want %q", id2, id1)
			}
		})
	}
}

func TestCorrelatorRestoreSkipsClosedIncidents(t *testing.T) {
	c := newTestCorrelator()
	resolved := Incident{
		ID: "inc_closed", Status: StatusResolved, Severity: alert.High, Account: "alice",
		CreatedAt: time.Unix(1_700_000_000, 0), UpdatedAt: time.Unix(1_700_000_000, 0),
	}
	c.Restore([]Incident{resolved})

	c.now = func() time.Time { return time.Unix(1_700_000_000+5*60, 0) }
	_, created, _ := c.OnFinding(alert.Finding{
		Check: "x", Severity: alert.High, TenantID: "alice",
		Timestamp: time.Unix(1_700_000_000+5*60, 0),
	})
	if !created {
		t.Errorf("Restore must NOT bind closed incidents to the active byKey index")
	}
}

func TestCorrelatorPruneClosedOlderThanRemovesMemoryEntries(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	old := now.Add(-(30*24*time.Hour + time.Second))
	c := newTestCorrelator()
	c.Restore([]Incident{
		{ID: "inc_old_closed", Status: StatusResolved, Severity: alert.High, Account: "alice", CreatedAt: old, UpdatedAt: old},
		{ID: "inc_old_open", Status: StatusOpen, Severity: alert.High, Account: "bob", CreatedAt: old, UpdatedAt: old},
		{ID: "inc_fresh_closed", Status: StatusDismissed, Severity: alert.High, Account: "carol", CreatedAt: now, UpdatedAt: now},
	})

	pruned := c.PruneClosedOlderThan(now, 30*24*time.Hour)
	if pruned != 1 {
		t.Fatalf("PruneClosedOlderThan pruned %d, want 1", pruned)
	}
	if _, ok := c.Get("inc_old_closed"); ok {
		t.Fatal("old closed incident still present")
	}
	if _, ok := c.Get("inc_old_open"); !ok {
		t.Fatal("old open incident was pruned")
	}
	if _, ok := c.Get("inc_fresh_closed"); !ok {
		t.Fatal("fresh closed incident was pruned")
	}
}

// TestCorrelatorPruneClosedUnbindsSpray pins that pruning a closed
// incident also drops any spray-detector binding pointing at it. The
// binding is normally released at close time, but a restore path or a
// future direct prune could leave one attached; without the unbind the
// orphaned perIP entry is never reaped (PruneStale skips bound entries)
// and a later finding from that IP would route into a deleted incident.
func TestCorrelatorPruneClosedUnbindsSpray(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	old := now.Add(-(30*24*time.Hour + time.Second))
	ip1 := "203.0.113.7"
	ip2 := "203.0.113.8"
	activeIP := "203.0.113.9"
	c := NewCorrelator(CorrelatorConfig{
		SpraySuppression: SpraySuppressionConfig{Enabled: true, DistinctMailboxes: 10, MaxTrackedIPs: 100},
	})
	c.now = func() time.Time { return now }
	if c.spray == nil {
		t.Fatal("setup: spray detector not constructed")
	}
	c.Restore([]Incident{
		{
			ID:             "inc_spray_closed_a",
			Kind:           KindCredentialSpray,
			Status:         StatusResolved,
			Severity:       alert.High,
			CorrelationKey: &Key{RemoteIP: ip1},
			CreatedAt:      old,
			UpdatedAt:      old,
		},
		{
			ID:             "inc_spray_closed_b",
			Kind:           KindCredentialSpray,
			Status:         StatusDismissed,
			Severity:       alert.High,
			CorrelationKey: &Key{RemoteIP: ip2},
			CreatedAt:      old,
			UpdatedAt:      old,
		},
		{
			ID:             "inc_spray_open",
			Kind:           KindCredentialSpray,
			Status:         StatusOpen,
			Severity:       alert.High,
			CorrelationKey: &Key{RemoteIP: activeIP},
			CreatedAt:      old,
			UpdatedAt:      old,
		},
	})

	c.mu.Lock()
	c.spray.Rehydrate(ip1, "inc_spray_closed_a", old)
	c.spray.Rehydrate(ip2, "inc_spray_closed_b", old)
	c.mu.Unlock()
	if got := c.spray.IncidentForIP(ip1); got != "inc_spray_closed_a" {
		t.Fatalf("setup: spray binding for %s = %q, want inc_spray_closed_a", ip1, got)
	}
	if got := c.spray.IncidentForIP(ip2); got != "inc_spray_closed_b" {
		t.Fatalf("setup: spray binding for %s = %q, want inc_spray_closed_b", ip2, got)
	}

	if pruned := c.PruneClosedOlderThan(now, 30*24*time.Hour); pruned != 2 {
		t.Fatalf("PruneClosedOlderThan pruned %d, want 2", pruned)
	}
	if got := c.spray.IncidentForIP(ip1); got != "" {
		t.Errorf("spray binding survived prune of closed incident: %q", got)
	}
	if got := c.spray.IncidentForIP(ip2); got != "" {
		t.Errorf("spray binding survived prune of dismissed incident: %q", got)
	}
	if got := c.spray.IncidentForIP(activeIP); got != "inc_spray_open" {
		t.Errorf("spray binding for active incident = %q, want inc_spray_open", got)
	}
}

// TestCorrelatorHostTakeoverCompound pins the uid0 + suid host-takeover
// compound: two distinct privilege-escalation legs on the same host
// inside the merge window escalate the incident from host_integrity_risk
// to host_takeover.
func TestCorrelatorHostTakeoverCompound(t *testing.T) {
	c := newTestCorrelator()
	now := time.Unix(1_700_000_000, 0)

	id1, created1, err := c.OnFinding(alert.Finding{
		Check: "uid0_account", Severity: alert.High,
		Message: "new uid-0 account bob", Timestamp: now,
	})
	if err != nil || !created1 {
		t.Fatalf("uid0 finding must open an incident: created=%v err=%v", created1, err)
	}
	if inc, _ := c.Get(id1); inc.Kind != KindHostIntegrityRisk {
		t.Fatalf("after uid0 only: Kind=%s, want host_integrity_risk", inc.Kind)
	}

	c.now = func() time.Time { return now.Add(time.Minute) }
	id2, created2, _ := c.OnFinding(alert.Finding{
		Check: "suid_binary", Severity: alert.High,
		Message: "planted suid /home/bob/x", Timestamp: now.Add(time.Minute),
	})
	if created2 || id1 != id2 {
		t.Fatalf("suid must merge into the host incident: created=%v id1=%s id2=%s", created2, id1, id2)
	}
	inc, _ := c.Get(id1)
	if inc.Kind != KindHostTakeover {
		t.Fatalf("after uid0+suid: Kind=%s, want host_takeover", inc.Kind)
	}
	if !inc.CompoundFlags.UID0 || !inc.CompoundFlags.SUID {
		t.Errorf("compound flags = %+v, want UID0 and SUID set", inc.CompoundFlags)
	}
}

// TestCorrelatorSingleHostLegStaysIntegrityRisk confirms one leg alone
// does not escalate to host_takeover.
func TestCorrelatorSingleHostLegStaysIntegrityRisk(t *testing.T) {
	c := newTestCorrelator()
	id, _, _ := c.OnFinding(alert.Finding{
		Check: "suid_binary", Severity: alert.High,
		Message: "planted suid", Timestamp: time.Unix(1_700_000_000, 0),
	})
	if inc, _ := c.Get(id); inc.Kind != KindHostIntegrityRisk {
		t.Fatalf("single leg Kind=%s, want host_integrity_risk", inc.Kind)
	}
}

func TestCorrelatorSetStatusUpdatesIncidentAndAppendsAction(t *testing.T) {
	c := newTestCorrelator()
	id, _, _ := c.OnFinding(alert.Finding{Check: "x", Severity: alert.High, TenantID: "alice", Timestamp: time.Unix(1_700_000_000, 0)})

	if err := c.SetStatus(id, StatusResolved, "operator-marked"); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}
	inc, _ := c.Get(id)
	if inc.Status != StatusResolved {
		t.Errorf("Status: %v", inc.Status)
	}
	if len(inc.Actions) == 0 {
		t.Fatal("expected status-change action")
	}
	last := inc.Actions[len(inc.Actions)-1]
	if last.Action != "incident_status_changed" {
		t.Errorf("Action: %q", last.Action)
	}
}

func TestCorrelatorSetStatusUnbindsClosed(t *testing.T) {
	c := newTestCorrelator()
	id1, _, _ := c.OnFinding(alert.Finding{Check: "x", Severity: alert.High, TenantID: "alice", Timestamp: time.Unix(1_700_000_000, 0)})
	if err := c.SetStatus(id1, StatusResolved, "done"); err != nil {
		t.Fatal(err)
	}

	c.now = func() time.Time { return time.Unix(1_700_000_000+30, 0) }
	id2, created, _ := c.OnFinding(alert.Finding{Check: "y", Severity: alert.High, TenantID: "alice", Timestamp: time.Unix(1_700_000_000+30, 0)})
	if !created {
		t.Errorf("after status=resolved, the next finding for the account must start a new incident")
	}
	if id1 == id2 {
		t.Errorf("ids must differ; got %q twice", id1)
	}
}

func TestCorrelatorSetStatusReopenRebindsKey(t *testing.T) {
	c := newTestCorrelator()
	id1, _, _ := c.OnFinding(alert.Finding{Check: "x", Severity: alert.High, TenantID: "alice", Timestamp: time.Unix(1_700_000_000, 0)})
	if err := c.SetStatus(id1, StatusResolved, "done"); err != nil {
		t.Fatal(err)
	}
	if err := c.SetStatus(id1, StatusOpen, "reopened"); err != nil {
		t.Fatal(err)
	}

	c.now = func() time.Time { return time.Unix(1_700_000_000+30, 0) }
	id2, created, _ := c.OnFinding(alert.Finding{Check: "y", Severity: alert.High, TenantID: "alice", Timestamp: time.Unix(1_700_000_000+30, 0)})
	if created {
		t.Fatal("finding after reopen created a new incident")
	}
	if id2 != id1 {
		t.Fatalf("id after reopen = %q, want %q", id2, id1)
	}
}

func TestCorrelatorSetStatusRejectsUnknownID(t *testing.T) {
	c := newTestCorrelator()
	if err := c.SetStatus("inc_nope", StatusResolved, ""); err == nil {
		t.Errorf("expected error for unknown id")
	}
}

func TestCorrelatorSetStatusRejectsInvalidStatus(t *testing.T) {
	c := newTestCorrelator()
	id, _, _ := c.OnFinding(alert.Finding{Check: "x", Severity: alert.High, TenantID: "alice", Timestamp: time.Unix(1_700_000_000, 0)})
	if err := c.SetStatus(id, Status("bogus"), "x"); err == nil {
		t.Errorf("expected error for invalid status")
	}
}

func TestIncrementCompactedTotalBumpsMetric(t *testing.T) {
	c := newTestCorrelator()
	if c.counters.compactedTotal.Load() != 0 {
		t.Fatal("setup")
	}
	c.IncrementCompactedTotal(7)
	if got := c.counters.compactedTotal.Load(); got != 7 {
		t.Errorf("compactedTotal: want 7, got %d", got)
	}
	c.IncrementCompactedTotal(-3) // negative ignored; counter must not underflow
	if got := c.counters.compactedTotal.Load(); got != 7 {
		t.Errorf("negative input must be ignored; got %d", got)
	}
}
