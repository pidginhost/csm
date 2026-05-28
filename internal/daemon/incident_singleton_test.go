package daemon

import (
	"bytes"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/incident"
	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/store"
)

func TestIncidentCorrelatorSingletonReturnsSameInstance(t *testing.T) {
	resetIncidentForTest()
	c1 := IncidentCorrelator()
	c2 := IncidentCorrelator()
	if c1 != c2 {
		t.Fatal("expected singleton")
	}
}

func TestIncidentCorrelatorIngestsDirectFindings(t *testing.T) {
	resetIncidentForTest()
	c := IncidentCorrelator()

	_, _, _ = c.OnFinding(alert.Finding{
		Check:     "wp_login_bruteforce",
		Severity:  alert.High,
		TenantID:  "alice",
		Timestamp: time.Now(),
	})

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if c.OpenCount() > 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("incident not created within deadline")
}

// TestIncidentCorrelatorHonorsProductionThreshold proves the daemon
// wires the production OpenThreshold (>= 2) through to the correlator
// singleton, so an isolated High-severity finding does NOT open an
// incident on the first hit. This is the wiring contract that keeps
// scanner one-shots out of the /incident page on busy hosts.
func TestIncidentCorrelatorHonorsProductionThreshold(t *testing.T) {
	resetIncidentForTestWithThreshold(2)
	c := IncidentCorrelator()

	f := alert.Finding{
		Check:     "wp_login_bruteforce",
		Severity:  alert.High,
		TenantID:  "alice",
		Timestamp: time.Now(),
	}
	if _, created, _ := c.OnFinding(f); created {
		t.Fatalf("first non-Critical finding opened incident under production threshold")
	}
	if got := c.OpenCount(); got != 0 {
		t.Fatalf("OpenCount after first finding = %d, want 0", got)
	}
	if got := c.PendingCount(); got != 1 {
		t.Fatalf("PendingCount after first finding = %d, want 1", got)
	}

	// Second correlated finding inside the merge window must promote.
	if _, created, _ := c.OnFinding(f); !created {
		t.Fatalf("second finding did not open incident")
	}
	if got := c.OpenCount(); got != 1 {
		t.Fatalf("OpenCount after second finding = %d, want 1", got)
	}
}

// TestIncidentCorrelatorCriticalBypassesThreshold proves Critical
// findings page on first hit even under the production threshold.
// Account-compromise events must not be deferred to a second event.
func TestIncidentCorrelatorCriticalBypassesThreshold(t *testing.T) {
	resetIncidentForTestWithThreshold(2)
	c := IncidentCorrelator()

	if _, created, _ := c.OnFinding(alert.Finding{
		Check:     "email_compromised_account",
		Severity:  alert.Critical,
		Mailbox:   "alice@example.com",
		Domain:    "example.com",
		Timestamp: time.Now(),
	}); !created {
		t.Fatalf("Critical finding did not open incident on first hit")
	}
	if got := c.OpenCount(); got != 1 {
		t.Fatalf("OpenCount = %d, want 1", got)
	}
}

func TestIncidentCorrelatorSprayBlockerHonorsLiveAutoResponseConfig(t *testing.T) {
	resetIncidentForTest()
	t.Cleanup(resetIncidentForTest)

	cfg := &config.Config{}
	cfg.AutoResponse.BlockIPs = true
	cfg.AutoResponse.BlockExpiry = "15m"
	cfg.Incidents.SpraySuppression.Enabled = true
	cfg.Incidents.SpraySuppression.DryRun = false
	cfg.Incidents.SpraySuppression.DistinctMailboxes = 3
	cfg.Incidents.SpraySuppression.SeverityEscalateAt = 6
	cfg.Incidents.SpraySuppression.PerCheck = []string{"email_auth_failure_realtime"}
	cfg.Incidents.SpraySuppression.BlockAtSeverity = "high"
	SetIncidentConfigSource(func() *config.Config { return cfg })

	type blockCall struct {
		ip      string
		reason  string
		timeout time.Duration
	}
	var (
		mu    sync.Mutex
		calls []blockCall
	)
	SetIncidentSprayBlocker(func(ip, reason string, timeout time.Duration) (bool, error) {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, blockCall{ip: ip, reason: reason, timeout: timeout})
		return true, nil
	})

	c := IncidentCorrelator()
	feedSpray(t, c, "192.0.2.80", 3)
	mu.Lock()
	gotDisabled := len(calls)
	mu.Unlock()
	if gotDisabled != 0 {
		t.Fatalf("spray blocker fired %d times while auto_response.enabled=false; want 0", gotDisabled)
	}

	cfg.AutoResponse.Enabled = true
	feedSpray(t, c, "192.0.2.81", 3)
	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 1 {
		t.Fatalf("spray blocker calls = %d, want 1 after auto_response enabled", len(calls))
	}
	if calls[0].ip != "192.0.2.81" {
		t.Errorf("spray block IP = %q, want 192.0.2.81", calls[0].ip)
	}
	if !strings.Contains(calls[0].reason, "CSM credential_spray: credential_spray: 3 distinct mailboxes") {
		t.Errorf("spray block reason = %q, want CSM credential_spray prefix and mailbox count", calls[0].reason)
	}
	if calls[0].timeout != 15*time.Minute {
		t.Errorf("spray block timeout = %s, want 15m", calls[0].timeout)
	}
}

func TestIncidentCorrelatorSprayBlockerRequiresLiveOutcome(t *testing.T) {
	resetIncidentForTest()
	t.Cleanup(resetIncidentForTest)

	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.Incidents.SpraySuppression.Enabled = true
	cfg.Incidents.SpraySuppression.DryRun = false
	cfg.Incidents.SpraySuppression.DistinctMailboxes = 3
	cfg.Incidents.SpraySuppression.SeverityEscalateAt = 6
	cfg.Incidents.SpraySuppression.PerCheck = []string{"email_auth_failure_realtime"}
	cfg.Incidents.SpraySuppression.BlockAtSeverity = "high"
	SetIncidentConfigSource(func() *config.Config { return cfg })

	var calls int
	SetIncidentSprayBlocker(func(_, _ string, _ time.Duration) (bool, error) {
		calls++
		return false, nil
	})

	c := IncidentCorrelator()
	feedSpray(t, c, "192.0.2.82", 3)
	if calls != 1 {
		t.Fatalf("spray blocker calls = %d, want 1", calls)
	}
	for _, inc := range c.Snapshot() {
		if inc.Kind != incident.KindCredentialSpray {
			continue
		}
		for _, action := range inc.Actions {
			if action.Action == "credential_spray_block_requested" {
				t.Fatalf("non-live blocker outcome recorded block action: %+v", action)
			}
		}
	}
}

func feedSpray(t *testing.T, c *incident.Correlator, ip string, count int) {
	t.Helper()
	now := time.Unix(1_700_000_000, 0)
	for i := 0; i < count; i++ {
		_, _, err := c.OnFinding(alert.Finding{
			Check:     "email_auth_failure_realtime",
			Severity:  alert.High,
			SourceIP:  ip,
			Mailbox:   "user" + strconv.Itoa(i) + "@example.com",
			Timestamp: now.Add(time.Duration(i) * time.Minute),
		})
		if err != nil {
			t.Fatalf("OnFinding: %v", err)
		}
	}
}

func TestRunIncidentCompactionPrunesStoreAndMemory(t *testing.T) {
	resetIncidentForTest()
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	prev := store.Global()
	store.SetGlobal(db)
	t.Cleanup(func() {
		resetIncidentForTest()
		store.SetGlobal(prev)
		_ = db.Close()
	})

	old := time.Now().Add(-(incidentRetentionPeriod + time.Hour))
	inc := incident.Incident{
		ID:        "inc_old",
		Status:    incident.StatusResolved,
		Severity:  alert.High,
		Account:   "alice",
		CreatedAt: old,
		UpdatedAt: old,
	}
	if err := db.SaveIncident(inc); err != nil {
		t.Fatalf("SaveIncident: %v", err)
	}

	c := IncidentCorrelator()
	if _, ok := c.Get("inc_old"); !ok {
		t.Fatal("setup incident was not restored into memory")
	}

	runIncidentCompaction(c)
	if _, ok := c.Get("inc_old"); ok {
		t.Fatal("compacted incident still visible in memory")
	}
	if _, ok, err := db.GetIncident("inc_old"); err != nil {
		t.Fatalf("GetIncident: %v", err)
	} else if ok {
		t.Fatal("compacted incident still visible in store")
	}
}

func TestIncidentCorrelatorLogsRestoreFailure(t *testing.T) {
	resetIncidentForTest()
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	prev := store.Global()
	store.SetGlobal(db)
	if closeErr := db.Close(); closeErr != nil {
		t.Fatalf("db.Close: %v", closeErr)
	}
	finishLog := captureCSMLog(t)
	t.Cleanup(func() {
		_ = finishLog()
		resetIncidentForTest()
		store.SetGlobal(prev)
	})

	_ = IncidentCorrelator()

	out := finishLog()
	if !strings.Contains(out, "WARN: incident restore failed") {
		t.Fatalf("restore failure was not logged: %q", out)
	}
	if !strings.Contains(out, `err="database not open"`) {
		t.Fatalf("restore log did not include bbolt error: %q", out)
	}
}

func TestIncidentCorrelatorLogsPersistFailure(t *testing.T) {
	resetIncidentForTest()
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	prev := store.Global()
	store.SetGlobal(db)
	finishLog := captureCSMLog(t)
	t.Cleanup(func() {
		_ = finishLog()
		resetIncidentForTest()
		store.SetGlobal(prev)
		_ = db.Close()
	})

	c := IncidentCorrelator()
	if closeErr := db.Close(); closeErr != nil {
		t.Fatalf("db.Close: %v", closeErr)
	}
	_, created, err := c.OnFinding(alert.Finding{
		Check:     "wp_login_bruteforce",
		Severity:  alert.High,
		TenantID:  "alice",
		Timestamp: time.Now(),
	})
	if err != nil {
		t.Fatalf("OnFinding: %v", err)
	}
	if !created {
		t.Fatal("finding did not create an incident")
	}

	out := finishLog()
	if !strings.Contains(out, "WARN: incident persist failed") {
		t.Fatalf("persist failure was not logged: %q", out)
	}
	if !strings.Contains(out, "id=inc_") {
		t.Fatalf("persist log did not include incident id: %q", out)
	}
	if !strings.Contains(out, "status=open") {
		t.Fatalf("persist log did not include incident status: %q", out)
	}
	if !strings.Contains(out, `err="database not open"`) {
		t.Fatalf("persist log did not include bbolt error: %q", out)
	}
}

func captureCSMLog(t *testing.T) func() string {
	t.Helper()
	t.Setenv("CSM_LOG_FORMAT", "text")
	t.Setenv("CSM_LOG_LEVEL", "debug")

	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stderr = w
	csmlog.Init()

	var (
		once sync.Once
		out  string
	)
	return func() string {
		once.Do(func() {
			_ = w.Close()
			var buf bytes.Buffer
			_, _ = io.Copy(&buf, r)
			_ = r.Close()
			os.Stderr = oldStderr
			csmlog.Init()
			out = buf.String()
		})
		return out
	}
}

func TestIncidentCorrelatorSingletonIsIdempotent(t *testing.T) {
	resetIncidentForTest()
	_ = IncidentCorrelator()
	_ = IncidentCorrelator()
	_ = IncidentCorrelator()
	// No panic, no duplicate metric registration. The metrics seam is
	// pinned in TestMain to a private NewRegistry; if this test ever
	// hits metrics.Default it will panic on duplicate registration.
}
