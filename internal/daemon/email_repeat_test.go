package daemon

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/store"
)

// repeatWebhook records every generic webhook body.
type repeatWebhook struct {
	mu     sync.Mutex
	bodies []string
	status int
	onSend func()
}

func (w *repeatWebhook) RoundTrip(req *http.Request) (*http.Response, error) {
	body, _ := io.ReadAll(req.Body)
	w.mu.Lock()
	w.bodies = append(w.bodies, string(body))
	status := w.status
	if status == 0 {
		status = http.StatusOK
	}
	onSend := w.onSend
	w.mu.Unlock()
	if onSend != nil {
		onSend()
	}
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header), Request: req}, nil
}

func (w *repeatWebhook) count(marker string) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := 0
	for _, b := range w.bodies {
		if strings.Contains(b, marker) {
			n++
		}
	}
	return n
}

func (w *repeatWebhook) last() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.bodies) == 0 {
		return ""
	}
	return w.bodies[len(w.bodies)-1]
}

func emailRepeatSetup(t *testing.T) (*config.Config, *repeatWebhook) {
	t.Helper()
	resetIncidentForTest()
	t.Cleanup(resetIncidentForTest)
	previousStore := store.Global()
	store.SetGlobal(nil)
	t.Cleanup(func() { store.SetGlobal(previousStore) })
	hook := &repeatWebhook{}
	t.Cleanup(alert.SetWebhookTransportForTest(hook))
	// One fixed budget hour: a run across an hour boundary would reset the cap.
	budgetHour := time.Date(2026, 1, 2, 10, 30, 0, 0, time.UTC)
	t.Cleanup(alert.SetRateLimitClockForTest(func() time.Time { return budgetHour }))
	cfg := &config.Config{StatePath: t.TempDir(), Hostname: "host.example.com"}
	cfg.Alerts.MaxPerHour = 100
	cfg.Alerts.Webhook.Enabled = true
	cfg.Alerts.Webhook.URL = "https://hooks.example.com/csm"
	return cfg, hook
}

func openRepeatDaemon(t *testing.T, cfg *config.Config) *Daemon {
	t.Helper()
	st, err := state.Open(cfg.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return New(cfg, st, nil, "")
}

// rewriteState closes the daemon's store, lets edit change the persisted
// entries, and reopens it, as a restart would.
func rewriteState(t *testing.T, d *Daemon, edit func(map[string]map[string]any)) {
	t.Helper()
	if err := d.store.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(d.cfg.StatePath, "state.json")
	entries := map[string]map[string]any{}
	if data, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(data, &entries); err != nil {
			t.Fatal(err)
		}
	}
	edit(entries)
	data, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := state.Open(d.cfg.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	d.store = st
}

func repeatFinding(message string) alert.Finding {
	return alert.Finding{
		Check:     "wp_core_integrity",
		Severity:  alert.High,
		Message:   message,
		Details:   "file /home/example/public_html/wp-includes/version.php",
		Timestamp: time.Now(),
	}
}

func historyCount(d *Daemon) int {
	_, total := d.store.ReadHistory(1000, 0)
	return total
}

// Identical re-reports reach the audit log every time; email and the webhook
// only on the first report.
func TestDispatchBatchIdenticalReReportAuditOnly(t *testing.T) {
	cfg, hook := emailRepeatSetup(t)
	cfg.Alerts.AuditLog.File.Enabled = true
	cfg.Alerts.AuditLog.File.Path = filepath.Join(t.TempDir(), "audit.jsonl")
	t.Cleanup(alert.CloseAuditSinks)
	d := openRepeatDaemon(t, cfg)
	f := repeatFinding("core file changed")

	for i := 0; i < 3; i++ {
		f.Timestamp = time.Unix(int64(1000+i), 0)
		d.dispatchBatch([]alert.Finding{f})
	}
	alert.CloseAuditSinks()

	data, err := os.ReadFile(cfg.Alerts.AuditLog.File.Path)
	if err != nil {
		t.Fatal(err)
	}
	records := 0
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var row struct {
			Check string `json:"check"`
		}
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatal(err)
		}
		if row.Check == f.Check {
			records++
		}
	}
	if records != 3 {
		t.Errorf("audit records = %d, want 3", records)
	}
	if got := hook.count(f.Message); got != 1 {
		t.Errorf("webhooks = %d, want 1", got)
	}
}

func TestDispatchBatchNoDailyEmailReminder(t *testing.T) {
	cfg, hook := emailRepeatSetup(t)
	f := repeatFinding("core file changed")
	now := time.Now()
	seed := map[string]map[string]any{f.Key(): {
		"hash":       f.Fingerprint(),
		"first_seen": now.Add(-48 * time.Hour),
		"last_seen":  now.Add(-time.Hour),
		"alert_sent": now.Add(-25 * time.Hour),
		"emailed":    f.Fingerprint(),
	}}
	data, err := json.Marshal(seed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.StatePath, "state.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	d := openRepeatDaemon(t, cfg)

	d.dispatchBatch([]alert.Finding{f})

	if got := historyCount(d); got != 1 {
		t.Errorf("history rows = %d, want the daily reminder", got)
	}
	if got := hook.count(f.Message); got != 0 {
		t.Errorf("webhooks = %d, want no email reminder", got)
	}
}

func TestDispatchBatchEmailsChangeAndReturn(t *testing.T) {
	for _, tc := range []struct {
		name  string
		again func(t *testing.T, d *Daemon, f alert.Finding) alert.Finding
	}{
		{"content changed", func(_ *testing.T, _ *Daemon, f alert.Finding) alert.Finding {
			f.Details = "file /home/example/public_html/wp-includes/load.php"
			return f
		}},
		{"entry unseen 25h", func(t *testing.T, d *Daemon, f alert.Finding) alert.Finding {
			rewriteState(t, d, func(entries map[string]map[string]any) {
				old := time.Now().Add(-25 * time.Hour)
				entries[f.Key()]["last_seen"] = old
				entries[f.Key()]["alert_sent"] = old
			})
			// Any later batch sweeps the stale entry.
			d.dispatchBatch([]alert.Finding{repeatFinding("unrelated change")})
			return f
		}},
		{"retired by a covering run", func(_ *testing.T, d *Daemon, f alert.Finding) alert.Finding {
			checks.StoreLatestScanFindingsWithCoverage(d.store, []string{f.Check}, nil, nil)
			return f
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, hook := emailRepeatSetup(t)
			d := openRepeatDaemon(t, cfg)
			f := repeatFinding("core file changed")
			checks.StoreLatestScanFindingsWithCoverage(d.store, []string{f.Check}, []alert.Finding{f}, nil)
			d.dispatchBatch([]alert.Finding{f})
			if got := hook.count(f.Message); got != 1 {
				t.Fatalf("first report: %d webhooks, want 1", got)
			}

			again := tc.again(t, d, f)
			before := hook.count(again.Message)
			d.dispatchBatch([]alert.Finding{again})
			if got := hook.count(again.Message) - before; got != 1 {
				t.Fatalf("%s: %d webhooks, want 1", tc.name, got)
			}
		})
	}
}

func TestCapDroppedFindingRetriesOnReminder(t *testing.T) {
	cfg, hook := emailRepeatSetup(t)
	cfg.Alerts.MaxPerHour = 1
	budgetHour := time.Date(2026, 1, 2, 10, 30, 0, 0, time.UTC)
	t.Cleanup(alert.SetRateLimitClockForTest(func() time.Time { return budgetHour }))
	d := openRepeatDaemon(t, cfg)
	first := repeatFinding("first core change")
	second := repeatFinding("second core change")

	d.dispatchBatch([]alert.Finding{first})
	d.dispatchBatch([]alert.Finding{second})
	if hook.count(first.Message) != 1 || hook.count(second.Message) != 0 {
		t.Fatalf("setup: want only the first delivered, got first=%d second=%d",
			hook.count(first.Message), hook.count(second.Message))
	}

	// A day later both are offered again by the history reminder, in a new
	// budget hour.
	rewriteState(t, d, func(entries map[string]map[string]any) {
		old := time.Now().Add(-25 * time.Hour)
		for _, f := range []alert.Finding{first, second} {
			entries[f.Key()]["alert_sent"] = old
		}
	})
	budgetHour = budgetHour.Add(time.Hour)
	d.dispatchBatch([]alert.Finding{first, second})

	last := hook.last()
	if !strings.Contains(last, second.Message) || strings.Contains(last, first.Message) {
		t.Fatalf("retry delivered %q, want only the capped finding", last)
	}
	if got := hook.count(second.Message); got != 1 {
		t.Fatalf("capped finding delivered %d times, want 1", got)
	}
}

func TestCoverageGapFlapEmailsOnce(t *testing.T) {
	cfg, hook := emailRepeatSetup(t)
	d := openRepeatDaemon(t, cfg)
	gap := alert.Finding{
		Check:     "yara_scan_incomplete",
		Severity:  alert.Warning,
		Message:   "YARA scan incomplete: files skipped",
		DedupKey:  "host",
		Timestamp: time.Now(),
	}
	purge := []string{"yara_deep", "yara_scan_incomplete"}

	for _, run := range [][]alert.Finding{{gap}, nil, {gap}} {
		d.processScanFindingsWithCoverage(cfg, run, purge, nil, "deep")
		if batch := drainAlertCh(d); len(batch) > 0 {
			d.dispatchBatch(batch)
		}
	}
	if got := hook.count(gap.Message); got != 1 {
		t.Fatalf("flapping coverage gap: %d webhooks, want 1", got)
	}
}

func TestDispatchBatchReturnWithoutSweep(t *testing.T) {
	cfg, hook := emailRepeatSetup(t)
	d := openRepeatDaemon(t, cfg)
	f := repeatFinding("returned without another batch")
	d.dispatchBatch([]alert.Finding{f})
	rewriteState(t, d, func(entries map[string]map[string]any) {
		old := time.Now().Add(-25 * time.Hour)
		entries[f.Key()]["last_seen"] = old
		entries[f.Key()]["alert_sent"] = old
	})
	d.dispatchBatch([]alert.Finding{f})
	d.dispatchBatch([]alert.Finding{f})
	if got := hook.count(f.Message); got != 2 {
		t.Fatalf("return after 25h: webhooks = %d, want 2", got)
	}
}

func TestDispatchRetriesBeforeHistoryReminder(t *testing.T) {
	for _, initialScan := range []bool{false, true} {
		for _, mode := range []string{"cap", "webhook error", "disabled"} {
			t.Run(fmt.Sprintf("initial=%t/%s", initialScan, mode), func(t *testing.T) {
				cfg, hook := emailRepeatSetup(t)
				d := openRepeatDaemon(t, cfg)
				f := repeatFinding("waiting for delivery")
				switch mode {
				case "cap":
					cfg.Alerts.MaxPerHour = 1
					d.dispatchBatch([]alert.Finding{repeatFinding("spend budget")})
				case "webhook error":
					hook.status = http.StatusServiceUnavailable
				case "disabled":
					cfg.Alerts.Webhook.Enabled = false
				}
				d.dispatchBatch([]alert.Finding{f})
				entry, ok := d.store.EntryForKey(f.Key())
				if !ok || entry.Emailed != "" {
					t.Fatalf("undelivered receipt: %+v, present=%t", entry, ok)
				}
				before := hook.count(f.Message)
				history := historyCount(d)
				cfg.Alerts.MaxPerHour = 100
				cfg.Alerts.Webhook.Enabled = true
				hook.status = http.StatusOK
				if initialScan {
					d.respondToInitialScan(cfg, []alert.Finding{f})
				} else {
					d.dispatchBatch([]alert.Finding{f})
				}
				if got := hook.count(f.Message) - before; got != 1 {
					t.Errorf("retry before daily history reminder: webhooks = %d, want 1", got)
				}
				if !initialScan && historyCount(d) != history {
					t.Errorf("delivery retry added history: got %d, want %d", historyCount(d), history)
				}
				d.dispatchBatch([]alert.Finding{f})
				if got := hook.count(f.Message) - before; got != 1 {
					t.Errorf("delivered retry repeated: webhooks = %d, want 1", got)
				}
			})
		}
	}
}

func TestDerivedDeliveryRetriesWithObservedSources(t *testing.T) {
	cfg, hook := emailRepeatSetup(t)
	d := openRepeatDaemon(t, cfg)
	var findings []alert.Finding
	for _, account := range []string{"one", "two", "three"} {
		findings = append(findings, alert.Finding{
			Check: "webshell", Severity: alert.Critical, TenantID: account,
			Message: "webshell on " + account, Timestamp: time.Now(),
		})
	}
	derived := checks.CorrelateBatchFindings(findings).Derived
	if len(derived) != 2 {
		t.Fatalf("setup: got %d derived findings, want 2", len(derived))
	}
	cfg.Alerts.Webhook.Enabled = false
	d.dispatchBatch(findings)
	cfg.Alerts.Webhook.Enabled = true
	d.dispatchBatch(findings)
	for _, f := range derived {
		if got := hook.count(f.Message); got != 1 {
			t.Errorf("derived retry %s: got %d webhooks, want 1", f.Check, got)
		}
	}
	// Continued observations must keep derived delivery receipts alive even
	// while the sources are inside their history reminder window.
	rewriteState(t, d, func(entries map[string]map[string]any) {
		for _, f := range derived {
			if entry := entries[f.Key()]; entry != nil {
				entry["last_seen"] = time.Now().Add(-23 * time.Hour)
			}
		}
	})
	d.dispatchBatch(findings)
	for _, f := range derived {
		entry, ok := d.store.EntryForKey(f.Key())
		if !ok || time.Since(entry.LastSeen) > time.Minute {
			t.Errorf("derived observation did not refresh %s: %+v present=%t", f.Check, entry, ok)
		}
		if got := hook.count(f.Message); got != 1 {
			t.Errorf("derived repeat %s: got %d webhooks, want 1", f.Check, got)
		}
	}
}

func TestDeliveryCandidatesRespectAcknowledgedSources(t *testing.T) {
	for _, initialScan := range []bool{false, true} {
		t.Run(fmt.Sprintf("initial=%t", initialScan), func(t *testing.T) {
			cfg, hook := emailRepeatSetup(t)
			d := openRepeatDaemon(t, cfg)
			var findings []alert.Finding
			for _, account := range []string{"one", "two", "three"} {
				findings = append(findings, alert.Finding{
					Check: "webshell", Severity: alert.Critical, TenantID: account,
					Message: "acknowledged on " + account, Timestamp: time.Now(),
				})
			}
			d.store.SetBaseline(findings)
			if initialScan {
				d.respondToInitialScan(cfg, findings)
			} else {
				d.dispatchBatch(findings)
			}
			if got := hook.count(""); got != 0 {
				t.Fatalf("acknowledged sources generated %d notifications", got)
			}
		})
	}
}

func TestDeliveryCandidatesUseCurrentCorrelation(t *testing.T) {
	cfg, _ := emailRepeatSetup(t)
	d := openRepeatDaemon(t, cfg)
	var findings []alert.Finding
	for _, account := range []string{"one", "two", "three", "four"} {
		findings = append(findings, alert.Finding{
			Check: "webshell", Severity: alert.Critical, TenantID: account,
			Message: "webshell on " + account, Timestamp: time.Now(),
		})
	}
	// Only the latter pair is new to history. Its summary is narrower than
	// the condition still present across all four accounts.
	newFindings := expandWithCorrelation(append([]alert.Finding(nil), findings[2:]...), time.Now())
	want := checks.CorrelateBatchFindings(findings).Derived
	got := d.deliveryCandidates(findings, newFindings, nil)
	keys := make(map[string]bool)
	for _, f := range got {
		if checks.IsDerivedCorrelationCheck(f.Check) {
			keys[f.Key()] = true
		}
	}
	if len(want) != 2 || len(keys) != len(want) {
		t.Fatalf("current correlation has %d summaries, want 2", len(keys))
	}
	for _, f := range want {
		if !keys[f.Key()] {
			t.Errorf("missing current correlation %s", f.Check)
		}
	}
}

func TestDeliveryFinishingAfterClearDoesNotMuteReturn(t *testing.T) {
	cfg, hook := emailRepeatSetup(t)
	d := openRepeatDaemon(t, cfg)
	f := repeatFinding("returned while delivery completes")
	checks.StoreLatestScanFindings(d.store, []string{f.Check}, []alert.Finding{f})
	hook.onSend = func() {
		checks.StoreLatestScanFindings(d.store, []string{f.Check}, nil)
	}
	d.dispatchBatch([]alert.Finding{f})
	hook.onSend = nil
	checks.StoreLatestScanFindings(d.store, []string{f.Check}, []alert.Finding{f})
	d.dispatchBatch([]alert.Finding{f})
	d.dispatchBatch([]alert.Finding{f})
	if got := hook.count(f.Message); got != 2 {
		t.Fatalf("return after in-flight clear: webhooks=%d, want 2", got)
	}
}
