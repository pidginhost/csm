package alert

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAuditSourcesDoNotStartNotificationDelivery(t *testing.T) {
	resetAuditSinksForTest()
	t.Cleanup(resetAuditSinksForTest)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	cfg := cfgWithJSONLAudit(t, path)
	cfg.Alerts.Webhook.Enabled = true
	cfg.Alerts.Webhook.Type = "phpanel"
	// A source-only audit must not need notification state or credentials.
	cfg.StatePath = ""
	if err := DispatchWithSources(cfg, nil, []Finding{{Check: "pam_bruteforce", Message: "source observation"}}); err != nil {
		t.Fatalf("audit-only source entered delivery: %v", err)
	}
	resetAuditSinksForTest()
	if data, err := os.ReadFile(path); err != nil || len(data) == 0 {
		t.Fatalf("source audit missing: error=%v", err)
	}
}

func TestAuditSourcesDeduplicateAcrossBatchesAndRetryFailedSinks(t *testing.T) {
	isolateAuditManager(t)
	now := time.Unix(100, 0)
	auditNow = func() time.Time { return now }
	file := &managedTestSink{name: "jsonl"}
	syslog := &managedTestSink{name: "syslog", failEmit: true}
	openJSONLAuditSink = func(string) (AuditSink, error) { return file, nil }
	openSyslogAuditSink = func(SyslogConfig) (AuditSink, error) { return syslog, nil }
	cfg := cfgWithJSONLAudit(t, "unused")
	cfg.Alerts.AuditLog.Syslog.Enabled = true
	f := Finding{Check: "pam_bruteforce", Message: "same observation", Timestamp: now}
	for range 3 {
		if err := DispatchWithSources(cfg, nil, []Finding{f, f}); err != nil {
			t.Fatal(err)
		}
	}
	now = now.Add(time.Minute)
	syslog = &managedTestSink{name: "syslog"}
	if err := DispatchWithSources(cfg, nil, []Finding{f}); err != nil {
		t.Fatal(err)
	}
	if file.events.Load() != 1 || syslog.events.Load() != 1 {
		t.Fatalf("same observation delivered file=%d syslog=%d, want once to each", file.events.Load(), syslog.events.Load())
	}
	f.Timestamp = now
	if err := DispatchWithSources(cfg, nil, []Finding{f}); err != nil {
		t.Fatal(err)
	}
	if file.events.Load() != 2 || syslog.events.Load() != 2 {
		t.Fatal("dedup discarded a distinct repeat observation")
	}
}

func TestAuditSourcesShareTimestampWithoutMutatingInputs(t *testing.T) {
	resetAuditSinksForTest()
	t.Cleanup(resetAuditSinksForTest)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	cfg := cfgWithJSONLAudit(t, path)
	source := []Finding{{Check: "wp_login_bruteforce", Message: "source observation"}}
	notifications := append([]Finding(nil), source...)
	if err := DispatchWithSources(cfg, notifications, source); err != nil {
		t.Fatal(err)
	}
	resetAuditSinksForTest()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(strings.TrimSpace(string(data)), "\n") != 0 {
		t.Fatal("overlapping unstamped source emitted duplicate audit rows")
	}
	var event AuditEvent
	if decodeErr := json.Unmarshal(data, &event); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if event.FindingID == "" || event.Timestamp.IsZero() {
		t.Fatal("source identity or observation time missing")
	}
	if !source[0].Timestamp.IsZero() || !notifications[0].Timestamp.IsZero() {
		t.Fatal("dispatch mutated caller-owned timestamps")
	}
}

func TestAuditReplayReceiptsStayBoundedUnderFlood(t *testing.T) {
	isolateAuditManager(t)
	sink := &managedTestSink{name: "jsonl"}
	openJSONLAuditSink = func(string) (AuditSink, error) { return sink, nil }
	cfg := cfgWithJSONLAudit(t, "unused")
	now := time.Unix(100, 0)
	var last Finding
	for i := range 2 * auditReceiptCap {
		last = Finding{Check: "webshell_realtime", Message: fmt.Sprint(i), Timestamp: now}
		emitAuditWithSources(cfg, nil, []Finding{last})
	}
	for range 100 {
		emitAuditWithSources(cfg, nil, []Finding{last})
	}
	if sink.events.Load() != 2*auditReceiptCap {
		t.Fatal("replay flood duplicated records or discarded distinct observations")
	}
	if len(auditSinks[0].delivered) > auditReceiptCap || len(auditSinks[0].recent) > auditReceiptCap {
		t.Fatal("audit replay tracking grew beyond its bound")
	}
	// An evicted receipt can be delivered again; it must not suppress a record
	// merely because the fixed cache has seen more than its capacity.
	emitAuditWithSources(cfg, nil, []Finding{{Check: "webshell_realtime", Message: "0", Timestamp: now}})
	if sink.events.Load() != 2*auditReceiptCap+1 {
		t.Fatal("full receipt cache stopped admitting observations")
	}
}
