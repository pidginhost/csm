package alert

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

func cfgWithJSONLAudit(t *testing.T, path string) *config.Config {
	t.Helper()
	cfg := &config.Config{}
	cfg.Hostname = "host.test"
	cfg.StatePath = t.TempDir()
	cfg.Alerts.MaxPerHour = 100
	cfg.Alerts.AuditLog.File.Enabled = true
	cfg.Alerts.AuditLog.File.Path = path
	return cfg
}

func TestEmitAuditFiresBeforeRateLimit(t *testing.T) {
	resetAuditSinksForTest()
	defer resetAuditSinksForTest()

	path := filepath.Join(t.TempDir(), "audit.jsonl")
	cfg := cfgWithJSONLAudit(t, path)
	// Rate limit set to 0 so non-critical alerts are blocked, but
	// audit log should still fire.
	cfg.Alerts.MaxPerHour = 0

	findings := []Finding{
		{Severity: Warning, Check: "x", Message: "noisy", Timestamp: time.Now()},
	}
	if err := Dispatch(cfg, findings); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	resetAuditSinksForTest() // flush sinks so the file is closed before reading

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read jsonl: %v", err)
	}
	if len(data) == 0 {
		t.Error("audit log empty even though emit should fire before rate limit")
	}
}

func TestDispatchRedactsBothAuditSinks(t *testing.T) {
	resetAuditSinksForTest()
	t.Cleanup(resetAuditSinksForTest)
	addr, received := receiveOneUDP(t)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	cfg := cfgWithJSONLAudit(t, path)
	cfg.Alerts.MaxPerHour = 0
	cfg.Alerts.AuditLog.Syslog.Enabled = true
	cfg.Alerts.AuditLog.Syslog.Network = "udp"
	cfg.Alerts.AuditLog.Syslog.Address = addr
	cfg.Alerts.AuditLog.Syslog.Facility = "local0"
	f := Finding{
		Check: "cpanel_login_realtime", Severity: Warning, Timestamp: time.Unix(1757589449, 0),
		Message: "password=password-fixture",
		Details: "[whostmgrd] 198.51.100.56 NEW shop:session-fixture app=cpaneld",
	}
	if err := Dispatch(cfg, []Finding{f}); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	resetAuditSinksForTest()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	checkEvent := func(raw []byte) {
		t.Helper()
		var event AuditEvent
		if err := json.Unmarshal(raw, &event); err != nil {
			t.Fatalf("invalid audit JSON: %v", err)
		}
		if event.Message != "password=[REDACTED]" ||
			event.Details != "[whostmgrd] 198.51.100.56 NEW shop:[REDACTED] app=cpaneld" {
			t.Errorf("audit sink received unredacted text: %+v", event)
		}
		if event.FindingID != FindingID(f) {
			t.Errorf("audit sink lost finding correlation: %q", event.FindingID)
		}
	}
	checkEvent(raw)
	select {
	case raw := <-received:
		start := strings.IndexByte(string(raw), '{')
		if start < 0 {
			t.Fatalf("syslog JSON body missing: %q", raw)
		}
		checkEvent(raw[start:])
	case <-time.After(2 * time.Second):
		t.Fatal("syslog receive timeout")
	}
}

func TestEmitAuditFiresEvenWhenFilterBlockedRemovesAll(t *testing.T) {
	resetAuditSinksForTest()
	defer resetAuditSinksForTest()

	path := filepath.Join(t.TempDir(), "audit.jsonl")
	cfg := cfgWithJSONLAudit(t, path)

	// Suppression doesn't matter for this test -- just confirm that
	// even an empty post-filter finding list still records pre-filter
	// findings to the audit log.
	findings := []Finding{
		{Severity: Critical, Check: "fanotify_drop", Message: "drop", Timestamp: time.Now()},
		{Severity: Critical, Check: "fanotify_drop", Message: "drop", Timestamp: time.Now()},
	}
	if err := Dispatch(cfg, findings); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	resetAuditSinksForTest()

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	count := 0
	for scanner.Scan() {
		var m map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &m); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		count++
	}
	// Deduplicate runs first -- the two identical findings collapse
	// to one. Audit log sees the deduplicated set, which is what we
	// want for SIEM signal-to-noise.
	if count != 1 {
		t.Errorf("audit lines = %d, want 1 (dedup of identical findings)", count)
	}
}

func TestEnsureAuditSinksRebuildsOnConfigChange(t *testing.T) {
	resetAuditSinksForTest()
	defer resetAuditSinksForTest()

	pathA := filepath.Join(t.TempDir(), "a.jsonl")
	cfg := cfgWithJSONLAudit(t, pathA)
	ensureAuditSinks(cfg)
	if len(auditSinks) != 1 {
		t.Fatalf("first ensure: sinks = %d, want 1", len(auditSinks))
	}
	first := auditSinks[0]

	// Same config -- second call should be a no-op (same fingerprint).
	ensureAuditSinks(cfg)
	if auditSinks[0] != first {
		t.Error("identical config rebuilt sink (fingerprint compare failed)")
	}

	// Change path: fingerprint changes, sink should swap.
	pathB := filepath.Join(t.TempDir(), "b.jsonl")
	cfg.Alerts.AuditLog.File.Path = pathB
	ensureAuditSinks(cfg)
	if len(auditSinks) != 1 {
		t.Fatalf("after change: sinks = %d, want 1", len(auditSinks))
	}
	if auditSinks[0] == first {
		t.Error("path change did not rebuild sink")
	}
}

func TestEnsureAuditSinksDisabledMeansEmpty(t *testing.T) {
	resetAuditSinksForTest()
	defer resetAuditSinksForTest()

	cfg := &config.Config{}
	cfg.Hostname = "host.test"
	// Both sub-blocks disabled (zero value).
	ensureAuditSinks(cfg)
	if len(auditSinks) != 0 {
		t.Errorf("disabled config produced %d sinks", len(auditSinks))
	}
}
