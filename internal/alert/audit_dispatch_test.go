package alert

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
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
