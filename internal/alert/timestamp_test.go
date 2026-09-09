package alert

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Producers that build a Finding without a Timestamp (mail geo, sensitive
// file writes, mail AV degradation, YARA worker crash) used to reach the
// audit log with the zero time, which sorts before every real event in a
// SIEM and makes the finding id collide across occurrences.
func TestDispatchStampsMissingTimestamps(t *testing.T) {
	resetAuditSinksForTest()
	defer resetAuditSinksForTest()

	path := filepath.Join(t.TempDir(), "audit.jsonl")
	cfg := cfgWithJSONLAudit(t, path)
	fixed := time.Date(2026, 9, 9, 16, 0, 0, 0, time.UTC)
	auditNow = func() time.Time { return fixed }
	defer func() { auditNow = time.Now }()

	kept := time.Date(2026, 9, 9, 15, 0, 0, 0, time.UTC)
	findings := []Finding{
		{Severity: High, Check: "email_suspicious_geo", Message: "login from elsewhere"},
		{Severity: Critical, Check: "yara_worker_crashed", Message: "worker exited", Timestamp: kept},
	}
	if err := Dispatch(cfg, findings); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if findings[0].Timestamp != fixed {
		t.Fatalf("caller's finding not stamped: %v", findings[0].Timestamp)
	}
	if findings[1].Timestamp != kept {
		t.Fatalf("existing timestamp overwritten: %v", findings[1].Timestamp)
	}
	resetAuditSinksForTest()

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var got []AuditEvent
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var ev AuditEvent
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatal(err)
		}
		got = append(got, ev)
	}
	if len(got) != 2 {
		t.Fatalf("audit events = %d, want 2", len(got))
	}
	if !got[0].Timestamp.Equal(fixed) {
		t.Errorf("audit ts for unstamped finding = %v, want %v", got[0].Timestamp, fixed)
	}
	if !got[1].Timestamp.Equal(kept) {
		t.Errorf("audit ts for stamped finding = %v, want %v", got[1].Timestamp, kept)
	}
}

func TestFillTimestampsLeavesSetValues(t *testing.T) {
	now := time.Date(2026, 9, 9, 16, 0, 0, 0, time.UTC)
	kept := now.Add(-time.Hour)
	findings := []Finding{{Check: "a"}, {Check: "b", Timestamp: kept}, {Check: "c"}}
	FillTimestamps(findings, now)
	if findings[0].Timestamp != now || findings[2].Timestamp != now {
		t.Fatalf("zero timestamps not filled: %+v", findings)
	}
	if findings[1].Timestamp != kept {
		t.Fatalf("set timestamp changed: %v", findings[1].Timestamp)
	}
	FillTimestamps(nil, now)
}
