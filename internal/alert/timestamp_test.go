package alert

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

// Producers that build a Finding without a Timestamp (mail geo, sensitive
// file writes, mail AV degradation, YARA worker crash) used to reach the
// audit log with the zero time, which sorts before every real event in a
// SIEM and makes the finding id collide across occurrences.
func TestDispatchStampsMissingTimestamps(t *testing.T) {
	isolateAuditManager(t)

	path := filepath.Join(t.TempDir(), "audit.jsonl")
	cfg := cfgWithJSONLAudit(t, path)
	fixed := time.Date(2026, 9, 9, 16, 0, 0, 0, time.UTC)
	auditNow = func() time.Time { return fixed }

	kept := time.Date(2026, 9, 9, 15, 0, 0, 0, time.UTC)
	findings := []Finding{
		{Severity: High, Check: "email_suspicious_geo", Message: "login from elsewhere"},
		{Severity: Critical, Check: "yara_worker_crashed", Message: "worker exited", Timestamp: kept},
	}
	if err := Dispatch(cfg, findings); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if !findings[0].Timestamp.IsZero() {
		t.Errorf("caller's finding changed: %v", findings[0].Timestamp)
	}
	if findings[1].Timestamp != kept {
		t.Fatalf("existing timestamp overwritten: %v", findings[1].Timestamp)
	}
	second := fixed.Add(time.Minute)
	auditNow = func() time.Time { return second }
	if err := Dispatch(cfg, findings); err != nil {
		t.Fatalf("second Dispatch: %v", err)
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
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("audit events = %d, want 4", len(got))
	}
	if !got[0].Timestamp.Equal(fixed) {
		t.Errorf("audit ts for unstamped finding = %v, want %v", got[0].Timestamp, fixed)
	}
	if !got[1].Timestamp.Equal(kept) {
		t.Errorf("audit ts for stamped finding = %v, want %v", got[1].Timestamp, kept)
	}
	if !got[2].Timestamp.Equal(second) || got[2].FindingID == got[0].FindingID {
		t.Errorf("reused unstamped finding kept its first occurrence: %+v", got[2])
	}
	if !got[3].Timestamp.Equal(kept) || got[3].FindingID != got[1].FindingID {
		t.Errorf("replayed stamped finding changed identity: %+v", got[3])
	}
}

// Dispatch callers can share read-only input; assigning a timestamp in that
// slice races with another dispatch and silently changes later occurrences.
func TestDispatchConcurrentUnstampedFindings(t *testing.T) {
	isolateAuditManager(t)
	cfg := &config.Config{}
	findings := []Finding{{Severity: High, Check: "email_av_degraded", Message: "scanner unavailable"}}
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 8 {
		wg.Go(func() {
			<-start
			if err := Dispatch(cfg, findings); err != nil {
				t.Errorf("Dispatch: %v", err)
			}
		})
	}
	close(start)
	wg.Wait()
	if !findings[0].Timestamp.IsZero() {
		t.Fatalf("Dispatch mutated shared input: %v", findings[0].Timestamp)
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
