package store

import (
	"fmt"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func TestScanJobRoundTripAndRetention(t *testing.T) {
	db := openTestDB(t) // existing helper
	for i := 0; i < 25; i++ {
		id := fmt.Sprintf("job-%03d", i)
		if err := db.PutScanJob(ScanJobRecord{
			ID: id, Scope: "account", Target: "u", State: "done",
			Created: time.Unix(int64(i), 0),
		}); err != nil {
			t.Fatal(err)
		}
		_ = db.AppendScanJobFinding(id, 0, alert.Finding{Check: "webshells"})
	}
	got, ok, err := db.GetScanJob("job-010")
	if err != nil || !ok || got.Target != "u" {
		t.Fatalf("get = %+v ok=%v err=%v", got, ok, err)
	}
	jobs, err := db.ListScanJobs()
	if err != nil {
		t.Fatal(err)
	}
	if jobs[0].ID != "job-024" || jobs[len(jobs)-1].ID != "job-000" {
		t.Fatalf("jobs not newest first: first=%s last=%s", jobs[0].ID, jobs[len(jobs)-1].ID)
	}
	pruned, err := db.PruneScanJobs(20)
	if err != nil || pruned != 5 {
		t.Fatalf("prune = %d err=%v, want 5", pruned, err)
	}
	if _, ok, _ := db.GetScanJob("job-000"); ok {
		t.Error("oldest job should be pruned")
	}
	fs, total, err := db.ListScanJobFindings("job-024", 0, 10)
	if err != nil || total != 1 || len(fs) != 1 {
		t.Fatalf("findings = %d total=%d err=%v", len(fs), total, err)
	}
	old, total, err := db.ListScanJobFindings("job-000", 0, 10)
	if err != nil || total != 0 || len(old) != 0 {
		t.Fatalf("pruned job findings survived: len=%d total=%d err=%v", len(old), total, err)
	}
}
