package store

import (
	"fmt"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// TestScanJobFindingPrefixNoCollision verifies that the finding prefix for
// "job-1" does not match rows belonging to "job-10". This guards the
// invariant that findingPrefix uses a "/" suffix so "job-1/" is never a
// prefix of "job-10/...".
func TestScanJobFindingPrefixNoCollision(t *testing.T) {
	db := openTestDB(t)
	base := time.Unix(1000, 0)

	// job-10 gets one finding; job-1 gets none.
	if err := db.PutScanJob(ScanJobRecord{
		ID: "job-10", Scope: "account", Target: "u", State: "done",
		Created: base,
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.AppendScanJobFinding("job-10", 0, alert.Finding{Check: "webshells"}); err != nil {
		t.Fatal(err)
	}
	if err := db.PutScanJob(ScanJobRecord{
		ID: "job-1", Scope: "account", Target: "u", State: "done",
		Created: base.Add(-time.Second),
	}); err != nil {
		t.Fatal(err)
	}

	// job-1 must report zero findings; its prefix must not bleed into job-10.
	fs1, total1, err := db.ListScanJobFindings("job-1", 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if total1 != 0 || len(fs1) != 0 {
		t.Fatalf("job-1 prefix bled into job-10: total=%d len=%d", total1, len(fs1))
	}

	// job-10 must still return its one finding.
	fs10, total10, err := db.ListScanJobFindings("job-10", 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if total10 != 1 || len(fs10) != 1 {
		t.Fatalf("job-10 findings wrong: total=%d len=%d", total10, len(fs10))
	}
}

// TestAppendScanJobFindingsBatchesInOneTx proves the batch writer commits many
// findings in a single write transaction instead of one fsync per finding. The
// store's WriteTxID seam counts committed write transactions.
func TestAppendScanJobFindingsBatchesInOneTx(t *testing.T) {
	db := openTestDB(t)
	if err := db.PutScanJob(ScanJobRecord{
		ID: "bj", Scope: "account", Target: "u", State: "running", Created: time.Unix(1, 0),
	}); err != nil {
		t.Fatal(err)
	}

	findings := make([]alert.Finding, 50)
	for i := range findings {
		findings[i] = alert.Finding{Check: "webshells", Message: fmt.Sprintf("m%d", i)}
	}

	before := db.WriteTxID()
	if err := db.AppendScanJobFindings("bj", 0, findings); err != nil {
		t.Fatal(err)
	}
	after := db.WriteTxID()
	if delta := after - before; delta != 1 {
		t.Fatalf("batch of %d findings committed in %d write tx, want 1", len(findings), delta)
	}

	_, total, err := db.ListScanJobFindings("bj", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 50 {
		t.Fatalf("persisted %d findings, want 50", total)
	}
}

// TestPruneScanJobsFindingsVolumeCap verifies retention accounts for findings
// volume: even when the job-count keep is generous, older jobs are pruned so the
// retained finding rows stay under the volume cap. The newest job is always kept.
func TestPruneScanJobsFindingsVolumeCap(t *testing.T) {
	db := openTestDB(t)
	base := time.Unix(3000, 0)
	for i := 0; i < 5; i++ { // 5 jobs, 100 findings each (500 rows total)
		id := fmt.Sprintf("vj-%03d", i)
		if err := db.PutScanJob(ScanJobRecord{
			ID: id, Scope: "account", Target: "u", State: "done",
			Created: base.Add(time.Duration(i) * time.Second),
		}); err != nil {
			t.Fatal(err)
		}
		batch := make([]alert.Finding, 100)
		if err := db.AppendScanJobFindings(id, 0, batch); err != nil {
			t.Fatal(err)
		}
	}

	// keepJobs is generous (20); the 250-row volume cap is the binding limit.
	// Newest-first: vj-004 (100), vj-003 (200) fit; vj-002 would reach 300 -> prune it and older.
	pruned, err := db.PruneScanJobs(20, 250)
	if err != nil {
		t.Fatal(err)
	}
	if pruned != 3 {
		t.Fatalf("pruned=%d, want 3 (vj-000..vj-002 dropped by volume cap)", pruned)
	}
	for _, id := range []string{"vj-004", "vj-003"} {
		if _, total, _ := db.ListScanJobFindings(id, 0, 0); total != 100 {
			t.Errorf("kept job %s findings=%d, want 100", id, total)
		}
	}
	for _, id := range []string{"vj-002", "vj-001", "vj-000"} {
		if _, ok, _ := db.GetScanJob(id); ok {
			t.Errorf("job %s should be pruned by findings-volume cap", id)
		}
	}
}

func TestPruneScanJobsKeepsNewestOverVolumeCapOnLargeBucket(t *testing.T) {
	db := openTestDB(t)
	base := time.Unix(4000, 0)
	newestID := "large-newest"
	emptyID := "older-empty"
	oldID := "older-small"

	if err := db.PutScanJob(ScanJobRecord{
		ID: newestID, Scope: "account", Target: "u", State: "done",
		Created: base.Add(time.Second),
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.PutScanJob(ScanJobRecord{
		ID: emptyID, Scope: "account", Target: "u", State: "done",
		Created: base.Add(-time.Second),
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.PutScanJob(ScanJobRecord{
		ID: oldID, Scope: "account", Target: "u", State: "done",
		Created: base.Add(-2 * time.Second),
	}); err != nil {
		t.Fatal(err)
	}

	batch := make([]alert.Finding, 1000)
	for seq := 0; seq < 50000; seq += len(batch) {
		if err := db.AppendScanJobFindings(newestID, seq, batch); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.AppendScanJobFinding(oldID, 0, alert.Finding{Check: "webshells"}); err != nil {
		t.Fatal(err)
	}

	pruned, err := db.PruneScanJobs(20, 100)
	if err != nil {
		t.Fatal(err)
	}
	if pruned != 1 {
		t.Fatalf("pruned=%d, want 1", pruned)
	}
	if _, ok, _ := db.GetScanJob(newestID); !ok {
		t.Fatal("newest job was pruned even though it must survive the volume cap")
	}
	if _, total, err := db.ListScanJobFindings(newestID, 0, 1); err != nil || total != 50000 {
		t.Fatalf("newest findings total=%d err=%v, want 50000", total, err)
	}
	if _, ok, _ := db.GetScanJob(emptyID); !ok {
		t.Fatal("empty older job should not be pruned by a findings-volume cap")
	}
	if _, total, err := db.ListScanJobFindings(emptyID, 0, 1); err != nil || total != 0 {
		t.Fatalf("empty findings total=%d err=%v, want 0", total, err)
	}
	if _, ok, _ := db.GetScanJob(oldID); ok {
		t.Fatal("older job should be pruned when newest alone exceeds the volume cap")
	}
	if _, total, err := db.ListScanJobFindings(oldID, 0, 1); err != nil || total != 0 {
		t.Fatalf("old findings total=%d err=%v, want 0", total, err)
	}
}

// TestPruneScanJobsNoOrphanFindings verifies that PruneScanJobs removes all
// finding rows for each pruned job -- no orphan findings survive the prune.
func TestPruneScanJobsNoOrphanFindings(t *testing.T) {
	db := openTestDB(t)
	base := time.Unix(2000, 0)

	// Insert 5 jobs, each with 3 findings.
	for i := 0; i < 5; i++ {
		id := fmt.Sprintf("pj-%03d", i)
		if err := db.PutScanJob(ScanJobRecord{
			ID: id, Scope: "account", Target: "u", State: "done",
			Created: base.Add(time.Duration(i) * time.Second),
		}); err != nil {
			t.Fatal(err)
		}
		for seq := 0; seq < 3; seq++ {
			if err := db.AppendScanJobFinding(id, seq, alert.Finding{Check: "webshells"}); err != nil {
				t.Fatal(err)
			}
		}
	}

	// Prune down to 2; that removes the 3 oldest (pj-000, pj-001, pj-002).
	pruned, err := db.PruneScanJobs(2, 0)
	if err != nil {
		t.Fatal(err)
	}
	if pruned != 3 {
		t.Fatalf("pruned=%d, want 3", pruned)
	}

	// Pruned jobs must have no findings left.
	for i := 0; i < 3; i++ {
		id := fmt.Sprintf("pj-%03d", i)
		fs, total, ferr := db.ListScanJobFindings(id, 0, 10)
		if ferr != nil {
			t.Fatal(ferr)
		}
		if total != 0 || len(fs) != 0 {
			t.Fatalf("orphan findings for pruned %s: total=%d len=%d", id, total, len(fs))
		}
	}

	// Kept jobs must still have all 3 findings.
	for i := 3; i < 5; i++ {
		id := fmt.Sprintf("pj-%03d", i)
		fs, total, ferr := db.ListScanJobFindings(id, 0, 10)
		if ferr != nil {
			t.Fatal(ferr)
		}
		if total != 3 || len(fs) != 3 {
			t.Fatalf("kept job %s findings wrong: total=%d len=%d, want 3", id, total, len(fs))
		}
	}
}

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
	pruned, err := db.PruneScanJobs(20, 0)
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
