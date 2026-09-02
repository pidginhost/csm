package store

import (
	"testing"
	"time"
)

// Retention ranks jobs by creation time only. A burst of queued jobs is
// older than the job that just completed, so the first completion's prune
// deleted the jobs still waiting to run (and the one running): the scheduler
// then found "scan job missing at run time" and skipped them. Jobs that have
// not finished are never retention candidates.
func TestPruneScanJobsKeepsQueuedAndRunningJobs(t *testing.T) {
	db := openTestDB(t)
	base := time.Unix(4000, 0)
	for i, rec := range []ScanJobRecord{
		{ID: "old-done", State: "done"},
		{ID: "waiting", State: "queued"},
		{ID: "active", State: "running"},
		{ID: "new-done", State: "done"},
	} {
		rec.Scope, rec.Target = "account", "u"
		rec.Created = base.Add(time.Duration(i) * time.Second)
		if err := db.PutScanJob(rec); err != nil {
			t.Fatal(err)
		}
	}

	pruned, err := db.PruneScanJobs(1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if pruned != 1 {
		t.Fatalf("pruned = %d, want only the older finished job", pruned)
	}
	for _, id := range []string{"waiting", "active", "new-done"} {
		if _, ok, _ := db.GetScanJob(id); !ok {
			t.Errorf("job %s was pruned", id)
		}
	}
	if _, ok, _ := db.GetScanJob("old-done"); ok {
		t.Error("older finished job survived retention")
	}
}
