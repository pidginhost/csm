package store

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/pidginhost/csm/internal/alert"
)

const (
	scanJobsBucket        = "scan_jobs"
	scanJobFindingsBucket = "scan_job_findings"
)

// ScanJobRecord holds the metadata for a single full-scan job.
type ScanJobRecord struct {
	ID           string    `json:"id"`
	Scope        string    `json:"scope"`
	Target       string    `json:"target"`
	State        string    `json:"state"`
	Created      time.Time `json:"created"`
	Started      time.Time `json:"started,omitempty"`
	Finished     time.Time `json:"finished,omitempty"`
	FilesScanned int       `json:"files_scanned,omitempty"`
	FilesEst     int       `json:"files_est,omitempty"`
	FindingCount int       `json:"finding_count,omitempty"`
	// FindingsStored is how many findings were actually persisted. It equals
	// FindingCount unless the per-job cap truncated the tail, in which case
	// FindingsTruncated is set and the UI shows "showing first N of M".
	FindingsStored    int  `json:"findings_stored,omitempty"`
	FindingsTruncated bool `json:"findings_truncated,omitempty"`
	// Progress fields for scope="all" jobs. Zero/empty for account-scope jobs.
	AccountsTotal  int            `json:"accounts_total,omitempty"`
	AccountsDone   int            `json:"accounts_done,omitempty"`
	CurrentAccount string         `json:"current_account,omitempty"`
	Options        map[string]any `json:"options,omitempty"`
	Error          string         `json:"error,omitempty"`
}

// PutScanJob creates or replaces a scan-job record.
func (db *DB) PutScanJob(rec ScanJobRecord) error {
	val, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("scanjobs: marshal: %w", err)
	}
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(scanJobsBucket))
		if b == nil {
			return fmt.Errorf("bucket %q missing", scanJobsBucket)
		}
		return b.Put([]byte(rec.ID), val)
	})
}

// GetScanJob retrieves a single scan-job record. ok=false when the ID is absent.
func (db *DB) GetScanJob(id string) (ScanJobRecord, bool, error) {
	var rec ScanJobRecord
	var found bool
	err := db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(scanJobsBucket))
		if b == nil {
			return fmt.Errorf("bucket %q missing", scanJobsBucket)
		}
		v := b.Get([]byte(id))
		if v == nil {
			return nil
		}
		found = true
		return json.Unmarshal(v, &rec)
	})
	if err != nil {
		return ScanJobRecord{}, false, err
	}
	return rec, found, nil
}

// ListScanJobs returns all scan-job records ordered newest-first (by Created,
// with ID as a deterministic tiebreaker for equal timestamps).
func (db *DB) ListScanJobs() ([]ScanJobRecord, error) {
	var jobs []ScanJobRecord
	err := db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(scanJobsBucket))
		if b == nil {
			return fmt.Errorf("bucket %q missing", scanJobsBucket)
		}
		return b.ForEach(func(_, v []byte) error {
			var rec ScanJobRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			jobs = append(jobs, rec)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(jobs, func(i, j int) bool {
		ci, cj := jobs[i].Created, jobs[j].Created
		if ci.Equal(cj) {
			return jobs[i].ID > jobs[j].ID
		}
		return ci.After(cj)
	})
	return jobs, nil
}

// findingKey builds the bucket key for a scan-job finding.
// Format: "<job_id>/<zero-padded-seq>" using 8 decimal digits for seq so
// lexicographic order equals insertion order and prefix scans work cleanly.
func findingKey(jobID string, seq int) []byte {
	return []byte(fmt.Sprintf("%s/%08d", jobID, seq))
}

// findingPrefix returns the prefix used to address all findings for a job.
func findingPrefix(jobID string) []byte {
	return []byte(jobID + "/")
}

// AppendScanJobFinding persists a single finding for the given job.
// seq must be unique within the job (caller supplies a monotonic counter).
// Using many small values rather than one growing blob enables pagination
// via cursor seeks without loading the whole finding list into memory.
func (db *DB) AppendScanJobFinding(id string, seq int, f alert.Finding) error {
	return db.AppendScanJobFindings(id, seq, []alert.Finding{f})
}

// AppendScanJobFindings persists a batch of findings for the given job in a
// single write transaction. Keys are seq, seq+1, ... seq+len-1. Batching
// amortizes bbolt's per-commit fsync across the whole slice instead of paying
// one fsync per finding, which dominated the write cost of a large scan.
func (db *DB) AppendScanJobFindings(id string, seq int, findings []alert.Finding) error {
	if len(findings) == 0 {
		return nil
	}
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(scanJobFindingsBucket))
		if b == nil {
			return fmt.Errorf("bucket %q missing", scanJobFindingsBucket)
		}
		for i, f := range findings {
			val, err := json.Marshal(f)
			if err != nil {
				return fmt.Errorf("scanjobs: marshal finding: %w", err)
			}
			if err := b.Put(findingKey(id, seq+i), val); err != nil {
				return err
			}
		}
		return nil
	})
}

// ListScanJobFindings returns a paginated slice of findings for a job.
// total is the count of ALL findings for the job (ignoring offset/limit).
// offset and limit follow the usual slice semantics; limit=0 returns all.
func (db *DB) ListScanJobFindings(id string, offset, limit int) ([]alert.Finding, int, error) {
	prefix := findingPrefix(id)
	var findings []alert.Finding
	total := 0

	err := db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(scanJobFindingsBucket))
		if b == nil {
			return fmt.Errorf("bucket %q missing", scanJobFindingsBucket)
		}
		c := b.Cursor()
		pos := 0
		for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			total++
			if pos >= offset && (limit == 0 || len(findings) < limit) {
				var f alert.Finding
				if err := json.Unmarshal(v, &f); err != nil {
					return err
				}
				findings = append(findings, f)
			}
			pos++
		}
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	return findings, total, nil
}

// PruneScanJobs enforces two independent retention limits and removes the
// finding rows of every pruned job. Returns the number of jobs pruned.
//
//   - keepJobs bounds how many job records are retained.
//   - maxTotalFindings bounds the cumulative finding rows across retained jobs
//     (0 disables the volume cap). A single scan can emit tens of thousands of
//     findings, so a job-count cap alone lets retained findings grow without
//     bound; the volume cap keeps the state file in check.
//
// Jobs are ranked newest-first (Created desc, ID tiebreaker). The newest job is
// always kept even if it alone exceeds the volume cap, so retention never wipes
// the most recent result. The whole operation runs in one bolt.Update so a
// concurrent insert cannot make the decision stale.
func (db *DB) PruneScanJobs(keepJobs, maxTotalFindings int) (int, error) {
	pruned := 0
	err := db.bolt.Update(func(tx *bolt.Tx) error {
		jb := tx.Bucket([]byte(scanJobsBucket))
		if jb == nil {
			return fmt.Errorf("bucket %q missing", scanJobsBucket)
		}
		fb := tx.Bucket([]byte(scanJobFindingsBucket))
		if fb == nil {
			return fmt.Errorf("bucket %q missing", scanJobFindingsBucket)
		}

		// Collect all job records from the bucket (reads are allowed inside Update).
		var jobs []ScanJobRecord
		if err := jb.ForEach(func(_, v []byte) error {
			var rec ScanJobRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			jobs = append(jobs, rec)
			return nil
		}); err != nil {
			return err
		}

		// Sort newest-first: same ordering as ListScanJobs.
		sort.Slice(jobs, func(i, j int) bool {
			ci, cj := jobs[i].Created, jobs[j].Created
			if ci.Equal(cj) {
				return jobs[i].ID > jobs[j].ID
			}
			return ci.After(cj)
		})

		kept := 0
		keptFindings := 0
		var delErr error
		for _, rec := range jobs {
			overJobCount := keepJobs > 0 && kept >= keepJobs
			if overJobCount {
				if delErr = deleteScanJobAndFindings(jb, fb, rec.ID); delErr != nil {
					return delErr
				}
				pruned++
				continue
			}

			jobFindings := 0
			if maxTotalFindings > 0 {
				// Count only far enough to decide whether this job fits. For
				// the newest job, which is always kept, a saturated count is
				// enough to force later non-empty jobs over the volume cap.
				remaining := maxTotalFindings - keptFindings
				if kept == 0 {
					remaining = maxTotalFindings
				}
				if remaining < 0 {
					remaining = 0
				}
				jobFindings = countFindingRowsUpTo(fb, rec.ID, remaining+1)
				if kept >= 1 && keptFindings+jobFindings > maxTotalFindings {
					if delErr = deleteScanJobAndFindings(jb, fb, rec.ID); delErr != nil {
						return delErr
					}
					pruned++
					continue
				}
			}
			kept++
			keptFindings += jobFindings
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return pruned, nil
}

// countFindingRows returns the number of finding rows stored for jobID.
func countFindingRows(fb *bolt.Bucket, jobID string) int {
	return countFindingRowsUpTo(fb, jobID, 0)
}

// countFindingRowsUpTo counts finding rows stored for jobID, stopping early
// after limit rows when limit > 0. The volume-cap retention path only needs to
// know whether a job crosses a threshold, not its exact size above that point.
func countFindingRowsUpTo(fb *bolt.Bucket, jobID string, limit int) int {
	prefix := findingPrefix(jobID)
	n := 0
	c := fb.Cursor()
	for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
		n++
		if limit > 0 && n >= limit {
			break
		}
	}
	return n
}

// deleteScanJobAndFindings removes a job record and all of its finding rows.
// Keys are collected before deletion because the cursor cannot be mutated mid-iteration.
func deleteScanJobAndFindings(jb, fb *bolt.Bucket, jobID string) error {
	if err := jb.Delete([]byte(jobID)); err != nil {
		return err
	}
	prefix := findingPrefix(jobID)
	c := fb.Cursor()
	var stale [][]byte
	for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
		stale = append(stale, append([]byte(nil), k...))
	}
	for _, k := range stale {
		if err := fb.Delete(k); err != nil {
			return err
		}
	}
	return nil
}
