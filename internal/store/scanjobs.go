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
	ID           string         `json:"id"`
	Scope        string         `json:"scope"`
	Target       string         `json:"target"`
	State        string         `json:"state"`
	Created      time.Time      `json:"created"`
	Started      time.Time      `json:"started,omitempty"`
	Finished     time.Time      `json:"finished,omitempty"`
	FilesScanned int            `json:"files_scanned,omitempty"`
	FilesEst     int            `json:"files_est,omitempty"`
	FindingCount int            `json:"finding_count,omitempty"`
	Options      map[string]any `json:"options,omitempty"`
	Error        string         `json:"error,omitempty"`
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
	val, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("scanjobs: marshal finding: %w", err)
	}
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(scanJobFindingsBucket))
		if b == nil {
			return fmt.Errorf("bucket %q missing", scanJobFindingsBucket)
		}
		return b.Put(findingKey(id, seq), val)
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

// PruneScanJobs removes the oldest jobs beyond the newest keep, together with
// all their finding rows. Returns the number of jobs pruned.
// Jobs are ranked by Created descending; ID is the tiebreaker so the ordering
// is deterministic when two jobs share the same timestamp.
// The entire operation (read + sort + delete) runs inside a single bolt.Update
// so no concurrent insert can make the pruning decision stale.
func (db *DB) PruneScanJobs(keep int) (int, error) {
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

		if len(jobs) <= keep {
			return nil
		}

		// Sort newest-first: same ordering as ListScanJobs.
		sort.Slice(jobs, func(i, j int) bool {
			ci, cj := jobs[i].Created, jobs[j].Created
			if ci.Equal(cj) {
				return jobs[i].ID > jobs[j].ID
			}
			return ci.After(cj)
		})

		toDelete := jobs[keep:] // oldest entries are at the tail
		var delErr error
		for _, rec := range toDelete {
			if delErr = jb.Delete([]byte(rec.ID)); delErr != nil {
				return delErr
			}
			// Prefix-sweep all finding rows for this job.
			// Collect keys first (cursor cannot be mutated during iteration).
			prefix := findingPrefix(rec.ID)
			c := fb.Cursor()
			var stale [][]byte
			for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
				stale = append(stale, append([]byte(nil), k...))
			}
			for _, k := range stale {
				if delErr = fb.Delete(k); delErr != nil {
					return delErr
				}
			}
			pruned++
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return pruned, nil
}
