package store

import (
	"encoding/json"
	"time"

	bolt "go.etcd.io/bbolt"
)

// AuditResult represents a single hardening check result.
type AuditResult struct {
	Category string `json:"category"`
	Name     string `json:"name"`
	Title    string `json:"title"`
	Status   string `json:"status"`
	Message  string `json:"message"`
	Fix      string `json:"fix,omitempty"`
	// AutoFix describes the change CSM makes when the operator applies
	// this check from the hardening page. Empty means the fix is manual.
	AutoFix string `json:"auto_fix,omitempty"`
	// AutoFixCaution says what applying the fix can break on a working
	// host; the hardening page leaves such fixes unticked.
	AutoFixCaution string `json:"auto_fix_caution,omitempty"`
	// UndoAvailable says the root worker kept a record of what CSM's last
	// apply of this fix changed, so the hardening page offers to undo it.
	// It is worked out when a report is served and never saved.
	UndoAvailable bool `json:"undo_available,omitempty"`
}

// AuditReport is the full result of a hardening audit run.
type AuditReport struct {
	Timestamp  time.Time     `json:"timestamp,omitzero"`
	ServerType string        `json:"server_type"`
	Results    []AuditResult `json:"results"`
	Score      int           `json:"score"`
	Total      int           `json:"total"`
}

const hardeningReportKey = "hardening:report"

// SaveHardeningReport persists the latest audit report in the meta bucket.
func (db *DB) SaveHardeningReport(report *AuditReport) error {
	data, err := json.Marshal(report)
	if err != nil {
		return err
	}
	return db.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("meta")).Put([]byte(hardeningReportKey), data)
	})
}

// LoadHardeningReport retrieves the latest audit report from the meta bucket.
// Returns a zero-value report (nil Results) if no report has been saved yet.
func (db *DB) LoadHardeningReport() (*AuditReport, error) {
	var report AuditReport
	err := db.bolt.View(func(tx *bolt.Tx) error {
		v := tx.Bucket([]byte("meta")).Get([]byte(hardeningReportKey))
		if v == nil {
			return nil
		}
		return json.Unmarshal(v, &report)
	})
	return &report, err
}
