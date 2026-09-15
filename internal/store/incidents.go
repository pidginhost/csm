package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/pidginhost/csm/internal/incident"
	csmlog "github.com/pidginhost/csm/internal/log"
)

const incidentsBucket = "incidents"

// Bound rows inspected as well as deleted: retained or corrupt rows must
// not turn a sweep into one long transaction on bbolt's shared writer.
const incidentCompactionBatchSize = 256

// SaveIncident persists an incident, overwriting any prior record with
// the same ID. Caller is responsible for setting UpdatedAt before
// invoking; this method just writes.
func (db *DB) SaveIncident(inc incident.Incident) error {
	data, err := json.Marshal(inc)
	if err != nil {
		return err
	}
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(incidentsBucket))
		return b.Put([]byte(inc.ID), data)
	})
}

// GetIncident returns (incident, true, nil) if found, (zero, false, nil)
// if not, (zero, false, err) on store error.
func (db *DB) GetIncident(id string) (incident.Incident, bool, error) {
	var (
		inc   incident.Incident
		found bool
	)
	err := db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(incidentsBucket))
		v := b.Get([]byte(id))
		if v == nil {
			return nil
		}
		if err := json.Unmarshal(v, &inc); err != nil {
			return err
		}
		if err := validateIncidentRow(id, inc); err != nil {
			return err
		}
		found = true
		return nil
	})
	return inc, found, err
}

// ListIncidents returns every stored incident, newest UpdatedAt first.
// Rows that fail JSON decode or storage invariants are skipped with a
// warn log so the rest of the bucket is still restorable. Aborting on
// the first bad row would leave the daemon with no restored incidents
// at startup.
func (db *DB) ListIncidents() ([]incident.Incident, error) {
	var out []incident.Incident
	err := db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(incidentsBucket))
		return b.ForEach(func(k, v []byte) error {
			inc, ok := decodeIncidentRow(k, v)
			if !ok {
				return nil
			}
			out = append(out, inc)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].UpdatedAt.After(out[j].UpdatedAt)
	})
	return out, nil
}

// ListIncidentsByStatus returns incidents matching the requested status,
// newest UpdatedAt first.
func (db *DB) ListIncidentsByStatus(status incident.Status) ([]incident.Incident, error) {
	all, err := db.ListIncidents()
	if err != nil {
		return nil, err
	}
	out := all[:0]
	for _, inc := range all {
		if inc.Status == status {
			out = append(out, inc)
		}
	}
	return out, nil
}

// CompactIncidents removes resolved/dismissed incidents that have outlived
// their retention. Open and Contained incidents are never pruned regardless
// of age. Each transaction inspects a bounded batch, letting other store
// writers run during a large backlog. On error the count includes only
// committed deletions from preceding batches.
func (db *DB) CompactIncidents(now time.Time, retention incident.ClosedRetention) (int, error) {
	pruned := 0
	var next []byte
	for {
		n, resume, err := db.compactIncidentsBatch(now, retention, next)
		pruned += n
		if err != nil || resume == nil {
			return pruned, err
		}
		next = resume
	}
}

// The resume key is inclusive and copied before the transaction ends.
// Selection and deletion share a transaction so a concurrent operator
// update cannot be deleted using a stale retention decision.
func (db *DB) compactIncidentsBatch(now time.Time, retention incident.ClosedRetention, start []byte) (int, []byte, error) {
	var next []byte
	var toDelete [][]byte
	err := db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(incidentsBucket))
		cursor := b.Cursor()
		k, v := cursor.First()
		if start != nil {
			k, v = cursor.Seek(start)
		}
		for scanned := 0; k != nil && scanned < incidentCompactionBatchSize; scanned++ {
			inc, ok := decodeIncidentRow(k, v)
			if ok && retention.Expired(inc, now) {
				toDelete = append(toDelete, append([]byte(nil), k...))
			}
			k, v = cursor.Next()
		}
		if k != nil {
			next = append([]byte(nil), k...)
		}
		for _, k := range toDelete {
			if err := b.Delete(k); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return 0, nil, err
	}
	return len(toDelete), next, nil
}

func decodeIncidentRow(k, v []byte) (incident.Incident, bool) {
	rowID := string(k)
	var inc incident.Incident
	if err := json.Unmarshal(v, &inc); err != nil {
		warnSkippedIncidentRow(rowID, err)
		return incident.Incident{}, false
	}
	if err := validateIncidentRow(rowID, inc); err != nil {
		warnSkippedIncidentRow(rowID, err)
		return incident.Incident{}, false
	}
	return inc, true
}

func validateIncidentRow(rowID string, inc incident.Incident) error {
	if rowID == "" {
		return errors.New("empty row key")
	}
	if inc.ID == "" {
		return errors.New("empty incident id")
	}
	if inc.ID != rowID {
		return fmt.Errorf("incident id %q does not match row key %q", inc.ID, rowID)
	}
	if !incidentStatusValid(inc.Status) {
		return fmt.Errorf("invalid status %q", inc.Status)
	}
	return nil
}

func incidentStatusValid(status incident.Status) bool {
	switch status {
	case incident.StatusOpen, incident.StatusContained, incident.StatusResolved, incident.StatusDismissed:
		return true
	default:
		return false
	}
}

func warnSkippedIncidentRow(rowID string, err error) {
	csmlog.Warn("store: skipping corrupt incident row",
		"bucket", incidentsBucket, "id", rowID, "err", err)
}
