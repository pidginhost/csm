package store

import (
	"encoding/json"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/pidginhost/csm/internal/incident"
	csmlog "github.com/pidginhost/csm/internal/log"
)

const incidentsBucket = "incidents"

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
		found = true
		return json.Unmarshal(v, &inc)
	})
	return inc, found, err
}

// ListIncidents returns every stored incident, newest UpdatedAt first.
// Corrupt rows (torn writes, bit-flips, schema-mismatched legacy
// records) are skipped with a warn log so the rest of the bucket is
// still restorable. Aborting on the first bad row would erase every
// open incident from memory at daemon startup.
func (db *DB) ListIncidents() ([]incident.Incident, error) {
	var out []incident.Incident
	err := db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(incidentsBucket))
		return b.ForEach(func(k, v []byte) error {
			var inc incident.Incident
			if err := json.Unmarshal(v, &inc); err != nil {
				csmlog.Warn("store: skipping corrupt incident row",
					"bucket", incidentsBucket, "id", string(k), "err", err)
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

// CompactIncidents removes resolved/dismissed incidents whose UpdatedAt
// is older than now-retention. Open and Contained incidents are never
// pruned regardless of age. Returns the number of records removed.
func (db *DB) CompactIncidents(now time.Time, retention time.Duration) (int, error) {
	cutoff := now.Add(-retention)
	pruned := 0
	err := db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(incidentsBucket))
		var toDelete [][]byte
		err := b.ForEach(func(k, v []byte) error {
			var inc incident.Incident
			if err := json.Unmarshal(v, &inc); err != nil {
				csmlog.Warn("store: skipping corrupt incident row",
					"bucket", incidentsBucket, "id", string(k), "err", err)
				return nil
			}
			if inc.Status != incident.StatusResolved && inc.Status != incident.StatusDismissed {
				return nil
			}
			if inc.UpdatedAt.Before(cutoff) {
				toDelete = append(toDelete, append([]byte(nil), k...))
			}
			return nil
		})
		if err != nil {
			return err
		}
		for _, k := range toDelete {
			if err := b.Delete(k); err != nil {
				return err
			}
			pruned++
		}
		return nil
	})
	return pruned, err
}
