package store

import (
	"encoding/json"
	"sort"

	bolt "go.etcd.io/bbolt"

	"github.com/pidginhost/csm/internal/incident"
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
func (db *DB) ListIncidents() ([]incident.Incident, error) {
	var out []incident.Incident
	err := db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(incidentsBucket))
		return b.ForEach(func(_, v []byte) error {
			var inc incident.Incident
			if err := json.Unmarshal(v, &inc); err != nil {
				return err
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
