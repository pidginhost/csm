package attackdb

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/store"
	bolt "go.etcd.io/bbolt"
)

// Even when the saved score already matches, an idle record must lose the
// retired scoring state so an older daemon cannot reuse it after rollback.
func TestLoadRewritesLegacyBruteFields(t *testing.T) {
	for _, backend := range []string{"json", "bbolt"} {
		for _, savedScore := range []int{45, 75} {
			t.Run(backend+"/score="+strconv.Itoa(savedScore), func(t *testing.T) {
				const ip = "203.0.113.10"
				now := time.Now().UTC()
				legacy := map[string]any{
					"ip": ip, "first_seen": now, "last_seen": now,
					"event_count": 50, "threat_score": savedScore,
					"attack_counts":            map[string]int{"brute_force": 50},
					"accounts":                 map[string]int{"owner@example.test": 50},
					"brute_force_window_start": now.Add(-time.Hour),
					"brute_force_window_count": 50,
					"brute_force_sustained_at": now.Add(-time.Hour),
				}
				data, err := json.Marshal(legacy)
				if err != nil {
					t.Fatal(err)
				}
				previous := store.Global()
				store.SetGlobal(nil)
				t.Cleanup(func() { store.SetGlobal(previous) })
				db := newTestDB(t)
				var readSaved func() []byte
				if backend == "json" {
					path := filepath.Join(db.dbPath, recordsFile)
					payload, err := json.Marshal(map[string]json.RawMessage{ip: data})
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, payload, 0600); err != nil {
						t.Fatal(err)
					}
					readSaved = func() []byte {
						raw, err := os.ReadFile(path)
						if err != nil {
							t.Fatal(err)
						}
						var records map[string]json.RawMessage
						if err := json.Unmarshal(raw, &records); err != nil {
							t.Fatal(err)
						}
						return records[ip]
					}
				} else {
					dir := t.TempDir()
					sdb, err := store.Open(dir)
					if err != nil {
						t.Fatal(err)
					}
					path := sdb.Path()
					if closeErr := sdb.Close(); closeErr != nil {
						t.Fatal(closeErr)
					}
					rawDB, err := bolt.Open(path, 0600, nil)
					if err != nil {
						t.Fatal(err)
					}
					defer func() { _ = rawDB.Close() }()
					if writeErr := rawDB.Update(func(tx *bolt.Tx) error {
						return tx.Bucket([]byte("attacks:records")).Put([]byte(ip), data)
					}); writeErr != nil {
						t.Fatal(writeErr)
					}
					if closeErr := rawDB.Close(); closeErr != nil {
						t.Fatal(closeErr)
					}
					sdb, err = store.Open(dir)
					if err != nil {
						t.Fatal(err)
					}
					defer func() { _ = sdb.Close() }()
					store.SetGlobal(sdb)
					readSaved = func() []byte {
						if err := sdb.Close(); err != nil {
							t.Fatal(err)
						}
						rawDB, err := bolt.Open(path, 0600, &bolt.Options{ReadOnly: true})
						if err != nil {
							t.Fatal(err)
						}
						defer func() { _ = rawDB.Close() }()
						var raw []byte
						if err := rawDB.View(func(tx *bolt.Tx) error {
							raw = append([]byte(nil), tx.Bucket([]byte("attacks:records")).Get([]byte(ip))...)
							return nil
						}); err != nil {
							t.Fatal(err)
						}
						return raw
					}
				}
				db.load()
				rec := db.LookupIP(ip)
				if rec == nil || rec.ThreatScore != 45 || rec.EventCount != 50 || rec.Accounts["owner@example.test"] != 50 {
					t.Fatalf("legacy record changed scoring evidence: %+v", rec)
				}
				if err := db.Flush(); err != nil {
					t.Fatal(err)
				}
				var saved map[string]json.RawMessage
				if err := json.Unmarshal(readSaved(), &saved); err != nil {
					t.Fatal(err)
				}
				for _, key := range []string{"brute_force_window_start", "brute_force_window_count", "brute_force_sustained_at"} {
					if _, ok := saved[key]; ok {
						t.Errorf("retired field %s survived upgrade flush", key)
					}
				}
				var score int
				if err := json.Unmarshal(saved["threat_score"], &score); err != nil || score != 45 {
					t.Fatalf("saved score = %d, error = %v, want 45", score, err)
				}
			})
		}
	}
}
