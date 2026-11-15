package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestMigrateAttackRecordsCommitsOneBatch(t *testing.T) {
	for _, refuse := range []bool{false, true} {
		name := "commit"
		if refuse {
			name = "rollback"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			db, openErr := Open(dir)
			if openErr != nil {
				t.Fatal(openErr)
			}
			defer func() { _ = db.Close() }()
			records := map[string]IPRecord{
				"192.0.2.1":    {IP: "192.0.2.1", EventCount: 1},
				"198.51.100.2": {IP: "198.51.100.2", EventCount: 2},
				"203.0.113.3":  {IP: "203.0.113.3", EventCount: 3},
			}
			if refuse {
				records["192.0.2.9"] = IPRecord{IP: ""}
			}
			data, marshalErr := json.Marshal(records)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			if err := os.Mkdir(filepath.Join(dir, "attack_db"), 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "attack_db", "records.json")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			before := committedTx(t, db)
			migrationErr := db.migrateAttackDB(dir)
			if refuse {
				if migrationErr == nil {
					t.Fatal("migration accepted an invalid record")
				}
				if got := committedTx(t, db); got != before {
					t.Fatalf("failed migration committed %d transactions", got-before)
				}
				if saved := db.LoadAllIPRecords(); len(saved) != 0 {
					t.Fatalf("failed migration persisted partial records: %v", saved)
				}
				if got, err := os.ReadFile(path); err != nil || string(got) != string(data) {
					t.Fatalf("failed migration did not preserve source: %v", err)
				}
				if _, err := os.Stat(path + ".bak"); !os.IsNotExist(err) {
					t.Fatalf("failed migration created backup: %v", err)
				}
				return
			}
			if migrationErr != nil {
				t.Fatal(migrationErr)
			}
			if got := committedTx(t, db) - before; got != 1 {
				t.Fatalf("migration committed %d transactions, want 1", got)
			}
			saved := db.LoadAllIPRecords()
			if len(saved) != len(records) {
				t.Fatalf("persisted %d records, want %d", len(saved), len(records))
			}
			for ip, rec := range records {
				if got := saved[ip]; got == nil || got.EventCount != rec.EventCount {
					t.Fatalf("migrated record %s = %+v", ip, got)
				}
			}
			if got, err := os.ReadFile(path + ".bak"); err != nil || string(got) != string(data) {
				t.Fatalf("committed migration did not preserve backup: %v", err)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("committed migration left source: %v", err)
			}
		})
	}
}
