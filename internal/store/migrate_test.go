package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
)

func TestMigrateHistoryJSONL(t *testing.T) {
	dir := t.TempDir()

	findings := []alert.Finding{
		{Severity: alert.Critical, Check: "webshell", Message: "test1", Timestamp: time.Now().Add(-2 * time.Minute)},
		{Severity: alert.High, Check: "brute_force", Message: "test2", Timestamp: time.Now().Add(-1 * time.Minute)},
		{Severity: alert.Warning, Check: "reputation", Message: "test3", Timestamp: time.Now()},
	}
	histPath := filepath.Join(dir, "history.jsonl")
	f, err := os.Create(histPath)
	if err != nil {
		t.Fatal(err)
	}
	enc := json.NewEncoder(f)
	for _, finding := range findings {
		if err := enc.Encode(finding); err != nil {
			t.Fatal(err)
		}
	}
	f.Close()

	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	results, total := db.ReadHistory(10, 0)
	if total != 3 {
		t.Errorf("total = %d, want 3", total)
	}
	if len(results) != 3 {
		t.Fatalf("results = %d, want 3", len(results))
	}

	if _, err := os.Stat(histPath + ".bak"); err != nil {
		t.Errorf("expected .bak file: %v", err)
	}
	if _, err := os.Stat(histPath); err == nil {
		t.Error("expected original file to be renamed to .bak")
	}
}

func TestMigrateIdempotent(t *testing.T) {
	dir := t.TempDir()

	histPath := filepath.Join(dir, "history.jsonl")
	f, err := os.Create(histPath)
	if err != nil {
		t.Fatal(err)
	}
	enc := json.NewEncoder(f)
	if err := enc.Encode(alert.Finding{Severity: alert.Warning, Check: "test", Message: "msg", Timestamp: time.Now()}); err != nil {
		t.Fatal(err)
	}
	f.Close()

	db1, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	db1.Close()

	db2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()

	_, total := db2.ReadHistory(10, 0)
	if total != 1 {
		t.Errorf("total after second open = %d, want 1 (no duplicates)", total)
	}
}

func TestMigratePermanentTxt(t *testing.T) {
	dir := t.TempDir()

	threatDir := filepath.Join(dir, "threat_db")
	if err := os.MkdirAll(threatDir, 0755); err != nil {
		t.Fatal(err)
	}
	content := "1.2.3.4 # brute force [2026-04-01]\n5.6.7.8 # webshell [2026-03-25]\n"
	if err := os.WriteFile(filepath.Join(threatDir, "permanent.txt"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	_, ok := db.GetPermanentBlock("1.2.3.4")
	if !ok {
		t.Error("expected 1.2.3.4 to be imported")
	}
	_, ok = db.GetPermanentBlock("5.6.7.8")
	if !ok {
		t.Error("expected 5.6.7.8 to be imported")
	}
}
