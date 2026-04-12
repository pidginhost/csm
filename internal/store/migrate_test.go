package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
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
		if eerr := enc.Encode(finding); eerr != nil {
			t.Fatal(eerr)
		}
	}
	f.Close()

	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

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
	if eerr := enc.Encode(alert.Finding{Severity: alert.Warning, Check: "test", Message: "msg", Timestamp: time.Now()}); eerr != nil {
		t.Fatal(eerr)
	}
	f.Close()

	db1, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	_ = db1.Close()

	db2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db2.Close() }()

	_, total := db2.ReadHistory(10, 0)
	if total != 1 {
		t.Errorf("total after second open = %d, want 1 (no duplicates)", total)
	}
}

func TestMigrateAttackDBRecordsAndEvents(t *testing.T) {
	dir := t.TempDir()
	atkDir := filepath.Join(dir, "attack_db")
	_ = os.MkdirAll(atkDir, 0700)

	// Write records.json
	records := map[string]interface{}{
		"203.0.113.5": map[string]interface{}{
			"ip": "203.0.113.5", "event_count": 10, "threat_score": 50,
			"first_seen": time.Now().Add(-1 * time.Hour).Format(time.RFC3339),
			"last_seen":  time.Now().Format(time.RFC3339),
			"attacks":    map[string]int{"brute_force": 5},
			"accounts":   map[string]int{"alice": 3},
		},
	}
	data, _ := json.Marshal(records)
	_ = os.WriteFile(filepath.Join(atkDir, "records.json"), data, 0600)

	// Write events.jsonl
	event := map[string]interface{}{
		"ip": "203.0.113.5", "type": "brute_force", "check": "ssh_auth",
		"message": "test", "timestamp": time.Now().Format(time.RFC3339),
	}
	eventData, _ := json.Marshal(event)
	_ = os.WriteFile(filepath.Join(atkDir, "events.jsonl"), append(eventData, '\n'), 0600)

	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	loaded := db.LoadAllIPRecords()
	if len(loaded) != 1 {
		t.Errorf("got %d records, want 1", len(loaded))
	}
	if _, err := os.Stat(filepath.Join(atkDir, "records.json.bak")); err != nil {
		t.Error("records.json should be renamed to .bak")
	}
}

func TestMigrateFirewallState(t *testing.T) {
	dir := t.TempDir()
	fwDir := filepath.Join(dir, "firewall")
	_ = os.MkdirAll(fwDir, 0700)

	state := map[string]interface{}{
		"blocked": []map[string]interface{}{
			{"ip": "203.0.113.5", "reason": "brute", "blocked_at": time.Now().Format(time.RFC3339),
				"expires_at": time.Now().Add(1 * time.Hour).Format(time.RFC3339)},
		},
		"allowed": []map[string]interface{}{
			{"ip": "10.0.0.1", "reason": "infra"},
		},
		"blocked_nets": []map[string]interface{}{
			{"cidr": "192.168.0.0/16", "reason": "test", "blocked_at": time.Now().Format(time.RFC3339)},
		},
		"port_allowed": []map[string]interface{}{
			{"ip": "10.0.0.2", "port": 3306, "proto": "tcp", "reason": "mysql"},
		},
	}
	data, _ := json.Marshal(state)
	_ = os.WriteFile(filepath.Join(fwDir, "state.json"), data, 0600)

	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	fwState := db.LoadFirewallState()
	if len(fwState.Blocked) != 1 {
		t.Errorf("blocked: got %d, want 1", len(fwState.Blocked))
	}
	if len(fwState.Allowed) != 1 {
		t.Errorf("allowed: got %d, want 1", len(fwState.Allowed))
	}
}

func TestMigrateReputationCache(t *testing.T) {
	dir := t.TempDir()
	cache := map[string]interface{}{
		"entries": map[string]interface{}{
			"203.0.113.5": map[string]interface{}{
				"score": 75, "category": "DC",
				"checked_at": time.Now().Format(time.RFC3339),
			},
		},
	}
	data, _ := json.Marshal(cache)
	_ = os.WriteFile(filepath.Join(dir, "reputation_cache.json"), data, 0600)

	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	all := db.AllReputation()
	if len(all) != 1 {
		t.Errorf("got %d entries, want 1", len(all))
	}
}

func TestMigrateWhitelistTxt(t *testing.T) {
	dir := t.TempDir()
	threatDir := filepath.Join(dir, "threat_db")
	_ = os.MkdirAll(threatDir, 0700)

	expires := time.Now().Add(1 * time.Hour).Format(time.RFC3339)
	_ = os.WriteFile(filepath.Join(threatDir, "whitelist.txt"),
		[]byte("10.0.0.1 permanent\n10.0.0.2 expires="+expires+"\n"), 0600)

	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	wl := db.ListWhitelist()
	if len(wl) != 2 {
		t.Errorf("got %d whitelist, want 2", len(wl))
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
	defer func() { _ = db.Close() }()

	_, ok := db.GetPermanentBlock("1.2.3.4")
	if !ok {
		t.Error("expected 1.2.3.4 to be imported")
	}
	_, ok = db.GetPermanentBlock("5.6.7.8")
	if !ok {
		t.Error("expected 5.6.7.8 to be imported")
	}
}
