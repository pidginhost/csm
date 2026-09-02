package state

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Open used to copy state.json over state.json.bak before parsing it, so a
// corrupt state file destroyed the last good backup and every finding became
// "new" again on the next cycle. The backup is written only after a
// successful parse, and a corrupt file falls back to that backup.
func TestOpenKeepsBackupAndFallsBackWhenStateCorrupt(t *testing.T) {
	dir := t.TempDir()
	good := `{"k1":{"hash":"h1","first_seen":"2026-09-01T00:00:00Z","last_seen":"2026-09-01T00:00:00Z","alert_sent":"2026-09-01T00:00:00Z","is_baseline":false}}`
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.entries) != 1 {
		t.Fatalf("entries after good open = %d, want 1", len(s.entries))
	}
	_ = s.Close()
	bak, err := os.ReadFile(filepath.Join(dir, "state.json.bak"))
	if err != nil || string(bak) != good {
		t.Fatalf("backup after a good parse = %q, %v; want the parsed file", bak, err)
	}

	if err = os.WriteFile(filepath.Join(dir, "state.json"), []byte(`{"k1":{"hash":`), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if len(s.entries) != 1 || s.entries["k1"] == nil || s.entries["k1"].Hash != "h1" {
		t.Fatalf("corrupt state did not fall back to the backup: entries=%v", s.entries)
	}
	bak, err = os.ReadFile(filepath.Join(dir, "state.json.bak"))
	if err != nil || string(bak) != good {
		t.Fatalf("backup overwritten by the corrupt file: %q, %v", bak, err)
	}
	_ = time.Now()
}
