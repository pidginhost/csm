package atomicio

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicWriteJSON_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	want := map[string]any{"k": "v", "n": float64(42)}
	if err := AtomicWriteJSON(path, 0o600, want); err != nil {
		t.Fatalf("AtomicWriteJSON: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["k"] != "v" || got["n"] != float64(42) {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("tmp file should be removed after rename, stat err=%v", err)
	}
}

func TestAtomicWriteJSON_EnforcesMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "s.json")
	if err := AtomicWriteJSON(path, 0o600, map[string]int{"x": 1}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("mode = %o, want 0o600", mode)
	}
}

func TestAtomicWriteJSON_ReplacesStaleTmpWithRequestedMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "s.json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(`{"old":true}`), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := AtomicWriteJSON(path, 0o600, map[string]int{"x": 1}); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("mode = %o, want 0o600", mode)
	}
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Errorf("stale tmp should be removed after successful write, stat err=%v", err)
	}
}

func TestAtomicWriteJSON_MarshalError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	bad := func() {} // funcs are not JSON-marshalable
	if err := AtomicWriteJSON(path, 0o600, bad); err == nil {
		t.Fatal("expected marshal error")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("target file should not exist on marshal failure, err=%v", err)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("tmp file should not exist on marshal failure, err=%v", err)
	}
}
