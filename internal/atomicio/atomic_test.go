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

func TestAtomicWrite_RoundTripAndMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "raw.yaml")
	want := []byte("key: value\n")
	if err := AtomicWrite(path, 0o600, want); err != nil {
		t.Fatalf("AtomicWrite: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("content = %q, want %q", got, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("mode = %o, want 0o600", mode)
	}
}

func TestAtomicWrite_LeavesSiblingTmpFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "raw.yaml")
	tmp := path + ".tmp"
	tmpBody := []byte("operator scratch\n")
	if err := os.WriteFile(tmp, tmpBody, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := AtomicWrite(path, 0o600, []byte("key: value\n")); err != nil {
		t.Fatalf("AtomicWrite: %v", err)
	}

	got, err := os.ReadFile(tmp)
	if err != nil {
		t.Fatalf("read sibling tmp: %v", err)
	}
	if string(got) != string(tmpBody) {
		t.Fatalf("sibling tmp = %q, want %q", got, tmpBody)
	}
}

// A replaced destination must come from a rename, never an in-place
// truncate+write: a crash mid-write would otherwise leave a torn file.
func TestAtomicWrite_ReplacesViaRename(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "raw.yaml")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if werr := AtomicWrite(path, 0o600, []byte("new")); werr != nil {
		t.Fatal(werr)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(before, after) {
		t.Fatal("destination was rewritten in place, want rename of a new inode")
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
