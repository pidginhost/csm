package state

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMigrateStateDir_CopiesWhenNewEmpty(t *testing.T) {
	root := t.TempDir()
	old := filepath.Join(root, "old")
	new_ := filepath.Join(root, "new")
	mustMk(t, old)
	must(t, os.WriteFile(filepath.Join(old, "csm.db"), []byte("db-bytes"), 0o600))
	must(t, os.WriteFile(filepath.Join(old, "state.json"), []byte("{}"), 0o600))

	migrated, err := MigrateStateDir(old, new_)
	if err != nil {
		t.Fatal(err)
	}
	if !migrated {
		t.Fatal("expected migrated=true")
	}
	for _, f := range []string{"csm.db", "state.json"} {
		if _, err := os.Stat(filepath.Join(new_, f)); err != nil {
			t.Fatalf("expected %s in new dir: %v", f, err)
		}
	}
}

func TestMigrateStateDir_NoopWhenNewHasContent(t *testing.T) {
	root := t.TempDir()
	old := filepath.Join(root, "old")
	new_ := filepath.Join(root, "new")
	mustMk(t, old)
	mustMk(t, new_)
	must(t, os.WriteFile(filepath.Join(old, "csm.db"), []byte("OLD"), 0o600))
	must(t, os.WriteFile(filepath.Join(new_, "csm.db"), []byte("NEW"), 0o600))

	migrated, err := MigrateStateDir(old, new_)
	if err != nil {
		t.Fatal(err)
	}
	if migrated {
		t.Fatal("expected migrated=false (new dir non-empty)")
	}
	got, _ := os.ReadFile(filepath.Join(new_, "csm.db"))
	if string(got) != "NEW" {
		t.Fatalf("expected NEW preserved, got %s", got)
	}
}

func TestMigrateStateDir_IgnoresActiveLockFile(t *testing.T) {
	root := t.TempDir()
	old := filepath.Join(root, "old")
	new_ := filepath.Join(root, "new")
	mustMk(t, old)
	mustMk(t, new_)
	must(t, os.WriteFile(filepath.Join(old, "csm.db"), []byte("db-bytes"), 0o600))
	must(t, os.WriteFile(filepath.Join(old, lockFileName), []byte("stale lock"), 0o600))
	must(t, os.WriteFile(filepath.Join(new_, lockFileName), []byte("active lock"), 0o600))

	migrated, err := MigrateStateDir(old, new_)
	if err != nil {
		t.Fatal(err)
	}
	if !migrated {
		t.Fatal("expected migrated=true when new dir contains only the active lock")
	}
	if got, err := os.ReadFile(filepath.Join(new_, lockFileName)); err != nil {
		t.Fatal(err)
	} else if string(got) != "active lock" {
		t.Fatalf("active lock file was overwritten with %q", got)
	}
	if got, err := os.ReadFile(filepath.Join(new_, "csm.db")); err != nil {
		t.Fatal(err)
	} else if string(got) != "db-bytes" {
		t.Fatalf("migrated db = %q", got)
	}
}

func TestMigrateStateDir_OldOnlyLockFileIsNoop(t *testing.T) {
	root := t.TempDir()
	old := filepath.Join(root, "old")
	new_ := filepath.Join(root, "new")
	mustMk(t, old)
	must(t, os.WriteFile(filepath.Join(old, lockFileName), []byte("stale lock"), 0o600))

	migrated, err := MigrateStateDir(old, new_)
	if err != nil {
		t.Fatal(err)
	}
	if migrated {
		t.Fatal("expected migrated=false when old dir only contains a stale lock")
	}
}

func TestMigrateStateDir_NoopWhenOldMissing(t *testing.T) {
	root := t.TempDir()
	old := filepath.Join(root, "old-absent")
	new_ := filepath.Join(root, "new")
	mustMk(t, new_)

	migrated, err := MigrateStateDir(old, new_)
	if err != nil {
		t.Fatal(err)
	}
	if migrated {
		t.Fatal("expected migrated=false (old dir absent)")
	}
}

func TestMigrateStateDir_SamePathIsNoop(t *testing.T) {
	root := t.TempDir()
	migrated, err := MigrateStateDir(root, root)
	if err != nil {
		t.Fatal(err)
	}
	if migrated {
		t.Fatal("expected migrated=false (same path)")
	}
}

func mustMk(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o700); err != nil {
		t.Fatal(err)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
