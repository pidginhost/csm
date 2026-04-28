package checks

import (
	"os"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/store"
)

// withDBObjectsTempStore opens a fresh bbolt store and installs it
// as the global. The package's other test files already define
// `withTempStore`, but its impl does not call SetGlobal; rather
// than retroactively change a helper used by many tests, we add a
// distinct one for this suite.
func withDBObjectsTempStore(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	prev := store.Global()
	store.SetGlobal(db)
	t.Cleanup(func() {
		store.SetGlobal(prev)
		_ = db.Close()
	})
	return db
}

func TestDBDropObjectRejectsInvalidKind(t *testing.T) {
	res := DBDropObject("alice", "alice_wp", "view", "v1", true)
	if res.Success {
		t.Errorf("expected failure for invalid kind, got success")
	}
	if !strings.Contains(res.Message, "Invalid object kind") {
		t.Errorf("message = %q, want Invalid object kind", res.Message)
	}
}

func TestDBDropObjectRejectsBadSchemaName(t *testing.T) {
	res := DBDropObject("alice", "bad;schema", "trigger", "trg", true)
	if res.Success {
		t.Errorf("expected failure for bad schema, got success")
	}
	if !strings.Contains(strings.ToLower(res.Message), "invalid schema") {
		t.Errorf("message = %q, want Invalid schema", res.Message)
	}
}

func TestDBDropObjectRejectsBadObjectName(t *testing.T) {
	res := DBDropObject("alice", "alice_wp", "trigger", "bad`name", true)
	if res.Success {
		t.Errorf("expected failure for bad name, got success")
	}
	if !strings.Contains(strings.ToLower(res.Message), "invalid object name") {
		t.Errorf("message = %q", res.Message)
	}
}

func TestDBDropObjectRejectsUnknownSchemaForAccount(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			return nil, nil // no wp-config.php found
		},
	})
	res := DBDropObject("alice", "alice_wp", "trigger", "trg_audit", true)
	if res.Success {
		t.Errorf("expected failure when schema is unknown")
	}
	if !strings.Contains(res.Message, "not one of the databases") {
		t.Errorf("message = %q", res.Message)
	}
}

func TestDBDropObjectPreviewDoesNotDropOrBackup(t *testing.T) {
	db := withDBObjectsTempStore(t)

	// Stub osFS so findAccountSchemas finds alice_wp.
	withMockOS(t, &mockOSWPConfig{schema: "alice_wp"})

	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			joined := strings.Join(args, " ")
			if strings.Contains(joined, "SHOW CREATE") {
				return []byte("CREATE TRIGGER `trg_audit` BEFORE INSERT ON x FOR EACH ROW BEGIN END\n"), nil
			}
			if strings.Contains(joined, "DROP") {
				t.Errorf("DROP issued in preview mode (args=%v)", args)
			}
			return nil, nil
		},
	})

	res := DBDropObject("alice", "alice_wp", "trigger", "trg_audit", true)
	if !res.Success {
		t.Fatalf("preview drop reported failure: %+v", res)
	}
	if !strings.Contains(res.Message, "PREVIEW") {
		t.Errorf("preview message did not mark itself as PREVIEW: %q", res.Message)
	}

	// Confirm no backup row was written.
	backups, err := db.ListDBObjectBackups("alice")
	if err != nil {
		t.Fatalf("ListDBObjectBackups: %v", err)
	}
	if len(backups) != 0 {
		t.Errorf("preview wrote %d backup rows, want 0", len(backups))
	}
}

func TestDBDropObjectCommitWritesBackupAndIssuesDrop(t *testing.T) {
	db := withDBObjectsTempStore(t)
	withMockOS(t, &mockOSWPConfig{schema: "alice_wp"})

	dropCalled := false
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			joined := strings.Join(args, " ")
			switch {
			case strings.Contains(joined, "SHOW CREATE"):
				return []byte("CREATE TRIGGER `trg_audit` BEFORE INSERT ON x FOR EACH ROW BEGIN END\n"), nil
			case strings.Contains(joined, "DROP"):
				dropCalled = true
				return []byte("OK\n"), nil
			}
			return nil, nil
		},
	})

	res := DBDropObject("alice", "alice_wp", "trigger", "trg_audit", false)
	if !res.Success {
		t.Fatalf("Drop reported failure: %+v", res)
	}
	if !dropCalled {
		t.Error("expected DROP to be issued, but it was not")
	}

	backups, err := db.ListDBObjectBackups("alice")
	if err != nil {
		t.Fatalf("ListDBObjectBackups: %v", err)
	}
	if len(backups) != 1 {
		t.Fatalf("backup count = %d, want 1", len(backups))
	}
	b := backups[0]
	if b.Account != "alice" || b.Schema != "alice_wp" || b.Kind != "trigger" || b.Name != "trg_audit" {
		t.Errorf("backup metadata wrong: %+v", b)
	}
	if !strings.Contains(b.CreateSQL, "CREATE TRIGGER") {
		t.Errorf("backup CreateSQL missing: %q", b.CreateSQL)
	}
	if b.DroppedAt.IsZero() {
		t.Error("backup DroppedAt is zero")
	}
}

func TestDBDropObjectShowCreateMissingFailsClosed(t *testing.T) {
	withDBObjectsTempStore(t)
	withMockOS(t, &mockOSWPConfig{schema: "alice_wp"})
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			// SHOW CREATE returns empty -- object doesn't exist or
			// permission denied. Drop must not proceed.
			return nil, nil
		},
	})

	res := DBDropObject("alice", "alice_wp", "event", "ev_missing", false)
	if res.Success {
		t.Errorf("expected failure when SHOW CREATE returns no rows")
	}
}

// mockOSWPConfig stubs Glob to claim a single wp-config.php file
// exists, and Open to return a file descriptor whose contents
// declare the operator-supplied schema as DB_NAME. The minimum
// surface DBDropObject's findAccountSchemas + parseWPConfig need.
type mockOSWPConfig struct {
	mockOS
	schema string
}

func (m *mockOSWPConfig) Glob(pattern string) ([]string, error) {
	if strings.Contains(pattern, "/home/alice/") {
		return []string{"/home/alice/public_html/wp-config.php"}, nil
	}
	return nil, nil
}

func (m *mockOSWPConfig) Open(name string) (*os.File, error) {
	if name != "/home/alice/public_html/wp-config.php" {
		return nil, os.ErrNotExist
	}
	body := "define('DB_NAME','" + m.schema + "');\ndefine('DB_USER','alice_wp');\ndefine('DB_PASSWORD','x');\n"
	tmp, err := os.CreateTemp("", "wpconfig*.php")
	if err != nil {
		return nil, err
	}
	if _, err := tmp.WriteString(body); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	if _, err := tmp.Seek(0, 0); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	return tmp, nil
}
