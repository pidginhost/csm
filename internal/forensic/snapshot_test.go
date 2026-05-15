package forensic

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// readArchiveEntries returns the path -> body map of every tar.gz entry.
func readArchiveEntries(t *testing.T, archivePath string) map[string][]byte {
	t.Helper()
	f, err := os.Open(archivePath) // #nosec G304 -- test fixture path under t.TempDir.
	if err != nil {
		t.Fatalf("open archive: %v", err)
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	out := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar next: %v", err)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("tar read body for %s: %v", hdr.Name, err)
		}
		out[hdr.Name] = body
	}
	return out
}

func TestSnapshot_Write_RejectsEmptyAccount(t *testing.T) {
	s := Snapshot{Account: "", OutPath: filepath.Join(t.TempDir(), "x.tar.gz")}
	_, _, err := s.Write()
	if err == nil {
		t.Error("empty account must error")
	}
}

func TestSnapshot_Write_RejectsEmptyOutPath(t *testing.T) {
	s := Snapshot{Account: "alice", OutPath: ""}
	_, _, err := s.Write()
	if err == nil {
		t.Error("empty out path must error")
	}
}

func TestSnapshot_Write_RejectsOutPathInsideAccountHome(t *testing.T) {
	// Writing the archive into /home/<account>/ would expose forensic
	// content to the account user (and via the web if doc root sits
	// above). The snapshot must refuse that destination outright.
	s := Snapshot{
		Account: "alice",
		OutPath: "/home/alice/forensics.tar.gz",
	}
	_, _, err := s.Write()
	if err == nil {
		t.Error("out path inside /home/<account>/ must be rejected")
	}
}

func TestSnapshot_Write_ProducesArchiveWithManifestAndDumps(t *testing.T) {
	tmp := t.TempDir()
	out := filepath.Join(tmp, "snap.tar.gz")
	ts := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)

	s := Snapshot{
		Account:   "alice",
		OutPath:   out,
		Timestamp: ts,
		Sources: Sources{
			DiscoverTargets: func(string) []SchemaTarget {
				return []SchemaTarget{
					{Schema: "alice_wp1", TablePrefix: "wp_"},
					{Schema: "alice_wp2", TablePrefix: "wpxd_"},
				}
			},
			DumpSchema: func(schema string) ([]byte, error) {
				return []byte("-- mysqldump for " + schema + "\nCREATE TRIGGER foo;"), nil
			},
			ListAdmins: func(schema, _ string) ([]byte, error) {
				return []byte("1\tadmin\tadmin@example.test\n"), nil
			},
			ListSessions: func(schema, _ string) ([]byte, error) {
				return []byte("1\ta:1:{}"), nil
			},
			ListRecentFiles: func(_ string, _ time.Time) ([]byte, error) {
				return []byte("/home/alice/public_html/wp-config.php\t2026-05-15T11:55:00Z\n"), nil
			},
		},
	}

	archivePath, sha, err := s.Write()
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if archivePath != out {
		t.Errorf("returned path = %q, want %q", archivePath, out)
	}
	if len(sha) != 64 {
		t.Errorf("sha256 length = %d, want 64", len(sha))
	}

	entries := readArchiveEntries(t, out)
	mustContain := []string{
		"manifest.txt",
		"schema/alice_wp1-routines.sql",
		"schema/alice_wp2-routines.sql",
		"schema/alice_wp1-admins.tsv",
		"schema/alice_wp2-admins.tsv",
		"schema/alice_wp1-sessions.tsv",
		"schema/alice_wp2-sessions.tsv",
		"files/recent-mtimes.tsv",
	}
	for _, name := range mustContain {
		if _, ok := entries[name]; !ok {
			t.Errorf("archive missing %q (have %v)", name, keysOf(entries))
		}
	}

	manifest := string(entries["manifest.txt"])
	if !strings.Contains(manifest, "account=alice") {
		t.Errorf("manifest missing account: %s", manifest)
	}
	if !strings.Contains(manifest, ts.Format(time.RFC3339)) {
		t.Errorf("manifest missing timestamp: %s", manifest)
	}

	// Sidecar exists alongside archive.
	sidecar := out + ".sha256"
	body, err := os.ReadFile(sidecar) // #nosec G304 -- test artifact under t.TempDir.
	if err != nil {
		t.Fatalf("reading sidecar: %v", err)
	}
	if !strings.Contains(string(body), sha) {
		t.Errorf("sidecar content %q does not contain returned sha %q", body, sha)
	}
}

func TestSnapshot_Write_ManifestExcludesCredentials(t *testing.T) {
	// Snapshot is evidence only. Credentials live in a separate path
	// rotated by ops. Manifest, dumps, and TSVs must not contain any
	// raw passwords or password hashes.
	out := filepath.Join(t.TempDir(), "snap.tar.gz")
	s := Snapshot{
		Account:   "alice",
		OutPath:   out,
		Timestamp: time.Now(),
		Sources: Sources{
			DiscoverTargets: func(string) []SchemaTarget {
				return []SchemaTarget{{Schema: "alice_wp", TablePrefix: "wp_"}}
			},
			DumpSchema: func(string) ([]byte, error) {
				return []byte("-- routines only\n"), nil
			},
			ListAdmins: func(string, string) ([]byte, error) {
				// Snapshot intentionally omits user_pass and password hash columns.
				return []byte("1\tadmin\tadmin@example.test\n"), nil
			},
			ListSessions: func(string, string) ([]byte, error) { return []byte{}, nil },
			ListRecentFiles: func(string, time.Time) ([]byte, error) {
				return []byte("wp-config.php is intentionally not copied\n"), nil
			},
		},
	}
	if _, _, err := s.Write(); err != nil {
		t.Fatalf("Write: %v", err)
	}
	entries := readArchiveEntries(t, out)
	bad := []string{"DB_PASSWORD", "$wp$2y$", "user_pass", "$P$B"}
	for name, body := range entries {
		for _, marker := range bad {
			if strings.Contains(string(body), marker) {
				t.Errorf("entry %q contains forbidden token %q", name, marker)
			}
		}
	}
}

func TestSnapshot_Write_ArchiveHashStableAcrossRunsForSameInputs(t *testing.T) {
	// Two snapshots written with identical inputs must produce
	// byte-identical archives. The Timestamp is held constant; nothing
	// else in the snapshot reads from time.Now().
	makeOne := func() (string, string) {
		out := filepath.Join(t.TempDir(), "snap.tar.gz")
		s := Snapshot{
			Account:   "alice",
			OutPath:   out,
			Timestamp: time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC),
			Sources: Sources{
				DiscoverTargets: func(string) []SchemaTarget {
					return []SchemaTarget{{Schema: "alice_wp", TablePrefix: "wp_"}}
				},
				DumpSchema:      func(string) ([]byte, error) { return []byte("dump\n"), nil },
				ListAdmins:      func(string, string) ([]byte, error) { return []byte("admin\n"), nil },
				ListSessions:    func(string, string) ([]byte, error) { return []byte{}, nil },
				ListRecentFiles: func(string, time.Time) ([]byte, error) { return []byte{}, nil },
			},
		}
		_, sha, err := s.Write()
		if err != nil {
			t.Fatalf("Write: %v", err)
		}
		// Also hash the file contents directly so we cross-check that
		// Write's returned sha matches the file body.
		body, err := os.ReadFile(out) // #nosec G304 -- test artifact under t.TempDir.
		if err != nil {
			t.Fatalf("read archive: %v", err)
		}
		sum := sha256.Sum256(body)
		return sha, hex.EncodeToString(sum[:])
	}
	sha1, fileSha1 := makeOne()
	sha2, fileSha2 := makeOne()
	if sha1 != sha2 {
		t.Errorf("repeated snapshots produced different reported sha: %s vs %s", sha1, sha2)
	}
	if fileSha1 != fileSha2 {
		t.Errorf("repeated snapshots produced different file sha: %s vs %s", fileSha1, fileSha2)
	}
	if sha1 != fileSha1 {
		t.Errorf("reported sha %s does not match file sha %s", sha1, fileSha1)
	}
}

func TestSnapshot_Write_ContinuesWhenSchemaDumpFails(t *testing.T) {
	// A failure to dump one schema must not abort the whole snapshot --
	// we still want triggers/admins from the other schemas and a
	// manifest noting the failure.
	out := filepath.Join(t.TempDir(), "snap.tar.gz")
	s := Snapshot{
		Account:   "alice",
		OutPath:   out,
		Timestamp: time.Now(),
		Sources: Sources{
			DiscoverTargets: func(string) []SchemaTarget {
				return []SchemaTarget{
					{Schema: "good", TablePrefix: "wp_"},
					{Schema: "bad", TablePrefix: "wp_"},
				}
			},
			DumpSchema: func(schema string) ([]byte, error) {
				if schema == "bad" {
					return nil, &errString{"mysqldump exited 1"}
				}
				return []byte("ok\n"), nil
			},
			ListAdmins:      func(string, string) ([]byte, error) { return []byte("admin\n"), nil },
			ListSessions:    func(string, string) ([]byte, error) { return []byte{}, nil },
			ListRecentFiles: func(string, time.Time) ([]byte, error) { return []byte{}, nil },
		},
	}
	if _, _, err := s.Write(); err != nil {
		t.Fatalf("Write: %v", err)
	}
	entries := readArchiveEntries(t, out)
	if _, ok := entries["schema/good-routines.sql"]; !ok {
		t.Error("expected dump for healthy schema")
	}
	if _, ok := entries["schema/bad-routines.sql.err"]; !ok {
		t.Errorf("expected error sidecar for failed schema, have %v", keysOf(entries))
	}
}

func TestSnapshot_Write_InvalidSchemaTargetCannotCreateTraversalEntry(t *testing.T) {
	out := filepath.Join(t.TempDir(), "snap.tar.gz")
	s := Snapshot{
		Account:   "alice",
		OutPath:   out,
		Timestamp: time.Now(),
		Sources: Sources{
			DiscoverTargets: func(string) []SchemaTarget {
				return []SchemaTarget{{Schema: "../escape", TablePrefix: "wp_"}}
			},
			DumpSchema: func(string) ([]byte, error) {
				return []byte("must not be called\n"), nil
			},
			ListAdmins:   func(string, string) ([]byte, error) { return []byte("must not be called\n"), nil },
			ListSessions: func(string, string) ([]byte, error) { return []byte("must not be called\n"), nil },
		},
	}
	if _, _, err := s.Write(); err != nil {
		t.Fatalf("Write: %v", err)
	}
	entries := readArchiveEntries(t, out)
	if _, ok := entries["schema/../escape-routines.sql"]; ok {
		t.Fatal("archive contains traversal entry for invalid schema")
	}
	if _, ok := entries["schema/invalid-target-0.err"]; !ok {
		t.Fatalf("archive missing invalid target marker; entries=%v", keysOf(entries))
	}
	for name := range entries {
		if strings.Contains(name, "..") || strings.HasPrefix(name, "/") {
			t.Fatalf("unsafe archive entry %q", name)
		}
	}
}

func TestWriteArchiveEntryRejectsUnsafeNames(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, name := range []string{"../escape", "/abs/path", "schema/../../escape", `schema\escape`} {
		if err := writeArchiveEntry(tw, name, []byte("x"), time.Now()); err == nil {
			t.Errorf("writeArchiveEntry(%q) succeeded, want error", name)
		}
	}
}

type errString struct{ s string }

func (e *errString) Error() string { return e.s }

func keysOf(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestSnapshot_Write_RejectsTraversalInAccountName(t *testing.T) {
	// Account name flows into manifest, archive entries, and the
	// SchemaTarget discovery hook. Must reject anything that could
	// allow path traversal.
	bad := []string{"../escape", "alice/..", "a:b", "alice\x00null", strings.Repeat("a", 256)}
	for _, name := range bad {
		s := Snapshot{
			Account: name,
			OutPath: filepath.Join(t.TempDir(), "x.tar.gz"),
		}
		_, _, err := s.Write()
		if err == nil {
			t.Errorf("invalid account name %q must be rejected", name)
		}
	}
}

func TestBytesContainsOnlyASCII(t *testing.T) {
	// Helper sanity for accountValid().
	if !accountNameValid("alice") {
		t.Error("alice must be valid")
	}
	if !accountNameValid("alice123") {
		t.Error("alphanumeric must be valid")
	}
	if accountNameValid("") {
		t.Error("empty must be invalid")
	}
	if accountNameValid("../etc") {
		t.Error("path traversal must be invalid")
	}
}

// Compile-time assertion that Sources implements all expected hooks.
var _ = Sources{}.DumpSchema

func TestBytes_RoundTripCompressionWorks(t *testing.T) {
	// Sanity-check the archive read helper itself.
	tmp := t.TempDir()
	out := filepath.Join(tmp, "test.tar.gz")
	f, err := os.Create(out) // #nosec G304 -- test fixture path under t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	body := []byte("hi")
	if err := tw.WriteHeader(&tar.Header{Name: "x.txt", Size: int64(len(body)), Mode: 0o600}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	got := readArchiveEntries(t, out)
	if !bytes.Equal(got["x.txt"], body) {
		t.Errorf("round trip body = %q, want %q", got["x.txt"], body)
	}
}
