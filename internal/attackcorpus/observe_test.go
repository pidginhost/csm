package attackcorpus

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// quarantine moves abs into dir the way the responders do: a flat entry plus
// a .meta sidecar recording the original path.
func quarantine(t *testing.T, dir, abs string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	entry := filepath.Join(dir, "20261107-120000_TESTRAND_"+strings.ReplaceAll(abs, "/", "_"))
	if err := os.Rename(abs, entry); err != nil {
		t.Fatal(err)
	}
	meta, err := json.Marshal(map[string]any{"original_path": abs, "owner_uid": 1000, "mode": "-rw-r--r--", "reason": "test"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(entry+".meta", meta, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestObserveRemediationRequiresRetainedContent(t *testing.T) {
	for _, damage := range []string{"missing file", "changed file", "missing directory member", "symlink"} {
		t.Run(damage, func(t *testing.T) {
			planted, original, home := plantAll(t, fileA)
			qdir := t.TempDir()
			target := planted[fileA]
			if damage == "missing directory member" {
				target = filepath.Join(home, "public_html")
			}
			quarantine(t, qdir, target)
			entries, err := os.ReadDir(qdir)
			if err != nil || len(entries) != 2 {
				t.Fatal("expected an archive and its metadata")
			}
			var archived string
			for _, e := range entries {
				if !strings.HasSuffix(e.Name(), ".meta") {
					archived = filepath.Join(qdir, e.Name())
				}
			}
			if damage == "missing directory member" {
				archived = filepath.Join(archived, "a.php")
			}
			if damage == "changed file" {
				err = os.WriteFile(archived, []byte("different content"), 0o600)
			} else {
				err = os.Remove(archived)
			}
			if err != nil {
				t.Fatal(err)
			}
			if damage == "symlink" {
				outside := filepath.Join(t.TempDir(), "outside")
				if err = os.WriteFile(outside, original[fileA], 0o600); err != nil {
					t.Fatal(err)
				}
				if err = os.Symlink(outside, archived); err != nil {
					t.Fatal(err)
				}
			}
			got, sums, err := ObserveRemediation(planted, original, qdir)
			if err == nil || got != nil || sums != nil {
				t.Fatal("damaged quarantine did not fail observation without partial results")
			}
		})
	}
}

func TestObserveRemediationRequiresOriginalBytes(t *testing.T) {
	planted, _, _ := plantAll(t, fileA)
	if err := os.WriteFile(planted[fileA], nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, original := range []map[string][]byte{nil, {fileA: nil}, {fileA: {}}} {
		if _, _, err := ObserveRemediation(planted, original, t.TempDir()); err == nil {
			t.Error("a missing or empty baseline certified a truncated file as untouched")
		}
	}
}

func plantAll(t *testing.T, paths ...string) (map[string]string, map[string][]byte, string) {
	t.Helper()
	var files []File
	original := map[string][]byte{}
	for _, p := range paths {
		files = append(files, File{Path: p, B64: "a.b64"})
		original[p] = []byte("harmless test text\n")
	}
	root := t.TempDir()
	planted, err := loaded(t, controlWith(files...), nil).Plant(root, filepath.Join(root, "cron"), "acct")
	if err != nil {
		t.Fatal(err)
	}
	return planted, original, filepath.Join(root, "acct")
}

func TestObserveRemediationQuarantinedCleanedUntouched(t *testing.T) {
	planted, original, home := plantAll(t,
		"public_html/q.php", "public_html/c.php", "public_html/u.php",
		"public_html/plugin/p.php", "public_html/plugin/readme.txt")
	qdir := filepath.Join(t.TempDir(), "quarantine")

	quarantine(t, qdir, planted["public_html/q.php"])
	// A directory quarantine records the directory, not each file in it.
	quarantine(t, qdir, filepath.Join(home, "public_html", "plugin"))
	if err := os.WriteFile(planted["public_html/c.php"], []byte("cleaned text\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, sums, err := ObserveRemediation(planted, original, qdir)
	if err != nil {
		t.Fatalf("ObserveRemediation: %v", err)
	}
	want := map[string]Remediation{
		"public_html/q.php":             Quarantined,
		"public_html/c.php":             Cleaned,
		"public_html/u.php":             Untouched,
		"public_html/plugin/p.php":      Quarantined,
		"public_html/plugin/readme.txt": Quarantined,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("remediation = %v\nwant %v", got, want)
	}
	sum := sha256.Sum256([]byte("cleaned text\n"))
	if wantSums := map[string]string{"public_html/c.php": hex.EncodeToString(sum[:])}; !reflect.DeepEqual(sums, wantSums) {
		t.Errorf("cleaned sha256 = %v, want %v", sums, wantSums)
	}
}

func TestObserveRemediationRemoved(t *testing.T) {
	planted, original, home := plantAll(t, "public_html/a.php", "public_html/b.php", "public_html/c.php", "public_html/ab.php")
	qdir := filepath.Join(t.TempDir(), "quarantine")

	// Two files gone, one entry: attribution follows the recorded path, so the
	// count of entries cannot make b.php look quarantined.
	quarantine(t, qdir, planted["public_html/a.php"])
	if err := os.Remove(planted["public_html/b.php"]); err != nil {
		t.Fatal(err)
	}
	// A pre-clean backup is not a quarantine entry.
	backup := filepath.Join(qdir, "pre_clean")
	if err := os.MkdirAll(backup, 0o700); err != nil {
		t.Fatal(err)
	}
	meta, err := json.Marshal(map[string]string{"original_path": planted["public_html/c.php"]})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(backup, "x.meta"), meta, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(planted["public_html/c.php"]); err != nil {
		t.Fatal(err)
	}
	// A recorded path that only shares a prefix with a planted file.
	if err = os.Remove(planted["public_html/ab.php"]); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(home, "public_html", "a"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	quarantine(t, qdir, filepath.Join(home, "public_html", "a"))

	got, sums, err := ObserveRemediation(planted, original, qdir)
	if err != nil {
		t.Fatalf("ObserveRemediation: %v", err)
	}
	want := map[string]Remediation{
		"public_html/a.php":  Quarantined,
		"public_html/b.php":  Removed,
		"public_html/c.php":  Removed,
		"public_html/ab.php": Removed,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("remediation = %v\nwant %v", got, want)
	}
	if len(sums) != 0 {
		t.Errorf("cleaned sha256 = %v, want none", sums)
	}

	// No quarantine directory at all: nothing was quarantined.
	got, _, err = ObserveRemediation(planted, original, filepath.Join(t.TempDir(), "never-created"))
	if err != nil {
		t.Fatalf("ObserveRemediation without a quarantine dir: %v", err)
	}
	if got["public_html/a.php"] != Removed {
		t.Errorf("a.php without a quarantine dir = %s, want removed", got["public_html/a.php"])
	}

	// A sidecar that does not parse leaves the run incomplete.
	if err := os.WriteFile(filepath.Join(qdir, "broken.meta"), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ObserveRemediation(planted, original, qdir); err == nil {
		t.Error("ObserveRemediation accepted an unreadable quarantine sidecar")
	}
}
