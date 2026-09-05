package corpusgate

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPreparePinnedCorpus(t *testing.T) {
	for _, mode := range []string{"valid", "checksum", "empty", "missing license", "traversal", "symlink", "missing manifest"} {
		t.Run(mode, func(t *testing.T) {
			cache := t.TempDir()
			archive := filepath.Join(cache, "app-1.zip")
			f, err := os.Create(archive)
			if err != nil {
				t.Fatal(err)
			}
			z := zip.NewWriter(f)
			entries := map[string]string{"app/license.txt": "test license", "app/index.php": "<?php echo 'clean';"}
			if mode == "empty" {
				entries = nil
			}
			if mode == "missing license" {
				delete(entries, "app/license.txt")
			}
			if mode == "traversal" {
				entries["../escape"] = "bad"
			}
			for name, body := range entries {
				h := &zip.FileHeader{Name: name}
				h.SetMode(0600)
				if mode == "symlink" && strings.HasSuffix(name, "index.php") {
					h.SetMode(os.ModeSymlink | 0600)
				}
				w, e := z.CreateHeader(h)
				if e != nil {
					t.Fatal(e)
				}
				if _, e = w.Write([]byte(body)); e != nil {
					t.Fatal(e)
				}
			}
			if err = z.Close(); err != nil {
				t.Fatal(err)
			}
			if err = f.Close(); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(archive)
			if err != nil {
				t.Fatal(err)
			}
			hash := sha256.Sum256(data)
			m := Manifest{Version: 1, Sources: []Source{{ID: "app", Version: "1", URL: "https://example.org/app.zip", SHA256: hex.EncodeToString(hash[:]), License: "test", LicenseFile: "app/license.txt", Files: 2}}}
			if mode == "checksum" {
				m.Sources[0].SHA256 = strings.Repeat("0", 64)
			}
			if mode == "missing manifest" {
				m.Sources = nil
			}
			dest := filepath.Join(t.TempDir(), "corpus")
			rows, err := Prepare(context.Background(), m, cache, dest)
			if mode != "valid" {
				if err == nil {
					t.Fatal("invalid corpus accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(rows) != 2 || rows[0].Path != "app/app/index.php" || rows[0].SHA256 == "" {
				t.Fatalf("inventory=%+v", rows)
			}
			actual, err := os.ReadFile(filepath.Join(dest, "app/app/index.php"))
			if err != nil || string(actual) != entries["app/index.php"] {
				t.Fatalf("payload=%q error=%v", actual, err)
			}
			if _, err = Prepare(context.Background(), m, cache, dest); err == nil {
				t.Fatal("existing corpus accepted; stale files could survive")
			}
		})
	}
}

func TestReportRejectsBadDetectorAndMissingInput(t *testing.T) {
	if err := (Report{Engine: "bad", Scanned: 5000, Hits: map[string]int{"always_true": 5000}}).Validate(); err == nil {
		t.Fatal("bad detector accepted")
	}
	if err := (Report{Engine: "empty", Scanned: 0}).Validate(); err == nil {
		t.Fatal("empty corpus accepted")
	}
	if err := (Report{Engine: "clean", Scanned: 2, Hits: map[string]int{"rule": 0}}).Validate(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CSM_CORPUS_REQUIRED", "1")
	t.Setenv("TEST_CORPUS_ROOT", "")
	if _, err := Root("TEST_CORPUS_ROOT"); err == nil {
		t.Fatal("required corpus input missing")
	}
}
