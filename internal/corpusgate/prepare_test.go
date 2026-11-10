package corpusgate

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPreparePinnedCorpus(t *testing.T) {
	for _, mode := range []string{"valid", "checksum", "empty", "missing license", "traversal", "symlink", "missing manifest"} {
		t.Run(mode, func(t *testing.T) {
			installCorpusTransport(t, func(*http.Request) (*http.Response, error) {
				return nil, errors.New("offline")
			})
			cache := t.TempDir()
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
			data := testArchive(t, entries, mode == "symlink")
			hash := sha256.Sum256(data)
			if err := os.WriteFile(filepath.Join(cache, "app-"+hex.EncodeToString(hash[:])+".zip"), data, 0600); err != nil {
				t.Fatal(err)
			}
			m := Manifest{Version: ManifestVersion,
				Sources: []Source{{ID: "app", CMS: "wordpress", Version: "1", URL: "https://example.org/app.zip", SHA256: hex.EncodeToString(hash[:]), License: "test", LicenseFile: "app/license.txt", Files: 2}},
				Pending: pendingExcept("wordpress")}
			if mode == "checksum" {
				// Same name, different bytes: a cache entry that rotted in place.
				if err := os.WriteFile(filepath.Join(cache, "app-"+m.Sources[0].SHA256+".zip"), append(data, 0), 0600); err != nil {
					t.Fatal(err)
				}
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

// testArchive builds a ZIP holding entries; symlink marks every index.php as
// a symbolic link.
func testArchive(t *testing.T, entries map[string]string, symlink bool) []byte {
	t.Helper()
	var buf bytes.Buffer
	z := zip.NewWriter(&buf)
	for name, body := range entries {
		h := &zip.FileHeader{Name: name}
		h.SetMode(0600)
		if symlink && strings.HasSuffix(name, "index.php") {
			h.SetMode(os.ModeSymlink | 0600)
		}
		w, err := z.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// The cache key no longer changes with the manifest, so archives it stops
// pinning must leave the cache instead of piling up in it.
func TestPrepareDropsUnpinnedArchives(t *testing.T) {
	cache := t.TempDir()
	m, data := cacheFixture(t)
	requests := 0
	installCorpusTransport(t, func(*http.Request) (*http.Response, error) {
		requests++
		return archiveResponse(data), nil
	})
	if err := prepareCache(t, m, cache); err != nil {
		t.Fatal(err)
	}
	old := m.Sources[0].SHA256
	data = testArchive(t, map[string]string{"app/license.txt": "updated license", "app/index.php": "<?php echo 'clean';"}, false)
	hash := sha256.Sum256(data)
	m.Sources[0].SHA256 = hex.EncodeToString(hash[:])
	if err := prepareCache(t, m, cache); err != nil {
		t.Fatal(err)
	}
	managed := filepath.Join(cache, archiveCacheDir)
	if _, err := os.Stat(filepath.Join(managed, old+".zip")); !os.IsNotExist(err) {
		t.Fatalf("retired archive survived: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(managed, m.Sources[0].SHA256+".zip"))
	if err != nil || !bytes.Equal(body, data) {
		t.Fatalf("new pin missing or changed: %v", err)
	}
	if requests != 2 {
		t.Fatalf("downloads = %d, want 2", requests)
	}
}
