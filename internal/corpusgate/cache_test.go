package corpusgate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Transport stubs keep recovery tests offline, including unexpected requests.
type corpusTransport func(*http.Request) (*http.Response, error)

func (f corpusTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func installCorpusTransport(t *testing.T, f corpusTransport) {
	t.Helper()
	old := http.DefaultTransport
	http.DefaultTransport = f
	t.Cleanup(func() { http.DefaultTransport = old })
}

func archiveResponse(data []byte) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(data))}
}

func cacheFixture(t *testing.T) (Manifest, []byte) {
	t.Helper()
	data := testArchive(t, map[string]string{"app/license.txt": "test license", "app/index.php": "<?php echo 'clean';"}, false)
	hash := sha256.Sum256(data)
	return Manifest{Version: ManifestVersion,
		Sources: []Source{{ID: "app", CMS: "wordpress", Version: "1", URL: "https://example.org/app.zip", SHA256: hex.EncodeToString(hash[:]), License: "test", LicenseFile: "app/license.txt", Files: 2}},
		Pending: pendingExcept("wordpress")}, data
}

func prepareCache(t *testing.T, m Manifest, cache string) error {
	t.Helper()
	dest := filepath.Join(t.TempDir(), "corpus")
	rows, err := Prepare(context.Background(), m, cache, dest)
	if err == nil {
		if len(rows) != 2*len(m.Sources) {
			t.Fatalf("inventory has %d files, want %d", len(rows), 2*len(m.Sources))
		}
		for _, s := range m.Sources {
			body, readErr := os.ReadFile(filepath.Join(dest, s.ID, "app/index.php"))
			if readErr != nil || string(body) != "<?php echo 'clean';" {
				t.Fatalf("extracted payload = %q, %v", body, readErr)
			}
		}
	}
	return err
}

func TestPrepareReusesPinsAcrossMetadataEdits(t *testing.T) {
	m, data := cacheFixture(t)
	cache := t.TempDir()
	requests := 0
	installCorpusTransport(t, func(*http.Request) (*http.Response, error) {
		requests++
		return archiveResponse(data), nil
	})
	if err := prepareCache(t, m, cache); err != nil {
		t.Fatal(err)
	}
	m.Pending[0].Reason = "updated pending reason"
	if err := prepareCache(t, m, cache); err != nil {
		t.Fatal(err)
	}
	m.Sources[0].ID, m.Sources[0].Version = "renamed", "2"
	m.Sources[0].SHA256 = strings.ToUpper(m.Sources[0].SHA256)
	m.Sources[0].URL = "https://example.org/mirror.zip"
	if err := prepareCache(t, m, cache); err != nil {
		t.Fatal(err)
	}
	if requests != 1 {
		t.Fatalf("unchanged pin downloaded %d times, want 1", requests)
	}
}

func TestPrepareRepairsCorruptCache(t *testing.T) {
	for _, mode := range []string{"checksum", "empty", "oversize", "restricted permissions", "symlink", "dangling symlink"} {
		t.Run(mode, func(t *testing.T) {
			m, data := cacheFixture(t)
			cache := t.TempDir()
			requests := 0
			installCorpusTransport(t, func(*http.Request) (*http.Response, error) {
				requests++
				return archiveResponse(data), nil
			})
			if err := prepareCache(t, m, cache); err != nil {
				t.Fatal(err)
			}
			var archive string
			if err := filepath.WalkDir(cache, func(path string, e os.DirEntry, err error) error {
				if err == nil && e.Type().IsRegular() && strings.HasSuffix(e.Name(), ".zip") {
					archive = path
				}
				return err
			}); err != nil || archive == "" {
				t.Fatalf("find downloaded archive: %q, %v", archive, err)
			}
			wantRequests := 2
			switch mode {
			case "checksum", "empty":
				var bad []byte
				if mode == "checksum" {
					bad = []byte("corrupt cache")
				}
				if err := os.WriteFile(archive, bad, 0600); err != nil {
					t.Fatal(err)
				}
			case "restricted permissions":
				if err := os.Chmod(archive, 0); err != nil {
					t.Fatal(err)
				}
				// Privileged CI users can still read mode 000. Such a file is
				// verifiable and must be reused; other users need a repair.
				if f, err := os.Open(archive); err == nil {
					if err := f.Close(); err != nil {
						t.Fatal(err)
					}
					wantRequests = 1
				}
			case "oversize":
				if err := os.Truncate(archive, maxArchive+1); err != nil {
					t.Fatal(err)
				}
			default:
				target := filepath.Join(t.TempDir(), "outside.zip")
				if mode == "symlink" {
					if err := os.WriteFile(target, data, 0600); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.Remove(archive); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, archive); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					body, err := os.ReadFile(target)
					if mode == "symlink" && (err != nil || !bytes.Equal(body, data)) {
						t.Errorf("symlink target changed: %v", err)
					}
					if mode == "dangling symlink" && !os.IsNotExist(err) {
						t.Errorf("dangling target created: %v", err)
					}
				})
			}
			if err := prepareCache(t, m, cache); err != nil {
				t.Fatal(err)
			}
			if err := prepareCache(t, m, cache); err != nil {
				t.Fatal(err)
			}
			if requests != wantRequests {
				t.Fatalf("downloads = %d, want %d", requests, wantRequests)
			}
		})
	}
}

func TestPrepareRejectsBadDownloadWithoutPoisoningCache(t *testing.T) {
	m, data := cacheFixture(t)
	cache := t.TempDir()
	requests := 0
	installCorpusTransport(t, func(*http.Request) (*http.Response, error) {
		requests++
		if requests == 1 {
			return archiveResponse([]byte("not the pinned archive")), nil
		}
		return archiveResponse(data), nil
	})
	if err := prepareCache(t, m, cache); err == nil {
		t.Fatal("download with wrong checksum accepted")
	}
	if err := filepath.WalkDir(cache, func(path string, e os.DirEntry, err error) error {
		if err == nil && e.Type().IsRegular() && (strings.HasSuffix(e.Name(), ".zip") || strings.Contains(e.Name(), "download")) {
			t.Errorf("unverified download persisted: %s", path)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := prepareCache(t, m, cache); err != nil {
		t.Fatal(err)
	}
	if requests != 2 {
		t.Fatalf("downloads = %d, want 2", requests)
	}
}

func TestPreparePrunesOnlyOwnedArchivesBeforeFailure(t *testing.T) {
	m, data := cacheFixture(t)
	cache := t.TempDir()
	installCorpusTransport(t, func(*http.Request) (*http.Response, error) { return archiveResponse(data), nil })
	if err := prepareCache(t, m, cache); err != nil {
		t.Fatal(err)
	}
	foreign := []string{"backup.zip", "app-1.zip", "other-" + strings.Repeat("0", 64) + ".zip", strings.Repeat("f", 64) + ".zip", ".corpus-download-1234"}
	for _, name := range foreign {
		if err := os.WriteFile(filepath.Join(cache, name), []byte("operator data"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	m.Sources[0].SHA256 = strings.Repeat("a", 64)
	installCorpusTransport(t, func(*http.Request) (*http.Response, error) { return nil, errors.New("offline") })
	if err := prepareCache(t, m, cache); err == nil {
		t.Fatal("missing pinned archive accepted")
	}
	for _, name := range foreign {
		body, err := os.ReadFile(filepath.Join(cache, name))
		if err != nil || string(body) != "operator data" {
			t.Errorf("unrelated file %s changed: %q, %v", name, body, err)
		}
	}
	if err := filepath.WalkDir(cache, func(path string, e os.DirEntry, err error) error {
		if err == nil && e.Type().IsRegular() && strings.HasSuffix(e.Name(), ".zip") {
			body, readErr := os.ReadFile(path)
			if readErr != nil || string(body) != "operator data" {
				t.Errorf("stale tool archive survived failed run: %s", path)
			}
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPreparePreservesUnrelatedZIPOnSuccess(t *testing.T) {
	m, data := cacheFixture(t)
	cache := t.TempDir()
	unrelated := filepath.Join(cache, "operator-backup.zip")
	if err := os.WriteFile(unrelated, data, 0600); err != nil {
		t.Fatal(err)
	}
	installCorpusTransport(t, func(*http.Request) (*http.Response, error) { return archiveResponse(data), nil })
	if err := prepareCache(t, m, cache); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(unrelated)
	if err != nil || !bytes.Equal(body, data) {
		t.Fatalf("unrelated archive removed or changed: %v", err)
	}
}

func TestPrepareImportsFlatCachesWithoutDeletingInputs(t *testing.T) {
	for _, style := range []string{"version", "checksum"} {
		t.Run(style, func(t *testing.T) {
			m, data := cacheFixture(t)
			cache := t.TempDir()
			suffix := m.Sources[0].SHA256
			if style == "version" {
				suffix = m.Sources[0].Version
			}
			old := filepath.Join(cache, "app-"+suffix+".zip")
			if err := os.WriteFile(old, data, 0600); err != nil {
				t.Fatal(err)
			}
			requests := 0
			installCorpusTransport(t, func(*http.Request) (*http.Response, error) {
				requests++
				return nil, errors.New("offline")
			})
			if err := prepareCache(t, m, cache); err != nil {
				t.Fatal(err)
			}
			m.Sources[0].ID, m.Sources[0].Version = "renamed", "2"
			if err := prepareCache(t, m, cache); err != nil {
				t.Error(err)
			}
			if requests != 0 {
				t.Errorf("valid legacy pin downloaded %d times", requests)
			}
			body, err := os.ReadFile(old)
			if err != nil || !bytes.Equal(body, data) {
				t.Fatalf("flat input changed: %v", err)
			}
		})
	}
}

func TestPrepareCleansInterruptedDownloads(t *testing.T) {
	m, data := cacheFixture(t)
	cache := t.TempDir()
	installCorpusTransport(t, func(*http.Request) (*http.Response, error) { return archiveResponse(data), nil })
	if err := prepareCache(t, m, cache); err != nil {
		t.Fatal(err)
	}
	managed := filepath.Join(cache, archiveCacheDir)
	for _, digest := range []string{m.Sources[0].SHA256, strings.Repeat("0", 64)} {
		if err := os.WriteFile(filepath.Join(managed, digest+".download"), []byte("interrupted"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	installCorpusTransport(t, func(*http.Request) (*http.Response, error) { return nil, errors.New("offline") })
	if err := prepareCache(t, m, cache); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(managed)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Name() != m.Sources[0].SHA256+".zip" || entries[1].Name() != "lock" {
		t.Fatalf("cache retained interrupted downloads: %v", entries)
	}
}

func TestPrepareRejectsSymlinkedManagedDirectory(t *testing.T) {
	m, data := cacheFixture(t)
	cache, outside := t.TempDir(), t.TempDir()
	victim := filepath.Join(outside, strings.Repeat("0", 64)+".zip")
	if err := os.WriteFile(victim, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(cache, archiveCacheDir)); err != nil {
		t.Fatal(err)
	}
	installCorpusTransport(t, func(*http.Request) (*http.Response, error) {
		t.Error("network requested for an unsafe cache")
		return archiveResponse(data), nil
	})
	if err := prepareCache(t, m, cache); err == nil {
		t.Fatal("symlinked managed directory accepted")
	}
	body, err := os.ReadFile(victim)
	if err != nil || !bytes.Equal(body, data) {
		t.Fatalf("symlink target changed: %v", err)
	}
}

func TestPrepareSerializesSharedCache(t *testing.T) {
	m, data := cacheFixture(t)
	cache := t.TempDir()
	requests := 0
	installCorpusTransport(t, func(*http.Request) (*http.Response, error) {
		requests++
		if requests == 1 {
			err := prepareCache(t, m, cache)
			if err == nil || !strings.Contains(err.Error(), "cache is busy") {
				t.Errorf("concurrent cache writer error = %v, want busy", err)
			}
		}
		return archiveResponse(data), nil
	})
	if err := prepareCache(t, m, cache); err != nil {
		t.Fatal(err)
	}
	// Closing the first writer must release the lock even though its inode remains.
	if err := prepareCache(t, m, cache); err != nil {
		t.Fatal(err)
	}
	if requests != 1 {
		t.Fatalf("concurrent or repeated run downloaded %d archives, want 1", requests)
	}
}

// A failed source must not force successful pins back onto a rate-limited mirror.
func TestPrepareRetainsVerifiedPinsAfterLaterDownloadFails(t *testing.T) {
	m, first := cacheFixture(t)
	second := testArchive(t, map[string]string{"app/license.txt": "second license", "app/index.php": "<?php echo 'clean';"}, false)
	sum := sha256.Sum256(second)
	s := m.Sources[0]
	s.ID, s.SHA256, s.URL = "second", hex.EncodeToString(sum[:]), "https://example.org/second.zip"
	m.Sources = append(m.Sources, s)
	cache := t.TempDir()
	firstRequests, secondRequests := 0, 0
	installCorpusTransport(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/second.zip" {
			secondRequests++
			if secondRequests == 1 {
				return &http.Response{StatusCode: http.StatusTooManyRequests, Body: io.NopCloser(strings.NewReader("rate limited"))}, nil
			}
			return archiveResponse(second), nil
		}
		firstRequests++
		return archiveResponse(first), nil
	})
	if err := prepareCache(t, m, cache); err == nil || !strings.Contains(err.Error(), "HTTP 429") {
		t.Fatalf("rate-limit error = %v", err)
	}
	if err := prepareCache(t, m, cache); err != nil {
		t.Fatal(err)
	}
	m.Pending[0].Reason = "new pending reason"
	if err := prepareCache(t, m, cache); err != nil {
		t.Fatal(err)
	}
	if firstRequests != 1 || secondRequests != 2 {
		t.Fatalf("requests = (%d, %d), want (1, 2)", firstRequests, secondRequests)
	}
}

type brokenArchiveReader struct{}

func (brokenArchiveReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestPrepareRetriesAfterInterruptedDownload(t *testing.T) {
	m, data := cacheFixture(t)
	cache := t.TempDir()
	requests := 0
	installCorpusTransport(t, func(*http.Request) (*http.Response, error) {
		requests++
		if requests == 1 {
			return &http.Response{StatusCode: http.StatusOK,
				Body: io.NopCloser(io.MultiReader(bytes.NewReader(data[:len(data)/2]), brokenArchiveReader{}))}, nil
		}
		return archiveResponse(data), nil
	})
	if err := prepareCache(t, m, cache); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("interrupted download error = %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(cache, archiveCacheDir))
	if err != nil || len(entries) != 1 || entries[0].Name() != "lock" {
		t.Fatalf("failed download left cache entries: %v, %v", entries, err)
	}
	if err := prepareCache(t, m, cache); err != nil {
		t.Fatal(err)
	}
	if requests != 2 {
		t.Fatalf("downloads = %d, want 2", requests)
	}
}

func TestPreparePruningPreservesUnknownManagedEntries(t *testing.T) {
	m, data := cacheFixture(t)
	cache := t.TempDir()
	installCorpusTransport(t, func(*http.Request) (*http.Response, error) { return archiveResponse(data), nil })
	if err := prepareCache(t, m, cache); err != nil {
		t.Fatal(err)
	}
	managed := filepath.Join(cache, archiveCacheDir)
	for _, name := range []string{"notes.zip", "not-a-checksum.download", "backup"} {
		if err := os.WriteFile(filepath.Join(managed, name), []byte("keep"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	dir := filepath.Join(managed, strings.Repeat("0", 64)+".zip")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := prepareCache(t, m, cache); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"notes.zip", "not-a-checksum.download", "backup"} {
		body, err := os.ReadFile(filepath.Join(managed, name))
		if err != nil || string(body) != "keep" {
			t.Errorf("unrecognized entry %s changed: %q, %v", name, body, err)
		}
	}
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		t.Fatalf("directory was pruned as an archive: %v", err)
	}
}
