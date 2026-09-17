package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/pidginhost/csm/internal/corpusgate"
)

// writeFixtureArchive writes a tiny benign ZIP for id into cache under the
// name Prepare expects and returns its digest and file count.
func writeFixtureArchive(t *testing.T, cache, id string) (digest string, files int) {
	t.Helper()
	var buf bytes.Buffer
	z := zip.NewWriter(&buf)
	entries := []struct{ name, body string }{{id + "/license.txt", "test license"}, {id + "/index.php", "<?php echo 'clean';"}}
	for _, e := range entries {
		w, err := z.Create(e.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(e.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cache, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cache, id+"-1.0.zip"), buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(buf.Bytes())
	return hex.EncodeToString(sum[:]), len(entries)
}

func fixtureSource(t *testing.T, cache, id, kind string) corpusgate.Source {
	t.Helper()
	digest, files := writeFixtureArchive(t, cache, id)
	return corpusgate.Source{ID: id, CMS: kind, Version: "1.0", URL: "https://downloads.example.com/" + id + ".zip",
		SHA256: digest, License: "GPL-2.0-or-later", LicenseFile: id + "/license.txt", Files: files}
}

func writeManifest(t *testing.T, m corpusgate.Manifest) string {
	t.Helper()
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

type countingTransport struct{ n atomic.Int32 }

func (c *countingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	c.n.Add(1)
	return nil, http.ErrNotSupported
}

func installCountingTransport(t *testing.T) *countingTransport {
	t.Helper()
	ct := &countingTransport{}
	prev := http.DefaultTransport
	http.DefaultTransport = ct
	t.Cleanup(func() { http.DefaultTransport = prev })
	return ct
}

func TestRunPrintsSourcedAndPendingSummary(t *testing.T) {
	ct := installCountingTransport(t)
	cache := filepath.Join(t.TempDir(), "cache")
	m := corpusgate.Manifest{Version: corpusgate.ManifestVersion,
		Sources: []corpusgate.Source{fixtureSource(t, cache, "wp", "wordpress"), fixtureSource(t, cache, "plugin", "wordpress"), fixtureSource(t, cache, "joomla", "joomla")},
		Pending: []corpusgate.PendingCMS{{CMS: "opencart", Reason: "await c"}, {CMS: "drupal", Reason: "await b"}, {CMS: "magento", Reason: "await d"}}}
	out := filepath.Join(t.TempDir(), "out")
	var stdout bytes.Buffer
	if err := run(writeManifest(t, m), cache, filepath.Join(t.TempDir(), "corpus"), out, &stdout); err != nil {
		t.Fatal(err)
	}
	if ct.n.Load() != 0 {
		t.Fatal("cached archives must not be downloaded")
	}
	want := "Verified and extracted 6 files from 3 pinned applications\n" +
		"sourced: joomla, wordpress\n" +
		"pending (no clean-corpus evidence):\n" +
		"  drupal: await b\n" +
		"  magento: await d\n" +
		"  opencart: await c\n"
	if stdout.String() != want {
		t.Fatalf("summary:\n%s\nwant:\n%s", stdout.String(), want)
	}
	archived, err := os.ReadFile(filepath.Join(out, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var back corpusgate.Manifest
	if err = json.Unmarshal(archived, &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, m) {
		t.Fatalf("archived manifest = %+v, want %+v", back, m)
	}
	inventory, err := os.ReadFile(filepath.Join(out, "inventory.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rows []corpusgate.File
	if err = json.Unmarshal(inventory, &rows); err != nil {
		t.Fatal(err)
	}
	var wantRows []corpusgate.File
	for _, id := range []string{"wp", "plugin", "joomla"} {
		for _, entry := range []struct{ name, body string }{{"index.php", "<?php echo 'clean';"}, {"license.txt", "test license"}} {
			digest := sha256.Sum256([]byte(entry.body))
			wantRows = append(wantRows, corpusgate.File{Path: id + "/" + id + "/" + entry.name,
				SHA256: hex.EncodeToString(digest[:]), Bytes: int64(len(entry.body))})
		}
	}
	sort.Slice(wantRows, func(i, j int) bool { return wantRows[i].Path < wantRows[j].Path })
	if !reflect.DeepEqual(rows, wantRows) {
		t.Fatalf("inventory = %+v, want %+v", rows, wantRows)
	}
}

func TestRunInvalidManifestHasNoSideEffects(t *testing.T) {
	ct := installCountingTransport(t)
	fixtureCache := t.TempDir()
	good := fixtureSource(t, fixtureCache, "wp", "wordpress")
	archive, err := os.ReadFile(filepath.Join(fixtureCache, "wp-1.0.zip"))
	if err != nil {
		t.Fatal(err)
	}
	type invalidCase struct{ name, body, want string }
	cases := []invalidCase{{"malformed json", "{not json", "invalid character"}}
	for _, tc := range []struct {
		name   string
		mutate func(*corpusgate.Manifest)
		want   string
	}{
		{"version 0", func(m *corpusgate.Manifest) { m.Version = 0 }, "version 0"},
		{"version 1", func(m *corpusgate.Manifest) { m.Version = 1 }, "version 1"},
		{"version 3", func(m *corpusgate.Manifest) { m.Version = 3 }, "version 3"},
		{"no sources", func(m *corpusgate.Manifest) { m.Sources = nil; m.Pending = nil }, "no source"},
		{"all pending", func(m *corpusgate.Manifest) {
			m.Sources = nil
			m.Pending = append(m.Pending, corpusgate.PendingCMS{CMS: "wordpress", Reason: "await corpus"})
		}, "no source"},
		{"missing cms", func(m *corpusgate.Manifest) { m.Sources[0].CMS = "" }, "cms field"},
		{"unknown cms", func(m *corpusgate.Manifest) { m.Sources[0].CMS = "prestashop" }, "prestashop"},
		{"whitespace cms", func(m *corpusgate.Manifest) { m.Sources[0].CMS = " wordpress" }, `" wordpress"`},
		{"case-variant cms", func(m *corpusgate.Manifest) { m.Sources[0].CMS = "WordPress" }, `"WordPress"`},
		{"missing pending cms", func(m *corpusgate.Manifest) { m.Pending[0].CMS = "" }, `pending cms ""`},
		{"unknown pending cms", func(m *corpusgate.Manifest) { m.Pending[0].CMS = "prestashop" }, "prestashop"},
		{"whitespace pending cms", func(m *corpusgate.Manifest) { m.Pending[0].CMS = " joomla" }, `" joomla"`},
		{"case-variant pending cms", func(m *corpusgate.Manifest) { m.Pending[0].CMS = "Joomla" }, `"Joomla"`},
		{"duplicate pending", func(m *corpusgate.Manifest) { m.Pending = append(m.Pending, m.Pending[0]) }, "twice"},
		{"blank reason", func(m *corpusgate.Manifest) { m.Pending[0].Reason = "" }, "reason"},
		{"whitespace reason", func(m *corpusgate.Manifest) { m.Pending[0].Reason = " \t\n" }, "reason"},
		{"overlap", func(m *corpusgate.Manifest) {
			m.Pending = append(m.Pending, corpusgate.PendingCMS{CMS: "wordpress", Reason: "await corpus"})
		}, "both"},
		{"missing disposition", func(m *corpusgate.Manifest) { m.Pending = m.Pending[1:] }, "neither"},
		{"duplicate source", func(m *corpusgate.Manifest) { m.Sources = append(m.Sources, good) }, "twice"},
		{"bad second source", func(m *corpusgate.Manifest) {
			bad := good
			bad.ID, bad.SHA256 = "second", "nope"
			m.Sources = append(m.Sources, bad)
		}, `source "second": sha256`},
		{"http url", func(m *corpusgate.Manifest) { m.Sources[0].URL = "http://example.org/app.zip" }, "url"},
		{"unparseable url", func(m *corpusgate.Manifest) { m.Sources[0].URL = "https://[bad" }, "url"},
		{"url without host", func(m *corpusgate.Manifest) { m.Sources[0].URL = "https:///app.zip" }, "url"},
		{"short digest", func(m *corpusgate.Manifest) { m.Sources[0].SHA256 = "abcd" }, "sha256"},
		{"nonhex digest", func(m *corpusgate.Manifest) { m.Sources[0].SHA256 = strings.Repeat("zz", 32) }, "sha256"},
		{"empty id", func(m *corpusgate.Manifest) { m.Sources[0].ID = "" }, "id"},
		{"slash in id", func(m *corpusgate.Manifest) { m.Sources[0].ID = "a/b" }, "id"},
		{"backslash in id", func(m *corpusgate.Manifest) { m.Sources[0].ID = "a\\b" }, "id"},
		{"nul in id", func(m *corpusgate.Manifest) { m.Sources[0].ID = "a\x00b" }, "id"},
		{"dot id", func(m *corpusgate.Manifest) { m.Sources[0].ID = "." }, "id"},
		{"dot-dot id", func(m *corpusgate.Manifest) { m.Sources[0].ID = ".." }, "id"},
		{"empty version", func(m *corpusgate.Manifest) { m.Sources[0].Version = "" }, "version"},
		{"slash in version", func(m *corpusgate.Manifest) { m.Sources[0].Version = "1/0" }, "version"},
		{"backslash in version", func(m *corpusgate.Manifest) { m.Sources[0].Version = "1\\0" }, "version"},
		{"nul in version", func(m *corpusgate.Manifest) { m.Sources[0].Version = "1\x000" }, "version"},
		{"empty license", func(m *corpusgate.Manifest) { m.Sources[0].License = "" }, "license"},
		{"empty license path", func(m *corpusgate.Manifest) { m.Sources[0].LicenseFile = "" }, "license_file"},
		{"absolute license path", func(m *corpusgate.Manifest) { m.Sources[0].LicenseFile = "/license.txt" }, "license_file"},
		{"escaping license path", func(m *corpusgate.Manifest) { m.Sources[0].LicenseFile = "../license.txt" }, "license_file"},
		{"zero files", func(m *corpusgate.Manifest) { m.Sources[0].Files = 0 }, "files"},
		{"negative files", func(m *corpusgate.Manifest) { m.Sources[0].Files = -1 }, "files"},
		{"too many files", func(m *corpusgate.Manifest) { m.Sources[0].Files = 30001 }, "files"},
	} {
		m := corpusgate.Manifest{Version: corpusgate.ManifestVersion, Sources: []corpusgate.Source{good},
			Pending: []corpusgate.PendingCMS{{CMS: "joomla", Reason: "x"}, {CMS: "drupal", Reason: "x"}, {CMS: "opencart", Reason: "x"}, {CMS: "magento", Reason: "x"}}}
		tc.mutate(&m)
		cases = append(cases, invalidCase{tc.name, string(mustJSON(t, m)), tc.want})
	}
	for _, tc := range cases {
		for _, existing := range []bool{false, true} {
			state := "absent"
			if existing {
				state = "existing"
			}
			t.Run(tc.name+"/"+state, func(t *testing.T) {
				p := filepath.Join(t.TempDir(), "manifest.json")
				if err := os.WriteFile(p, []byte(tc.body), 0o600); err != nil {
					t.Fatal(err)
				}
				cache := filepath.Join(t.TempDir(), "cache")
				dest := filepath.Join(t.TempDir(), "corpus")
				out := filepath.Join(t.TempDir(), "out")
				sentinels := []struct {
					dir, name string
					data      []byte
				}{{cache, "wp-1.0.zip", archive}, {dest, "keep", []byte("sentinel")}, {out, "keep", []byte("sentinel")}}
				if existing {
					for _, s := range sentinels {
						if err := os.Mkdir(s.dir, 0o700); err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(filepath.Join(s.dir, s.name), s.data, 0o600); err != nil {
							t.Fatal(err)
						}
					}
				}
				var stdout bytes.Buffer
				before := ct.n.Load()
				err := run(p, cache, dest, out, &stdout)
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Errorf("error = %v, want diagnostic containing %q", err, tc.want)
				}
				if ct.n.Load() != before {
					t.Error("HTTP request made for an invalid manifest")
				}
				if stdout.Len() != 0 {
					t.Errorf("summary printed on failure: %q", stdout.String())
				}
				for _, s := range sentinels {
					if !existing {
						if _, statErr := os.Stat(s.dir); !os.IsNotExist(statErr) {
							t.Errorf("%s created for an invalid manifest: %v", s.dir, statErr)
						}
						continue
					}
					entries, err := os.ReadDir(s.dir)
					if err != nil || len(entries) != 1 || entries[0].Name() != s.name {
						t.Errorf("directory %s changed: %v, %v", s.dir, entries, err)
					}
					now, err := os.ReadFile(filepath.Join(s.dir, s.name))
					if err != nil || !bytes.Equal(now, s.data) {
						t.Errorf("sentinel in %s changed: %v", s.dir, err)
					}
				}
			})
		}
	}
}

func TestRunPreparationErrorPrintsNoSummary(t *testing.T) {
	installCountingTransport(t)
	cache := filepath.Join(t.TempDir(), "cache")
	bad := fixtureSource(t, cache, "wp", "wordpress")
	bad.SHA256 = strings.Repeat("00", 32)
	m := corpusgate.Manifest{Version: 2, Sources: []corpusgate.Source{bad},
		Pending: []corpusgate.PendingCMS{{CMS: "joomla", Reason: "x"}, {CMS: "drupal", Reason: "x"}, {CMS: "opencart", Reason: "x"}, {CMS: "magento", Reason: "x"}}}
	out := filepath.Join(t.TempDir(), "out")
	var stdout bytes.Buffer
	if err := run(writeManifest(t, m), cache, filepath.Join(t.TempDir(), "corpus"), out, &stdout); err == nil {
		t.Fatal("checksum mismatch accepted")
	}
	if stdout.Len() != 0 {
		t.Fatalf("summary printed after a preparation error: %q", stdout.String())
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("output directory created after a preparation error")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("closed pipe") }

func TestRunPropagatesWriterErrors(t *testing.T) {
	installCountingTransport(t)
	cache := filepath.Join(t.TempDir(), "cache")
	m := corpusgate.Manifest{Version: 2, Sources: []corpusgate.Source{fixtureSource(t, cache, "wp", "wordpress")},
		Pending: []corpusgate.PendingCMS{{CMS: "joomla", Reason: "x"}, {CMS: "drupal", Reason: "x"}, {CMS: "opencart", Reason: "x"}, {CMS: "magento", Reason: "x"}}}
	err := run(writeManifest(t, m), cache, filepath.Join(t.TempDir(), "corpus"), filepath.Join(t.TempDir(), "out"), failingWriter{})
	if err == nil || !strings.Contains(err.Error(), "closed pipe") {
		t.Fatalf("writer error not propagated: %v", err)
	}
}

func mustJSON(t *testing.T, m corpusgate.Manifest) []byte {
	t.Helper()
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
