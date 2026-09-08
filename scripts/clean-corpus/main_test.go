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
	if back.Version != corpusgate.ManifestVersion || len(back.Sources) != 3 || len(back.Pending) != 3 {
		t.Fatalf("archived manifest lost fields: %+v", back)
	}
	for i, s := range back.Sources {
		if s.CMS != m.Sources[i].CMS || s.SHA256 != m.Sources[i].SHA256 {
			t.Errorf("source %d changed: %+v", i, s)
		}
	}
	for i, p := range back.Pending {
		if p != m.Pending[i] {
			t.Errorf("pending %d changed: %+v", i, p)
		}
	}
	inventory, err := os.ReadFile(filepath.Join(out, "inventory.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rows []corpusgate.File
	if err = json.Unmarshal(inventory, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 6 || rows[0].SHA256 == "" {
		t.Fatalf("inventory %+v", rows)
	}
}

func TestRunInvalidManifestHasNoSideEffects(t *testing.T) {
	ct := installCountingTransport(t)
	cache := filepath.Join(t.TempDir(), "cache")
	good := fixtureSource(t, cache, "wp", "wordpress")
	sentinel := filepath.Join(cache, "wp-1.0.zip")
	sentinelBytes, err := os.ReadFile(sentinel)
	if err != nil {
		t.Fatal(err)
	}
	pending := []corpusgate.PendingCMS{{CMS: "joomla", Reason: "x"}, {CMS: "drupal", Reason: "x"}, {CMS: "opencart", Reason: "x"}, {CMS: "magento", Reason: "x"}}
	cases := map[string]string{
		"malformed json": "{not json",
		"version 1":      string(mustJSON(t, corpusgate.Manifest{Version: 1, Sources: []corpusgate.Source{good}, Pending: pending})),
		"missing cms": string(mustJSON(t, corpusgate.Manifest{Version: 2, Sources: []corpusgate.Source{{ID: good.ID, Version: good.Version, URL: good.URL,
			SHA256: good.SHA256, License: good.License, LicenseFile: good.LicenseFile, Files: good.Files}}, Pending: pending})),
		"bad second source": string(mustJSON(t, corpusgate.Manifest{Version: 2, Sources: []corpusgate.Source{good, {ID: "second", CMS: "wordpress", Version: "1.0",
			URL: "https://downloads.example.com/second.zip", SHA256: "nope", License: "x", LicenseFile: "second/license.txt", Files: 1}}, Pending: pending})),
		"missing disposition": string(mustJSON(t, corpusgate.Manifest{Version: 2, Sources: []corpusgate.Source{good}, Pending: pending[1:]})),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "manifest.json")
			if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			dest := filepath.Join(t.TempDir(), "corpus")
			out := filepath.Join(t.TempDir(), "out")
			var stdout bytes.Buffer
			before := ct.n.Load()
			err := run(p, cache, dest, out, &stdout)
			if err == nil {
				t.Fatal("invalid manifest accepted")
			}
			if name == "version 1" && !strings.Contains(err.Error(), "version 1") {
				t.Errorf("diagnostic %q does not name the version", err)
			}
			if ct.n.Load() != before {
				t.Error("HTTP request made for an invalid manifest")
			}
			if stdout.Len() != 0 {
				t.Errorf("summary printed on failure: %q", stdout.String())
			}
			for _, d := range []string{dest, out} {
				if _, statErr := os.Stat(d); !os.IsNotExist(statErr) {
					t.Errorf("%s created for an invalid manifest", d)
				}
			}
			now, err := os.ReadFile(sentinel)
			if err != nil || !bytes.Equal(now, sentinelBytes) {
				t.Error("cached archive changed")
			}
		})
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
