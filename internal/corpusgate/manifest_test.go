package corpusgate

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/pidginhost/csm/internal/cms"
)

// supportedKindNames is an independent expectation of the supported set so
// the manifest tests do not merely mirror cms.All().
var supportedKindNames = []string{"wordpress", "joomla", "drupal", "opencart", "magento"}

func validSource(id, kind string) Source {
	return Source{ID: id, Version: "1.0", CMS: kind,
		URL:    "https://downloads.example.com/" + id + ".zip",
		SHA256: strings.Repeat("ab", 32), License: "GPL-2.0-or-later",
		LicenseFile: id + "/license.txt", Files: 3}
}

// pendingExcept lists every supported kind except the given ones as pending.
func pendingExcept(sourced ...string) []PendingCMS {
	skip := map[string]bool{}
	for _, s := range sourced {
		skip[s] = true
	}
	var out []PendingCMS
	for _, k := range supportedKindNames {
		if !skip[k] {
			out = append(out, PendingCMS{CMS: k, Reason: "await precision items; see ROADMAP"})
		}
	}
	return out
}

func coveredManifest() Manifest {
	return Manifest{Version: ManifestVersion,
		Sources: []Source{validSource("wordpress", "wordpress"), validSource("woocommerce", "wordpress"), validSource("joomla", "joomla")},
		Pending: pendingExcept("wordpress", "joomla")}
}

func TestManifestValidateAcceptsCompleteDisposition(t *testing.T) {
	if err := coveredManifest().Validate(); err != nil {
		t.Fatal(err)
	}
	if len(cms.All()) != len(supportedKindNames) {
		t.Fatalf("supported set changed; update supportedKindNames and the repository manifest")
	}
}

func TestManifestValidateRejects(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Manifest)
		want   []string // substrings the error must contain
	}{
		{"version 0", func(m *Manifest) { m.Version = 0 }, []string{"version 0", "version 2", "cms"}},
		{"version 1", func(m *Manifest) { m.Version = 1 }, []string{"version 1", "version 2", "cms"}},
		{"version 3", func(m *Manifest) { m.Version = 3 }, []string{"version 3", "version 2", "cms"}},
		{"no sources", func(m *Manifest) { m.Sources = nil; m.Pending = pendingExcept() }, []string{"no source"}},
		{"all pending", func(m *Manifest) { m.Sources = nil; m.Pending = pendingExcept() }, []string{"no source"}},
		{"missing source cms", func(m *Manifest) { m.Sources[0].CMS = "" }, []string{"wordpress", "cms"}},
		{"unknown source cms", func(m *Manifest) { m.Sources[2].CMS = "prestashop" }, []string{"joomla", "prestashop"}},
		{"whitespace source cms", func(m *Manifest) { m.Sources[2].CMS = " joomla" }, []string{`" joomla"`}},
		{"case-variant source cms", func(m *Manifest) { m.Sources[2].CMS = "Joomla" }, []string{`"Joomla"`}},
		{"unknown pending cms", func(m *Manifest) { m.Pending[0].CMS = "prestashop" }, []string{"pending", "prestashop"}},
		{"whitespace pending cms", func(m *Manifest) { m.Pending[0].CMS = "drupal " }, []string{`"drupal "`}},
		{"case-variant pending cms", func(m *Manifest) { m.Pending[0].CMS = "DRUPAL" }, []string{`"DRUPAL"`}},
		{"duplicate pending", func(m *Manifest) { m.Pending = append(m.Pending, m.Pending[0]) }, []string{"drupal", "twice"}},
		{"blank reason", func(m *Manifest) { m.Pending[0].Reason = "" }, []string{"drupal", "reason"}},
		{"whitespace reason", func(m *Manifest) { m.Pending[1].Reason = " \t\n" }, []string{"opencart", "reason"}},
		{"sourced and pending", func(m *Manifest) { m.Pending = append(m.Pending, PendingCMS{CMS: "joomla", Reason: "x"}) }, []string{"joomla", "both"}},
		{"missing disposition", func(m *Manifest) { m.Pending = m.Pending[1:] }, []string{"drupal", "neither"}},
		{"duplicate source id", func(m *Manifest) { m.Sources = append(m.Sources, validSource("joomla", "joomla")) }, []string{"joomla", "twice"}},
		{"http url", func(m *Manifest) { m.Sources[1].URL = "http://downloads.example.com/x.zip" }, []string{"woocommerce", "url"}},
		{"unparseable url", func(m *Manifest) { m.Sources[1].URL = "https://[bad" }, []string{"woocommerce", "url"}},
		{"url without host", func(m *Manifest) { m.Sources[1].URL = "https:///x.zip" }, []string{"woocommerce", "url"}},
		{"short digest", func(m *Manifest) { m.Sources[0].SHA256 = "abcd" }, []string{"wordpress", "sha256"}},
		{"non-hex digest", func(m *Manifest) { m.Sources[0].SHA256 = strings.Repeat("zz", 32) }, []string{"wordpress", "sha256"}},
		{"empty id", func(m *Manifest) { m.Sources[0].ID = "" }, []string{"id"}},
		{"slash in id", func(m *Manifest) { m.Sources[0].ID = "a/b" }, []string{"a/b", "id"}},
		{"dot id", func(m *Manifest) { m.Sources[0].ID = "." }, []string{"id"}},
		{"dot-dot id", func(m *Manifest) { m.Sources[0].ID = ".." }, []string{"id"}},
		{"empty version", func(m *Manifest) { m.Sources[0].Version = "" }, []string{"wordpress", "version"}},
		{"unsafe version", func(m *Manifest) { m.Sources[0].Version = "1\\0" }, []string{"wordpress", "version"}},
		{"empty license", func(m *Manifest) { m.Sources[0].License = "" }, []string{"wordpress", "license"}},
		{"empty license path", func(m *Manifest) { m.Sources[0].LicenseFile = "" }, []string{"wordpress", "license_file"}},
		{"absolute license path", func(m *Manifest) { m.Sources[0].LicenseFile = "/etc/passwd" }, []string{"wordpress", "license_file"}},
		{"escaping license path", func(m *Manifest) { m.Sources[0].LicenseFile = "../x" }, []string{"wordpress", "license_file"}},
		{"zero files", func(m *Manifest) { m.Sources[0].Files = 0 }, []string{"wordpress", "files"}},
		{"too many files", func(m *Manifest) { m.Sources[0].Files = 30001 }, []string{"wordpress", "files"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := coveredManifest()
			tc.mutate(&m)
			err := m.Validate()
			if err == nil {
				t.Fatal("expected error")
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q does not mention %q", err, w)
				}
			}
		})
	}
	for _, n := range []int{1, 30000} {
		m := coveredManifest()
		m.Sources[0].Files = n
		if err := m.Validate(); err != nil {
			t.Errorf("files=%d rejected: %v", n, err)
		}
	}
}

// countingTransport records every HTTP request and refuses it.
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

func writeSentinel(t *testing.T, dir, name string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func assertUntouched(t *testing.T, dir string, sentinel string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("%s gained entries: %v", dir, entries)
	}
	data, err := os.ReadFile(sentinel)
	if err != nil || string(data) != "sentinel" {
		t.Fatalf("sentinel changed: %q %v", data, err)
	}
}

func TestPrepareInvalidManifestHasNoSideEffects(t *testing.T) {
	ct := installCountingTransport(t)
	cases := map[string]func(*Manifest){
		"version 1":           func(m *Manifest) { m.Version = 1 },
		"missing cms":         func(m *Manifest) { m.Sources[0].CMS = "" },
		"bad later source":    func(m *Manifest) { m.Sources[2].SHA256 = "nope" },
		"missing disposition": func(m *Manifest) { m.Pending = nil },
		"overlap":             func(m *Manifest) { m.Pending = append(m.Pending, PendingCMS{CMS: "wordpress", Reason: "x"}) },
		"unknown pending":     func(m *Manifest) { m.Pending[0].CMS = "prestashop" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cache := filepath.Join(t.TempDir(), "cache")
			sentinel := writeSentinel(t, cache, "keep.zip")
			dest := filepath.Join(t.TempDir(), "corpus")
			m := coveredManifest()
			mutate(&m)
			before := ct.n.Load()
			if _, err := Prepare(context.Background(), m, cache, dest); err == nil {
				t.Fatal("invalid manifest accepted")
			}
			if ct.n.Load() != before {
				t.Fatal("invalid manifest caused an HTTP request")
			}
			if _, err := os.Stat(dest); !os.IsNotExist(err) {
				t.Fatalf("destination created for invalid manifest: %v", err)
			}
			assertUntouched(t, cache, sentinel)
		})
	}
}

// repoManifestPath locates the checked-in manifest from this source file,
// independent of the process working directory.
func repoManifestPath(t *testing.T) string {
	t.Helper()
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	for dir := filepath.Dir(here); ; dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return filepath.Join(dir, "scripts", "clean-corpus", "manifest.json")
		}
		if filepath.Dir(dir) == dir {
			t.Fatalf("go.mod not found above %s", here)
		}
	}
}

// The checked-in manifest must validate offline. This proves coverage
// disposition for every supported CMS, not archive contents or scan results.
func TestRepositoryManifestValidates(t *testing.T) {
	t.Chdir(t.TempDir())
	data, err := os.ReadFile(repoManifestPath(t)) // #nosec G304 -- repository fixture located from source
	if err != nil {
		t.Fatal(err)
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	sourced := map[string]bool{}
	for _, s := range m.Sources {
		sourced[s.CMS] = true
	}
	if len(sourced) != 1 || !sourced["wordpress"] {
		t.Errorf("sourced kinds %v; only wordpress archives are pinned today, update this test when a source lands", sourced)
	}
	pending := map[string]string{}
	for _, p := range m.Pending {
		pending[p.CMS] = p.Reason
	}
	for _, k := range []string{"joomla", "drupal", "opencart", "magento"} {
		if !strings.Contains(pending[k], "Clean corpus growth and per-detector false-positive tracking") {
			t.Errorf("%s pending reason must name the roadmap item: %q", k, pending[k])
		}
	}
}
