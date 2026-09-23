package webui

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

func newRealUIServer(t *testing.T) *Server {
	t.Helper()
	uiDir, err := filepath.Abs("../../ui")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{StatePath: t.TempDir()}
	cfg.WebUI.UIDir = uiDir
	cfg.WebUI.Tokens = []config.WebUIToken{{Name: "ops", Token: "tok", Scope: "admin"}}
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	s, err := New(cfg, st)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func getStatic(s *Server, target string, header map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	for k, v := range header {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.httpSrv.Handler.ServeHTTP(w, req)
	return w
}

var staticRef = regexp.MustCompile(`(?:src|href)="(/static/[^"]+)"`)

// Pages link static files with a content version, so a browser can keep
// them for a long time and still fetch a new copy after an upgrade.
func TestPagesLinkVersionedStaticFiles(t *testing.T) {
	s := newRealUIServer(t)
	w := httptest.NewRecorder()
	s.handleHardening(w, httptest.NewRequest(http.MethodGet, "/hardening", nil))
	refs := staticRef.FindAllStringSubmatch(w.Body.String(), -1)
	if len(refs) == 0 {
		t.Fatal("page links no static files")
	}
	for _, m := range refs {
		if !strings.Contains(m[1], "?v=") {
			t.Errorf("%s has no version", m[1])
		}
	}
}

// Every template links static files through the asset helper.
func TestTemplatesLinkStaticFilesThroughTheAssetHelper(t *testing.T) {
	files, err := filepath.Glob("../../ui/templates/*.html")
	if err != nil {
		t.Fatal(err)
	}
	literal := regexp.MustCompile(`(?:src|href)="/static/`)
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if loc := literal.FindIndex(data); loc != nil {
			t.Errorf("%s links %q without {{asset}}", filepath.Base(f), data[loc[0]:min(len(data), loc[1]+30)])
		}
	}
}

func TestStaticCachePolicy(t *testing.T) {
	s := newRealUIServer(t)
	versioned := s.assetURL("js/csrf.js")
	if w := getStatic(s, versioned, nil); w.Code != http.StatusOK || !strings.Contains(w.Header().Get("Cache-Control"), "immutable") {
		t.Errorf("current version: code %d, Cache-Control %q, want a long immutable cache", w.Code, w.Header().Get("Cache-Control"))
	}
	for _, target := range []string{"/static/js/csrf.js", "/static/js/csrf.js?v=stale"} {
		w := getStatic(s, target, nil)
		if cc := w.Header().Get("Cache-Control"); w.Code != http.StatusOK || cc != "no-cache" {
			t.Errorf("%s: code %d, Cache-Control %q, want no-cache (revalidate)", target, w.Code, cc)
		}
	}
}

func TestStaticTextIsGzipped(t *testing.T) {
	s := newRealUIServer(t)
	want, err := os.ReadFile("../../ui/static/js/csrf.js")
	if err != nil {
		t.Fatal(err)
	}
	w := getStatic(s, "/static/js/csrf.js", map[string]string{"Accept-Encoding": "gzip"})
	if w.Header().Get("Content-Encoding") != "gzip" || !strings.Contains(w.Header().Get("Vary"), "Accept-Encoding") {
		t.Fatalf("headers %v, want gzip with Vary: Accept-Encoding", w.Header())
	}
	zr, err := gzip.NewReader(w.Body)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(zr)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("gzipped body does not decode to the file (err %v)", err)
	}

	// No encoding without Accept-Encoding, and never on a range request.
	if w := getStatic(s, "/static/js/csrf.js", nil); w.Header().Get("Content-Encoding") != "" || !bytes.Equal(w.Body.Bytes(), want) {
		t.Error("plain request was encoded")
	}
	if w := getStatic(s, "/static/js/csrf.js", map[string]string{"Accept-Encoding": "gzip", "Range": "bytes=0-9"}); w.Header().Get("Content-Encoding") != "" || w.Code != http.StatusPartialContent {
		t.Errorf("range request: code %d, encoding %q", w.Code, w.Header().Get("Content-Encoding"))
	}
}

func TestStaticGzipQuality(t *testing.T) {
	s := newRealUIServer(t)
	for _, tc := range []struct {
		accept string
		gzip   bool
	}{
		{"gzip;q=0", false}, {"gzip;q=0.0", false}, {"gzip;q=0.000", false},
		{"gzip;q=0.5", true}, {"br, GZIP; q=1.0", true},
		{"*;q=1", true}, {"gzip;q=0, *;q=1", false},
	} {
		w := getStatic(s, "/static/js/csrf.js", map[string]string{"Accept-Encoding": tc.accept})
		if got := w.Header().Get("Content-Encoding") == "gzip"; got != tc.gzip {
			t.Errorf("Accept-Encoding %q: gzip=%v, want %v", tc.accept, got, tc.gzip)
		}
	}
}

func TestStaticHeadAndNotModifiedHaveNoBody(t *testing.T) {
	s := newRealUIServer(t)
	initial := getStatic(s, "/static/js/csrf.js", nil)
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		for _, conditional := range []bool{false, true} {
			if method == http.MethodGet && !conditional {
				continue
			}
			r := httptest.NewRequest(method, "/static/js/csrf.js", nil)
			r.Header.Set("Accept-Encoding", "gzip")
			want := http.StatusOK
			if conditional {
				r.Header.Set("If-Modified-Since", initial.Header().Get("Last-Modified"))
				want = http.StatusNotModified
			}
			w := httptest.NewRecorder()
			s.httpSrv.Handler.ServeHTTP(w, r)
			if w.Code != want || w.Body.Len() != 0 {
				t.Errorf("%s conditional=%v: status=%d body=%d bytes", method, conditional, w.Code, w.Body.Len())
			}
			if !strings.Contains(w.Header().Get("Vary"), "Accept-Encoding") {
				t.Error("missing encoding variation")
			}
		}
	}
}

func TestStaticEmptyFileHasValidGzipBody(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "empty.js"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	s := &Server{staticDir: dir}
	r := httptest.NewRequest(http.MethodGet, "/static/empty.js", nil)
	r.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	s.staticHandler(dir).ServeHTTP(w, r)
	if w.Header().Get("Content-Encoding") != "gzip" {
		t.Fatal("missing gzip encoding")
	}
	zr, err := gzip.NewReader(w.Body)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = zr.Close() }()
	body, err := io.ReadAll(zr)
	if err != nil || len(body) != 0 {
		t.Fatalf("empty asset decoded to %q, err=%v", body, err)
	}
}

func TestStaticVersionChangesAfterPreservedTimestampReplacement(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "app.js")
	stamp := time.Date(2026, 9, 23, 0, 0, 0, 0, time.UTC)
	write := func(path, body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}
	write(file, "one")
	s := &Server{staticDir: dir}
	oldURL := s.assetURL("app.js")
	write(filepath.Join(dir, "replacement"), "two")
	if err := os.Rename(filepath.Join(dir, "replacement"), file); err != nil {
		t.Fatal(err)
	}
	if got := s.assetURL("app.js"); got == oldURL {
		t.Errorf("replacement kept stale asset URL %s", got)
	}
	w := httptest.NewRecorder()
	s.staticHandler(dir).ServeHTTP(w, httptest.NewRequest(http.MethodGet, oldURL, nil))
	if w.Header().Get("Cache-Control") != staticCacheOther || w.Body.String() != "two" {
		t.Errorf("stale version served as immutable: headers=%v body=%q", w.Header(), w.Body.String())
	}
}

type changingStaticFile struct {
	http.File
	change func()
}

func (f *changingStaticFile) Read(p []byte) (int, error) {
	n, err := f.File.Read(p)
	if f.change != nil {
		f.change()
		f.change = nil
	}
	return n, err
}

func TestStaticVersionRejectsChangesDuringHash(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.js")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var versions assetVersions
	changing := &changingStaticFile{File: f, change: func() {
		if err := os.WriteFile(path, []byte("new contents"), 0o600); err != nil {
			t.Fatal(err)
		}
	}}
	if got := versions.versionOf(path, changing); got != "" {
		t.Fatalf("unstable file received version %q", got)
	}
	stable := versions.version(path)
	if stable == "" || versions.version(path) != stable {
		t.Fatal("stable replacement did not get a reusable version")
	}
}

func TestStaticVersionUsesTheServedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.js")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var versions assetVersions
	oldVersion := versions.version(path)
	replacement := filepath.Join(dir, "replacement")
	if err := os.WriteFile(replacement, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	if got := versions.versionOf(path, f); got != oldVersion {
		t.Fatalf("open snapshot version=%q, want %q", got, oldVersion)
	}
	if got := versions.version(path); got == oldVersion || got == "" {
		t.Fatalf("replacement version=%q, want a different version", got)
	}
	if body, err := io.ReadAll(f); err != nil || string(body) != "old" {
		t.Fatalf("served snapshot=%q err=%v", body, err)
	}
}
