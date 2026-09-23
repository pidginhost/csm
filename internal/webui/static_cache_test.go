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
