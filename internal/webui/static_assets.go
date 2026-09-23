package webui

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Static files are linked with a content version (/static/js/app.js?v=...).
// A request carrying the current version may be cached for a year, since an
// upgrade changes the version and so the URL; any other request revalidates.
const (
	staticCacheVersioned = "public, max-age=31536000, immutable"
	staticCacheOther     = "no-cache"
)

// assetVersions caches each static file's content version, keyed by its size
// and modification time so a replaced file gets a new version.
type assetVersions struct {
	mu     sync.Mutex
	byPath map[string]assetVersion
}

type assetVersion struct {
	size    int64
	modTime time.Time
	version string
}

func (a *assetVersions) version(file string) string {
	info, err := os.Stat(file)
	if err != nil || info.IsDir() {
		return ""
	}
	a.mu.Lock()
	cached, ok := a.byPath[file]
	a.mu.Unlock()
	if ok && cached.size == info.Size() && cached.modTime.Equal(info.ModTime()) {
		return cached.version
	}
	// #nosec G304 -- file is a cleaned path under the UI static directory.
	f, err := os.Open(file)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	v := hex.EncodeToString(h.Sum(nil))[:12]
	a.mu.Lock()
	if a.byPath == nil {
		a.byPath = map[string]assetVersion{}
	}
	a.byPath[file] = assetVersion{size: info.Size(), modTime: info.ModTime(), version: v}
	a.mu.Unlock()
	return v
}

// staticFile maps a URL path below /static/ to a file in dir. path.Clean
// keeps it inside dir.
func staticFile(dir, rel string) string {
	return filepath.Join(dir, filepath.FromSlash(path.Clean("/"+rel)))
}

// assetURL is the versioned URL of a file below the static directory, for
// templates. A file that cannot be read gets the plain URL.
func (s *Server) assetURL(rel string) string {
	u := "/static/" + strings.TrimPrefix(rel, "/")
	if v := s.assets.version(staticFile(s.staticDir, rel)); v != "" {
		u += "?v=" + v
	}
	return u
}

// gzipTypes are the static file types worth compressing; fonts in woff2 and
// images are compressed already.
var gzipTypes = map[string]bool{".js": true, ".css": true, ".svg": true, ".json": true, ".map": true, ".ttf": true}

func (s *Server) staticHandler(dir string) http.Handler {
	files := http.StripPrefix("/static/", http.FileServer(noListDir{http.Dir(dir)}))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rel := strings.TrimPrefix(r.URL.Path, "/static/")
		cache := staticCacheOther
		if v := r.URL.Query().Get("v"); v != "" && v == s.assets.version(staticFile(dir, rel)) {
			cache = staticCacheVersioned
		}
		w.Header().Set("Cache-Control", cache)
		if !gzipTypes[strings.ToLower(path.Ext(rel))] {
			files.ServeHTTP(w, r)
			return
		}
		w.Header().Add("Vary", "Accept-Encoding")
		// A range is a byte range of the file; it cannot be served encoded.
		if r.Header.Get("Range") != "" || !acceptsGzip(r) {
			files.ServeHTTP(w, r)
			return
		}
		gw := &gzipResponseWriter{ResponseWriter: w}
		defer gw.close()
		files.ServeHTTP(gw, r)
	})
}

func acceptsGzip(r *http.Request) bool {
	for _, part := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		enc, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		if strings.EqualFold(strings.TrimSpace(enc), "gzip") {
			return strings.ReplaceAll(strings.TrimSpace(params), " ", "") != "q=0"
		}
	}
	return false
}

// gzipResponseWriter compresses a 200 response body. Other statuses (304,
// errors) pass through untouched.
type gzipResponseWriter struct {
	http.ResponseWriter
	zw          *gzip.Writer
	wroteHeader bool
}

func (g *gzipResponseWriter) WriteHeader(code int) {
	if g.wroteHeader {
		return
	}
	g.wroteHeader = true
	if code == http.StatusOK && g.Header().Get("Content-Encoding") == "" {
		g.Header().Del("Content-Length")
		g.Header().Set("Content-Encoding", "gzip")
		g.zw = gzip.NewWriter(g.ResponseWriter)
	}
	g.ResponseWriter.WriteHeader(code)
}

func (g *gzipResponseWriter) Write(p []byte) (int, error) {
	if !g.wroteHeader {
		g.WriteHeader(http.StatusOK)
	}
	if g.zw != nil {
		return g.zw.Write(p)
	}
	return g.ResponseWriter.Write(p)
}

func (g *gzipResponseWriter) close() {
	if g.zw != nil {
		_ = g.zw.Close()
	}
}
