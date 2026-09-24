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
	"strconv"
	"strings"
	"sync"

	"github.com/pidginhost/csm/internal/integrity"
)

// Static files are linked with a content version (/static/js/app.js?v=...).
// A request carrying the current version may be cached for a year, since an
// upgrade changes the version and so the URL; any other request revalidates.
const (
	staticCacheVersioned = "public, max-age=31536000, immutable"
	staticCacheOther     = "no-cache"
)

// assetVersions caches versions by file identity and change metadata, so an
// upgrade that preserves modification times still gets new URLs.
type assetVersions struct {
	mu     sync.Mutex
	byPath map[string]assetVersion
}

type assetVersion struct {
	info    os.FileInfo
	key     string
	version string
}

func (a *assetVersions) version(file string) string {
	// #nosec G304 -- file is a cleaned path under the UI static directory.
	f, err := os.Open(file)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	return a.versionOf(file, f)
}

func (a *assetVersions) versionOf(file string, f http.File) string {
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return ""
	}
	key := integrity.FileChangeKey(info)
	a.mu.Lock()
	cached, ok := a.byPath[file]
	a.mu.Unlock()
	if ok && cached.key == key && os.SameFile(cached.info, info) {
		return cached.version
	}
	h := sha256.New()
	_, hashErr := io.Copy(h, f)
	_, seekErr := f.Seek(0, io.SeekStart)
	if hashErr != nil || seekErr != nil {
		return ""
	}
	after, err := f.Stat()
	if err != nil || integrity.FileChangeKey(after) != key || !os.SameFile(info, after) {
		return ""
	}
	v := hex.EncodeToString(h.Sum(nil))[:12]
	a.mu.Lock()
	if a.byPath == nil {
		a.byPath = map[string]assetVersion{}
	}
	a.byPath[file] = assetVersion{info: info, key: key, version: v}
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

// Hash and serve the same open file. A pathname can be replaced by an upgrade
// between checking its version and opening it in FileServer.
type versionedStaticFS struct {
	http.FileSystem
	dir       string
	versions  *assetVersions
	requested string
	header    http.Header
}

func (fs versionedStaticFS) Open(name string) (http.File, error) {
	f, err := fs.FileSystem.Open(name)
	if err == nil && fs.requested != "" && fs.requested == fs.versions.versionOf(staticFile(fs.dir, name), f) {
		fs.header.Set("Cache-Control", staticCacheVersioned)
	}
	return f, err
}

func (s *Server) staticHandler(dir string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rel := strings.TrimPrefix(r.URL.Path, "/static/")
		w.Header().Set("Cache-Control", staticCacheOther)
		files := http.StripPrefix("/static/", http.FileServer(versionedStaticFS{
			FileSystem: noListDir{http.Dir(dir)}, dir: dir, versions: &s.assets,
			requested: r.URL.Query().Get("v"), header: w.Header(),
		}))
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
		gw := &gzipResponseWriter{ResponseWriter: w, head: r.Method == http.MethodHead}
		defer gw.close()
		files.ServeHTTP(gw, r)
	})
}

func acceptsGzip(r *http.Request) bool {
	wildcard := false
	for _, part := range strings.Split(strings.Join(r.Header.Values("Accept-Encoding"), ","), ",") {
		params := strings.Split(part, ";")
		enc := strings.TrimSpace(params[0])
		quality := 1.0
		for _, param := range params[1:] {
			name, value, _ := strings.Cut(strings.TrimSpace(param), "=")
			if strings.EqualFold(strings.TrimSpace(name), "q") {
				var err error
				quality, err = strconv.ParseFloat(strings.TrimSpace(value), 64)
				if err != nil {
					quality = 0
				}
			}
		}
		accepted := quality > 0 && quality <= 1
		if strings.EqualFold(enc, "gzip") {
			return accepted
		}
		if enc == "*" {
			wildcard = accepted
		}
	}
	return wildcard
}

// gzipResponseWriter compresses a 200 response body. Other statuses (304,
// errors) pass through untouched.
type gzipResponseWriter struct {
	http.ResponseWriter
	zw          *gzip.Writer
	head        bool
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
		if !g.head {
			g.zw = gzip.NewWriter(g.ResponseWriter)
		}
	}
	g.ResponseWriter.WriteHeader(code)
}

func (g *gzipResponseWriter) Write(p []byte) (int, error) {
	if !g.wroteHeader {
		g.WriteHeader(http.StatusOK)
	}
	if g.head {
		return len(p), nil
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
