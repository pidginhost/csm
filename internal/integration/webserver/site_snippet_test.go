package webserver

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// fakeSiteHandler is a fakeHandler whose sites read a per-site include, as
// cPanel's HTTPS site blocks do.
type fakeSiteHandler struct {
	fakeHandler
	sitePath   string
	siteBody   string
	active     bool
	rebuildErr error
	rebuilds   atomic.Int32
}

func (h *fakeSiteHandler) SiteSnippetPath() string { return h.sitePath }
func (h *fakeSiteHandler) SiteTemplate() string    { return h.siteBody }
func (h *fakeSiteHandler) SiteIncludeActive() (bool, error) {
	return h.active, nil
}
func (h *fakeSiteHandler) RebuildSiteIncludes() error {
	h.rebuilds.Add(1)
	if h.rebuildErr != nil {
		return h.rebuildErr
	}
	h.active = true
	return nil
}

func newSiteInstaller(t *testing.T, active bool) (*Installer, *fakeSiteHandler) {
	t.Helper()
	dir := t.TempDir()
	h := &fakeSiteHandler{
		fakeHandler: fakeHandler{kind: "apache", path: filepath.Join(dir, "csm-challenge.conf"), body: "RewriteEngine On\n"},
		sitePath:    filepath.Join(dir, "userdata", "csm-challenge.conf"),
		siteBody:    "RewriteEngine On\nRewriteRule ^ - [L]\n",
		active:      active,
	}
	i := newTestInstaller(t, &h.fakeHandler)
	i.Handler = h
	return i, h
}

func readVersioned(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if parseHeaderVersion(data) != TemplateVersion {
		t.Fatalf("%s lacks the managed version header: %q", path, data)
	}
	return string(data)
}

func TestInstallWritesTheSiteSnippetBesideTheServerSnippet(t *testing.T) {
	i, h := newSiteInstaller(t, true)
	if res, err := i.Install(); err != nil || res.Status != "ok" {
		t.Fatalf("Install = %+v, %v", res, err)
	}
	readVersioned(t, h.path)
	if body := readVersioned(t, h.sitePath); !strings.Contains(body, "RewriteRule ^ - [L]") {
		t.Fatalf("site snippet not rendered: %q", body)
	}
	if h.validates.Load() != 1 || h.reloads.Load() != 1 {
		t.Fatalf("validate/reload = %d/%d, want one each for both files", h.validates.Load(), h.reloads.Load())
	}
	if h.rebuilds.Load() != 0 {
		t.Fatal("rebuilt although the sites already read the include")
	}
	if res, err := i.Install(); err != nil || res.Status != "no-op" {
		t.Fatalf("second Install = %+v, %v; want no-op", res, err)
	}
}

// The daemon refreshes snippets on its own; it must never rebuild the web
// server configuration. Only the explicit command does.
func TestInstallRebuildsSiteIncludesOnlyWhenAsked(t *testing.T) {
	i, h := newSiteInstaller(t, false)
	res, err := i.Install()
	if err != nil || h.rebuilds.Load() != 0 {
		t.Fatalf("Install = %+v, %v, rebuilds %d; want no rebuild", res, err, h.rebuilds.Load())
	}
	if !strings.Contains(res.Message, "HTTPS") {
		t.Fatalf("message does not say HTTPS sites wait for a rebuild: %q", res.Message)
	}

	i.RebuildSiteIncludes = true
	res, err = i.Install()
	if err != nil || h.rebuilds.Load() != 1 {
		t.Fatalf("explicit Install = %+v, %v, rebuilds %d; want one rebuild", res, err, h.rebuilds.Load())
	}
	if h.validates.Load() != 2 || h.reloads.Load() != 2 {
		t.Fatalf("validate/reload = %d/%d, want the rebuild checked and applied", h.validates.Load(), h.reloads.Load())
	}
	if res, err := i.Install(); err != nil || res.Status != "no-op" || h.rebuilds.Load() != 1 {
		t.Fatalf("Install after the rebuild = %+v, %v, rebuilds %d; want no-op", res, err, h.rebuilds.Load())
	}
}

func TestInstallFailureRemovesBothNewSnippets(t *testing.T) {
	i, h := newSiteInstaller(t, true)
	h.validateErr = []error{errors.New("syntax error")}
	if _, err := i.Install(); err == nil {
		t.Fatal("expected configtest failure")
	}
	for _, p := range []string{h.path, h.sitePath} {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s left behind after a failed configtest", p)
		}
	}
}

func TestInstallRebuildFailureRollsBackWithoutReload(t *testing.T) {
	i, h := newSiteInstaller(t, false)
	i.RebuildSiteIncludes = true
	h.rebuildErr = errors.New("rebuildhttpdconf failed")
	if _, err := i.Install(); err == nil {
		t.Fatal("expected rebuild failure")
	}
	for _, p := range []string{h.path, h.sitePath} {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s left behind after a failed rebuild", p)
		}
	}
	if h.reloads.Load() != 0 {
		t.Fatalf("reloaded %d times after a failed rebuild", h.reloads.Load())
	}
}

func TestStatusIsStaleWhenTheSiteSnippetIsMissing(t *testing.T) {
	i, h := newSiteInstaller(t, true)
	if _, err := i.Install(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(h.sitePath); err != nil {
		t.Fatal(err)
	}
	if res, err := i.Status(); err != nil || res.Status != "stale" {
		t.Fatalf("Status = %+v, %v; want stale", res, err)
	}
}

func TestRemoveDeletesTheSiteSnippet(t *testing.T) {
	i, h := newSiteInstaller(t, true)
	if _, err := i.Install(); err != nil {
		t.Fatal(err)
	}
	if res, err := i.Remove(); err != nil || res.Status != "ok" {
		t.Fatalf("Remove = %+v, %v", res, err)
	}
	if _, err := os.Stat(h.sitePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("site snippet left behind by Remove")
	}
}

func TestCPanelSitesReadTheSiteSnippet(t *testing.T) {
	conf := filepath.Join(t.TempDir(), "httpd.conf")
	h := &cpanelSites{httpdConf: conf}
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(conf, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("<VirtualHost 192.0.2.10:443>\n  ServerName example.com\n</VirtualHost>\n")
	if active, err := h.SiteIncludeActive(); err != nil || active {
		t.Fatalf("active = %v, %v; want false without the include", active, err)
	}
	write("<VirtualHost 192.0.2.10:443>\n  Include \"/etc/apache2/conf.d/userdata/*.conf\"\n</VirtualHost>\n")
	if active, err := h.SiteIncludeActive(); err != nil || !active {
		t.Fatalf("active = %v, %v; want true with the include", active, err)
	}
}

// Certificate validation must keep working for an address on the list.
func TestSiteTemplateLeavesValidationPathsReachable(t *testing.T) {
	if !strings.Contains(cpanelSiteTemplate, `RewriteCond %{REQUEST_URI} !^/\.well-known/`) {
		t.Fatal("site rule also redirects /.well-known/ validation requests")
	}
}
