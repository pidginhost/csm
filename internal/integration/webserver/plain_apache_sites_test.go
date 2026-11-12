package webserver

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/platform"
)

type dumpIncludesRunner struct{ out string }

func (r dumpIncludesRunner) Run(context.Context, string, ...string) ([]byte, error) {
	return []byte(r.out), nil
}

// Apache applies server-wide rewrite rules inside no <VirtualHost> that does
// not opt in, so every site block must include the per-site snippet.
func TestPlainApacheSitesRequireTheIncludeInEveryVirtualHost(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	snippet := plainApacheSiteSnippetPath
	include := "    Include " + snippet + "\n"
	main := write("apache2.conf", "ServerRoot /etc/apache2\n")
	covered := write("site-a.conf", "<VirtualHost *:80>\n"+include+"</VirtualHost>\n<VirtualHost *:443>\n    IncludeOptional \""+snippet+"\"\n</VirtualHost>\n")
	missing := write("site-b.conf", "<VirtualHost *:443>\n    # Include "+snippet+"\n</VirtualHost>\n")
	dump := func(files ...string) string {
		var b strings.Builder
		b.WriteString("Included configuration files:\n  (*) " + main + "\n")
		for _, f := range files {
			b.WriteString("    (12) " + f + "\n")
		}
		return b.String()
	}
	for _, tc := range []struct {
		name   string
		files  []string
		active bool
	}{
		{"no sites yet", nil, true},
		{"every site includes it", []string{covered}, true},
		{"one site only has a comment", []string{covered, missing}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &plainApacheSites{ctl: "apache2ctl", runner: dumpIncludesRunner{dump(tc.files...)}}
			if active, err := s.SiteIncludeActive(); err != nil || active != tc.active {
				t.Fatalf("active = %v, %v; want %v", active, err, tc.active)
			}
		})
	}
}

func TestPlainApacheHandlerAsksForThePerSiteInclude(t *testing.T) {
	for _, info := range []platform.Info{
		{OS: platform.OSUbuntu, WebServer: platform.WSApache},
		{OS: platform.OSAlma, WebServer: platform.WSApache},
	} {
		h := newApacheHandler(info, dumpIncludesRunner{})
		if got := h.SiteSnippetPath(); got != plainApacheSiteSnippetPath {
			t.Fatalf("%v: site snippet = %q", info.OS, got)
		}
		if h.SiteConfigPath() != "" {
			t.Fatalf("%v: plain Apache must not offer a configuration rebuild", info.OS)
		}
		if !strings.Contains(h.PostInstallInstructions(), "Include "+plainApacheSiteSnippetPath) {
			t.Fatalf("%v: setup does not name the Include line: %q", info.OS, h.PostInstallInstructions())
		}
	}
	if h := newApacheHandler(platform.Info{Panel: platform.PanelCPanel, WebServer: platform.WSApache}, dumpIncludesRunner{}); h.PostInstallInstructions() != "" {
		t.Fatal("cPanel needs no manual step")
	}
}

// Without a rebuild to offer, the explicit command installs the snippet and
// tells the operator what to add, instead of failing or rebuilding.
func TestInstallDoesNotRebuildWhereSitesNeedManualIncludes(t *testing.T) {
	i, h := newSiteInstaller(t, false)
	h.configPath = ""
	h.fix = "add `Include " + h.sitePath + "` inside every <VirtualHost>"
	i.RebuildSiteIncludes = true
	res, err := i.Install()
	if err != nil || res.Status != "ok" {
		t.Fatalf("Install = %+v, %v", res, err)
	}
	if h.rebuilds.Load() != 0 {
		t.Fatal("rebuilt a stack that has no rebuild")
	}
	if !strings.Contains(res.Message, h.fix) {
		t.Fatalf("message does not give the manual step: %q", res.Message)
	}
}
