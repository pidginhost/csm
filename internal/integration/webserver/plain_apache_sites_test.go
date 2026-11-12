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
	main := write("apache2.conf", "ServerRoot /etc/apache2\nInclude sites/*.conf\n")
	covered := write("site-a.conf", "<VirtualHost *:80>\n"+include+"</VirtualHost>\n<VirtualHost *:443>\n    IncludeOptional \""+snippet+"\"\n</VirtualHost>\n")
	missing := write("site-b.conf", "<VirtualHost *:443>\n    # Include "+snippet+"\n</VirtualHost>\n")
	dump := func(files ...string) string {
		var b strings.Builder
		b.WriteString("Included configuration files:\n  (*) " + main + "\n")
		for _, f := range files {
			b.WriteString("    (2) " + f + "\n")
			if f == covered {
				b.WriteString("      (2) " + snippet + "\n      (5) " + snippet + "\n")
			}
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

func TestPlainApacheCoverageUsesLoadedIncludes(t *testing.T) {
	for _, tc := range []struct {
		name, conf, helper, children string
		want                         bool
		wantErr                      bool
	}{
		{name: "uncovered file with spaces", conf: "<VirtualHost *:443>\n</VirtualHost>\n"},
		{name: "inactive conditional include", conf: "<VirtualHost *:443>\n<IfDefine NEVER_SET>\nInclude SNIPPET\n</IfDefine>\n</VirtualHost>\n"},
		{name: "direct include", conf: "<VirtualHost *:443>\nInclude SNIPPET\n</VirtualHost>\n", children: "    (2) SNIPPET\n", want: true},
		{name: "nested include", conf: "<VirtualHost *:443>\nInclude HELPER\n</VirtualHost>\n", helper: "Include SNIPPET\n", children: "    (2) HELPER\n      (1) SNIPPET\n", want: true},
		{name: "one covered one inactive", conf: "<VirtualHost *:80>\nInclude SNIPPET\n</VirtualHost>\n<VirtualHost *:443>\n<IfDefine NEVER_SET>\nInclude SNIPPET\n</IfDefine>\n</VirtualHost>\n", children: "    (2) SNIPPET\n"},
		{name: "global include only", conf: "Include SNIPPET\n<VirtualHost *:443>\n</VirtualHost>\n", children: "    (1) SNIPPET\n"},
		{name: "continued virtualhost", conf: "<VirtualHost \\\n*:443>\nInclude SNIPPET\n</VirtualHost>\n", children: "    (3) SNIPPET\n", want: true},
		{name: "unreadable include", conf: "Include HELPER\n", children: "    (1) HELPER\n", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			main := filepath.Join(dir, "site.conf")
			if tc.name == "uncovered file with spaces" {
				main = filepath.Join(dir, "site with spaces.conf")
			}
			helper := filepath.Join(dir, "common.conf")
			replace := strings.NewReplacer("SNIPPET", plainApacheSiteSnippetPath, "HELPER", helper)
			if err := os.WriteFile(main, []byte(replace.Replace(tc.conf)), 0o644); err != nil {
				t.Fatal(err)
			}
			if tc.helper != "" {
				if err := os.WriteFile(helper, []byte(replace.Replace(tc.helper)), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			dump := "Included configuration files:\n  (*) " + main + "\n" + replace.Replace(tc.children)
			s := &plainApacheSites{ctl: "apachectl", runner: dumpIncludesRunner{dump}}
			active, err := s.SiteIncludeActive()
			if active != tc.want || (err != nil) != tc.wantErr {
				t.Fatalf("coverage = %v, %v; want %v, error %v", active, err, tc.want, tc.wantErr)
			}
		})
	}
}

func TestPlainApacheCoverageRejectsMissingDump(t *testing.T) {
	for _, dump := range []string{"", "Syntax OK\n", "Included configuration files:\n", "  (*) relative.conf\n"} {
		s := &plainApacheSites{ctl: "apachectl", runner: dumpIncludesRunner{dump}}
		if active, err := s.SiteIncludeActive(); active || err == nil {
			t.Errorf("dump %q: coverage = %v, %v; want an error", dump, active, err)
		}
	}
}

// A required Include can fail configtest until Install creates its target.
// Successful installation must report the coverage of the new configuration.
type fileAwareSiteHandler struct{ *fakeSiteHandler }

func (h fileAwareSiteHandler) SiteIncludeActive() (bool, error) {
	_, err := os.Stat(h.sitePath)
	return err == nil, err
}

func TestInstallRefreshesCoverageAfterWritingSiteSnippet(t *testing.T) {
	i, h := newSiteInstaller(t, false)
	h.configPath = ""
	i.Handler = fileAwareSiteHandler{h}
	res, err := i.Install()
	if err != nil || res.Status != "ok" {
		t.Fatalf("Install = %+v, %v", res, err)
	}
	if strings.Contains(res.Message, "could not tell") || strings.Contains(res.Message, "only after") {
		t.Fatalf("successful install reports stale coverage: %s", res.Message)
	}
}
