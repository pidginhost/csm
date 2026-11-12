package webserver

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A rebuild may replace httpd.conf before failing, or produce a configuration
// that passes the script but fails the server's configtest or reload.
type rebuildingSiteHandler struct {
	*fakeSiteHandler
	conf           string
	rebuildFailure error
}

func (h *rebuildingSiteHandler) SiteConfigPath() string { return h.conf }
func (h *rebuildingSiteHandler) RebuildSiteIncludes() error {
	h.rebuilds.Add(1)
	if err := atomicWrite(h.conf, []byte("changed by rebuild\n"), 0o600); err != nil {
		return err
	}
	h.active = true
	return h.rebuildFailure
}

func TestSiteRebuildRollbackRestoresOriginalConfig(t *testing.T) {
	for _, stage := range []string{"rebuild", "validate", "reload"} {
		t.Run(stage, func(t *testing.T) {
			i, base := newSiteInstaller(t, false)
			h := &rebuildingSiteHandler{fakeSiteHandler: base, conf: filepath.Join(t.TempDir(), "httpd.conf")}
			original := []byte("# original configuration\n")
			if err := os.WriteFile(h.conf, original, 0o640); err != nil {
				t.Fatal(err)
			}
			i.Handler = h
			i.RebuildSiteIncludes = true
			failure := errors.New("injected " + stage + " failure")
			switch stage {
			case "rebuild":
				h.rebuildFailure = failure
			case "validate":
				h.validateErr = []error{failure}
			case "reload":
				h.reloadErr = []error{failure}
			}
			if _, err := i.Install(); !errors.Is(err, failure) {
				t.Fatalf("Install error = %v", err)
			}
			got, err := os.ReadFile(h.conf)
			if err != nil || !bytes.Equal(got, original) {
				t.Errorf("httpd.conf was not restored: %q, %v", got, err)
			}
			info, err := os.Stat(h.conf)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o640 {
				t.Errorf("restored mode = %o", info.Mode().Perm())
			}
			if h.rebuilds.Load() != 1 {
				t.Errorf("rollback ran an unsafe second rebuild: %d", h.rebuilds.Load())
			}
			wantReloads := int32(0)
			if stage == "reload" {
				wantReloads = 2
			}
			if h.reloads.Load() != wantReloads {
				t.Errorf("reloads = %d, want %d", h.reloads.Load(), wantReloads)
			}
			for _, path := range []string{h.path, h.sitePath} {
				if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("new snippet remains: %s, %v", path, err)
				}
			}
		})
	}
}

func TestRemoveOrphanedSiteSnippet(t *testing.T) {
	i, h := newSiteInstaller(t, true)
	if _, err := i.Install(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(h.path); err != nil {
		t.Fatal(err)
	}
	res, err := i.Remove()
	if err != nil || res.Status != "ok" {
		t.Fatalf("Remove = %+v, %v", res, err)
	}
	if got, err := os.ReadFile(h.sitePath); err != nil || string(got) != disabledSiteSnippet {
		t.Fatalf("orphaned per-site redirect was not disabled: %q, %v", got, err)
	}
	if h.reloads.Load() != 2 {
		t.Fatalf("removal was not reloaded: %d", h.reloads.Load())
	}
}

type requiredSiteHandler struct{ *fakeSiteHandler }

func (h *requiredSiteHandler) Validate() error {
	h.validates.Add(1)
	if _, err := os.Stat(h.sitePath); err != nil {
		return fmt.Errorf("Include wildcard has no matches: %w", err)
	}
	return nil
}

func TestRemoveKeepsRequiredIncludeLoadable(t *testing.T) {
	i, base := newSiteInstaller(t, true)
	h := &requiredSiteHandler{base}
	i.Handler = h
	if _, err := i.Install(); err != nil {
		t.Fatal(err)
	}
	res, err := i.Remove()
	if err != nil || res.Status != "ok" {
		t.Fatalf("Remove = %+v, %v", res, err)
	}
	body, err := os.ReadFile(h.sitePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(body), "\n") {
		if line != "" && !strings.HasPrefix(line, "#") {
			t.Fatalf("removed include has an active directive: %q", line)
		}
	}
	if _, statErr := os.Stat(h.path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("server snippet remains: %v", statErr)
	}
	if h.rebuilds.Load() != 0 {
		t.Fatal("Remove rebuilt httpd.conf")
	}
	if second, removeErr := i.Remove(); removeErr != nil || second.Status != "no-op" {
		t.Fatalf("second Remove = %+v, %v", second, removeErr)
	}
	if _, installErr := i.Install(); installErr != nil {
		t.Fatalf("reinstall: %v", installErr)
	}
	body, err = os.ReadFile(h.sitePath)
	if err != nil || !strings.Contains(string(body), "RewriteRule") {
		t.Fatalf("reinstall did not reactivate site: %q, %v", body, err)
	}
}

func TestSiteStatusDoesNotDowngradeNewerSnippets(t *testing.T) {
	for _, newer := range []string{"server", "site"} {
		t.Run(newer, func(t *testing.T) {
			i, h := newSiteInstaller(t, true)
			if _, err := i.Install(); err != nil {
				t.Fatal(err)
			}
			path := h.path
			stalePath := h.sitePath
			if newer == "site" {
				path, stalePath = stalePath, path
			}
			if err := os.WriteFile(path, []byte(fmt.Sprintf("%s%d\nnewer\n", templateHeaderPrefix, TemplateVersion+1)), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(stalePath, []byte(fmt.Sprintf("%s%d\nolder\n", templateHeaderPrefix, TemplateVersion-1)), 0o644); err != nil {
				t.Fatal(err)
			}
			if res, err := i.Status(); err != nil || res.Status != "ok" {
				t.Fatalf("Status permits startup to downgrade %s: %+v, %v", newer, res, err)
			}
		})
	}
}

func TestSiteCoverageRequiresSnippet(t *testing.T) {
	i, _ := newSiteInstaller(t, true)
	if _, active, _, err := i.SiteCoverage(); err != nil || active {
		t.Fatalf("missing snippet coverage = %v, %v", active, err)
	}
}

func TestServerAndSiteTemplatesExemptValidation(t *testing.T) {
	for name, body := range map[string]string{"apache": apacheTemplate, "lsws": lswsTemplate, "site": cpanelSiteTemplate} {
		if !strings.Contains(body, "RewriteCond %{REQUEST_URI} !^/\\.well-known/\nRewriteCond ${csm_chal:%{REMOTE_ADDR}} =challenge") {
			t.Errorf("%s redirects validation requests when inherited", name)
		}
	}
}

func TestSiteIncludeCoverageChecksHTTPSBlocks(t *testing.T) {
	// cPanel marks each user site block with its per-user include path; the
	// server's own hostname blocks have none and never get the global include.
	user := "# Include \"/etc/apache2/conf.d/userdata/ssl/2_4/user/example.com/*.conf\"\n"
	hostname := "<VirtualHost *:443>\nServerName server.example.net\n</VirtualHost>\n"
	for _, tc := range []struct {
		name, conf string
		active     bool
	}{
		{"comment", "<VirtualHost *:443>\n" + user + "# " + cpanelSiteInclude + "\n</VirtualHost>\n", false},
		{"global", cpanelSiteInclude + "\n<VirtualHost *:443>\n" + user + "</VirtualHost>\n", false},
		{"http only", "<VirtualHost *:80>\n" + cpanelSiteInclude + "\n</VirtualHost>\n<VirtualHost *:443>\n" + user + "</VirtualHost>\n", false},
		{"partial", "<VirtualHost *:443>\n" + user + cpanelSiteInclude + "\n</VirtualHost>\n<VirtualHost *:443>\n" + user + "</VirtualHost>\n", false},
		{"all HTTPS", "<VirtualHost *:80>\n</VirtualHost>\n<VirtualHost *:443>\n" + user + cpanelSiteInclude + "\n</VirtualHost>\n", true},
		{"custom TLS port", "<VirtualHost *:8443>\nSSLEngine On\n" + user + "</VirtualHost>\n", false},
		{"whitespace", "<VirtualHost *:443>\n" + user + " Include\t\"/etc/apache2/conf.d/userdata/*.conf\"\n</VirtualHost>\n", true},
		{"hostname block beside covered sites", hostname + "<VirtualHost *:443>\n" + user + cpanelSiteInclude + "\n</VirtualHost>\n", true},
		// Nothing to cover yet; a later site gets the include at its rebuild.
		{"no user sites", hostname, true},
		{"unterminated block", "<VirtualHost *:443>\n" + user, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "httpd.conf")
			if err := os.WriteFile(path, []byte(tc.conf), 0o644); err != nil {
				t.Fatal(err)
			}
			c := &cpanelSites{httpdConf: path}
			if active, err := c.SiteIncludeActive(); err != nil || active != tc.active {
				t.Fatalf("active = %v, %v; want %v", active, err, tc.active)
			}
		})
	}
}

func TestSiteRebuildSnapshotFailureLeavesSnippetsUntouched(t *testing.T) {
	i, h := newSiteInstaller(t, false)
	i.RebuildSiteIncludes = true
	failure := errors.New("cannot read generated config")
	i.ReadAt = func(path string) ([]byte, error) {
		if path == h.configPath {
			return nil, failure
		}
		return os.ReadFile(path)
	}
	if _, err := i.Install(); !errors.Is(err, failure) {
		t.Fatalf("Install error = %v", err)
	}
	for _, path := range []string{h.path, h.sitePath} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("snippet changed without a snapshot: %s, %v", path, err)
		}
	}
	if h.rebuilds.Load() != 0 || h.reloads.Load() != 0 {
		t.Fatal("web server changed without a snapshot")
	}
}

func TestSiteRebuildRecoveryFailuresPreventReload(t *testing.T) {
	for _, stage := range []string{"server", "site", "config", "configtest", "reload"} {
		t.Run(stage, func(t *testing.T) {
			i, h := newSiteInstaller(t, false)
			// Install once without a rebuild, then change both templates.
			if _, err := i.Install(); err != nil {
				t.Fatal(err)
			}
			serverBefore, err := os.ReadFile(h.path)
			if err != nil {
				t.Fatal(err)
			}
			siteBefore, err := os.ReadFile(h.sitePath)
			if err != nil {
				t.Fatal(err)
			}
			h.body += "# updated\n"
			h.siteBody += "# updated\n"
			i.RebuildSiteIncludes = true
			failure := errors.New("reload failed")
			recovery := errors.New("recovery " + stage + " failed")
			h.reloadErr = []error{nil, failure}
			if stage == "reload" {
				h.reloadErr = append(h.reloadErr, recovery)
			}
			if stage == "configtest" {
				h.validateErr = []error{nil, nil, recovery}
			}
			i.WriteAt = func(path string, data []byte, mode os.FileMode) error {
				if (stage == "server" && path == h.path && bytes.Equal(data, serverBefore)) ||
					(stage == "site" && path == h.sitePath && bytes.Equal(data, siteBefore)) ||
					(stage == "config" && path == h.configPath) {
					return recovery
				}
				return atomicWrite(path, data, mode)
			}
			res, err := i.Install()
			if !errors.Is(err, failure) || !errors.Is(err, recovery) {
				t.Fatalf("errors lost: %+v, %v", res, err)
			}
			if strings.Contains(res.Message, "(rolled back)") {
				t.Fatalf("claims recovery succeeded: %+v", res)
			}
			want := int32(2)
			if stage == "reload" {
				want = 3
			}
			if h.reloads.Load() != want {
				t.Fatalf("reloads = %d, want %d", h.reloads.Load(), want)
			}
		})
	}
}

func TestRemoveSiteRollback(t *testing.T) {
	for _, stage := range []string{"disable", "validate", "reload", "restore", "recovery validation"} {
		t.Run(stage, func(t *testing.T) {
			i, h := newSiteInstaller(t, true)
			if _, err := i.Install(); err != nil {
				t.Fatal(err)
			}
			serverBefore, err := os.ReadFile(h.path)
			if err != nil {
				t.Fatal(err)
			}
			siteBefore, err := os.ReadFile(h.sitePath)
			if err != nil {
				t.Fatal(err)
			}
			failure := errors.New("injected " + stage)
			recovery := errors.New("site restore failed")
			switch stage {
			case "disable":
				i.WriteAt = func(path string, data []byte, mode os.FileMode) error {
					if path == h.sitePath {
						return failure
					}
					return atomicWrite(path, data, mode)
				}
			case "validate":
				h.validateErr = []error{nil, failure}
			default:
				h.reloadErr = []error{nil, failure}
			}
			if stage == "restore" {
				i.WriteAt = func(path string, data []byte, mode os.FileMode) error {
					if path == h.sitePath && bytes.Equal(data, siteBefore) {
						return recovery
					}
					return atomicWrite(path, data, mode)
				}
			}
			if stage == "recovery validation" {
				h.validateErr = []error{nil, nil, recovery}
			}
			res, err := i.Remove()
			if !errors.Is(err, failure) || res.Status != "fail" {
				t.Fatalf("Remove = %+v, %v", res, err)
			}
			if (stage == "restore" || stage == "recovery validation") && !errors.Is(err, recovery) {
				t.Fatalf("lost recovery failure: %v", err)
			}
			got, err := os.ReadFile(h.path)
			if err != nil || !bytes.Equal(got, serverBefore) {
				t.Fatalf("server not restored: %q, %v", got, err)
			}
			got, err = os.ReadFile(h.sitePath)
			if stage != "restore" && (err != nil || !bytes.Equal(got, siteBefore)) {
				t.Fatalf("site not restored: %q, %v", got, err)
			}
			want := int32(1)
			switch stage {
			case "reload":
				want = 3
			case "restore", "recovery validation":
				want = 2
			}
			if h.reloads.Load() != want {
				t.Fatalf("reloads = %d, want %d", h.reloads.Load(), want)
			}
		})
	}
}

type unchangedCoverageHandler struct{ *fakeSiteHandler }

func (h *unchangedCoverageHandler) SiteIncludeActive() (bool, error) { return false, nil }

func TestInstallChecksCoverageAfterRebuild(t *testing.T) {
	i, base := newSiteInstaller(t, false)
	h := &unchangedCoverageHandler{base}
	i.Handler = h
	i.RebuildSiteIncludes = true
	res, err := i.Install()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Message, "still do not read") || strings.Contains(res.Message, "run `csm webserver-integration upgrade`") {
		t.Fatalf("after a rebuild without coverage the note must not send the operator back to upgrade: %+v", res)
	}
	if h.rebuilds.Load() != 1 {
		t.Fatalf("rebuilds = %d", h.rebuilds.Load())
	}
}

func TestRemoveWithMissingSiteSnippet(t *testing.T) {
	i, h := newSiteInstaller(t, true)
	if _, err := i.Install(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(h.sitePath); err != nil {
		t.Fatal(err)
	}
	res, err := i.Remove()
	if err != nil || res.Status != "ok" {
		t.Fatalf("Remove = %+v, %v", res, err)
	}
	for _, path := range []string{h.path, h.sitePath} {
		if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("unexpected snippet at %s: %v", path, statErr)
		}
	}
	if h.reloads.Load() != 2 || h.rebuilds.Load() != 0 {
		t.Fatal("expected one removal reload and no rebuild")
	}
}

func TestRemoveRefusesUnmanagedOrphan(t *testing.T) {
	i, h := newSiteInstaller(t, true)
	if err := os.MkdirAll(filepath.Dir(h.sitePath), 0o755); err != nil {
		t.Fatal(err)
	}
	body := []byte("# operator-owned site configuration\n")
	if err := os.WriteFile(h.sitePath, body, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := i.Remove(); !errors.Is(err, ErrManualEdits) {
		t.Fatalf("Remove error = %v", err)
	}
	got, err := os.ReadFile(h.sitePath)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("operator configuration changed: %q, %v", got, err)
	}
	if h.reloads.Load() != 0 {
		t.Fatal("unmanaged configuration was reloaded")
	}
}
