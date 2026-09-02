package checks

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/platform"
)

// mockModsecFiles serves the given path -> content map through osFS.Open.
func mockModsecFiles(t *testing.T, files map[string]string) {
	t.Helper()
	dir := t.TempDir()
	withMockOS(t, &mockOS{open: func(name string) (*os.File, error) {
		body, ok := files[name]
		if !ok {
			return nil, os.ErrNotExist
		}
		tmp := filepath.Join(dir, filepath.Base(name))
		if err := os.WriteFile(tmp, []byte(body), 0o644); err != nil {
			return nil, err
		}
		return os.Open(tmp)
	}})
}

// cPanel's modsec2.conf turns the engine on and then includes
// modsec2.cpanel.conf (WHM "Edit Global Directive") and modsec2.user.conf.
// Apache applies the last SecRuleEngine it parses, so DetectionOnly set
// through WHM must be reported even though modsec2.conf says On.
func TestCheckEngineModeCPanelLastDirectiveWins(t *testing.T) {
	mockModsecFiles(t, map[string]string{
		"/etc/apache2/conf.d/modsec2.conf":               "<IfModule mod_security2.c>\nSecRuleEngine On\nInclude \"/etc/apache2/conf.d/modsec/modsec2.cpanel.conf\"\n</IfModule>\n",
		"/etc/apache2/conf.d/modsec/modsec2.cpanel.conf": "SecAuditEngine RelevantOnly\nSecRuleEngine DetectionOnly\n",
	})
	info := platform.Info{Panel: platform.PanelCPanel, OS: platform.OSAlma, WebServer: platform.WSApache, ApacheConfigDir: "/etc/apache2"}
	if mode := checkEngineMode(info); mode != "detectiononly" {
		t.Fatalf("mode = %q, want detectiononly from the WHM global directive", mode)
	}

	// An operator re-enabling enforcement in modsec2.user.conf wins over
	// the WHM file, which is included before it.
	mockModsecFiles(t, map[string]string{
		"/etc/apache2/conf.d/modsec2.conf":               "SecRuleEngine On\n",
		"/etc/apache2/conf.d/modsec/modsec2.cpanel.conf": "SecRuleEngine DetectionOnly\n",
		"/etc/apache2/conf.d/modsec/modsec2.user.conf":   "SecRequestBodyAccess On\nSecRuleEngine On\n",
	})
	if mode := checkEngineMode(info); mode != "on" {
		t.Fatalf("mode = %q, want on from modsec2.user.conf", mode)
	}
}

// cPanel + LiteSpeed reads cPanel's Apache config tree (loadApacheConf), so
// the engine mode lives in the same files, not under /usr/local/lsws.
func TestCheckEngineModeCPanelLiteSpeedReadsApacheTree(t *testing.T) {
	mockModsecFiles(t, map[string]string{
		"/etc/apache2/conf.d/modsec2.conf":               "SecRuleEngine On\n",
		"/etc/apache2/conf.d/modsec/modsec2.cpanel.conf": "SecRuleEngine DetectionOnly\n",
	})
	info := platform.Info{Panel: platform.PanelCPanel, OS: platform.OSCloudLinux, WebServer: platform.WSLiteSpeed, ApacheConfigDir: "/etc/apache2"}
	if mode := checkEngineMode(info); mode != "detectiononly" {
		t.Fatalf("mode = %q, want detectiononly", mode)
	}
}

func TestCheckEngineModeCPanelHonorsApacheContainersAndComments(t *testing.T) {
	mockModsecFiles(t, map[string]string{
		"/etc/apache2/conf.d/modsec2.conf": `
# SecRuleEngine Off
SecRuleEngineDisabled Off
<IfModule mod_security2.c>
  SecRuleEngine On # active cPanel wrapper
  <IfModule !mod_security2.c>
    SecRuleEngine Off
  </IfModule>
</IfModule>
<VirtualHost *:443>
  SecRuleEngine DetectionOnly
</VirtualHost>
`,
	})
	info := platform.Info{Panel: platform.PanelCPanel, OS: platform.OSAlma, WebServer: platform.WSApache, ApacheConfigDir: "/etc/apache2"}
	if mode := checkEngineMode(info); mode != "on" {
		t.Fatalf("mode = %q, want active server-scope mode on", mode)
	}
}

func TestCheckEngineModeCPanelRejectsDirectiveInUnknownIfModule(t *testing.T) {
	mockModsecFiles(t, map[string]string{
		"/etc/apache2/conf.d/modsec2.conf": "SecRuleEngine On\n<IfModule ssl_module>\nSecRuleEngine Off\n</IfModule>\n",
	})
	info := platform.Info{Panel: platform.PanelCPanel, OS: platform.OSAlma, WebServer: platform.WSApache, ApacheConfigDir: "/etc/apache2"}
	if mode := checkEngineMode(info); mode != "" {
		t.Fatalf("mode = %q, want unknown because ssl_module load state is unavailable", mode)
	}
}

func TestCheckEngineModeCPanelRejectsAmbiguousLaterInclude(t *testing.T) {
	mockModsecFiles(t, map[string]string{
		"/etc/apache2/conf.d/modsec2.conf":             "SecRuleEngine On\n",
		"/etc/apache2/conf.d/modsec/modsec2.user.conf": "<IfModule ssl_module>\nSecRuleEngine Off\n</IfModule>\n",
	})
	info := platform.Info{Panel: platform.PanelCPanel, OS: platform.OSAlma, WebServer: platform.WSApache, ApacheConfigDir: "/etc/apache2"}
	if mode := checkEngineMode(info); mode != "" {
		t.Fatalf("mode = %q, want unknown because a later include is conditional", mode)
	}
}

func TestCheckEngineModeCPanelRejectsUnknownServerCondition(t *testing.T) {
	mockModsecFiles(t, map[string]string{
		"/etc/apache2/conf.d/modsec2.conf": "SecRuleEngine On\n<IfVersion >= 2.4>\nSecRuleEngine Off\n</IfVersion>\n",
	})
	info := platform.Info{Panel: platform.PanelCPanel, OS: platform.OSAlma, WebServer: platform.WSApache, ApacheConfigDir: "/etc/apache2"}
	if mode := checkEngineMode(info); mode != "" {
		t.Fatalf("mode = %q, want unknown because the server-scope condition cannot be evaluated", mode)
	}
}

func TestLastEngineDirectiveRejectsMalformedContainerNesting(t *testing.T) {
	mockModsecFiles(t, map[string]string{
		"/etc/apache2/conf.d/modsec2.conf": "<IfModule mod_security2.c>\nSecRuleEngine On\n</VirtualHost>\n",
	})
	if mode := lastEngineDirective("/etc/apache2/conf.d/modsec2.conf"); mode != "" {
		t.Fatalf("mode = %q, want unknown for malformed Apache nesting", mode)
	}
}
