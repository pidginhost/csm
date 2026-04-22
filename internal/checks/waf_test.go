package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/platform"
)

func TestIsRuleArtifact(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"REQUEST-901-INITIALIZATION.conf", true},
		{"crs-setup.conf", true},
		{"unicode.data", true},
		{"modsecurity.rules", true},
		{"README.md", false},
		{"LICENSE", false},
		{"ChangeLog.txt", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isRuleArtifact(tt.name); got != tt.want {
				t.Errorf("isRuleArtifact(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestCheckRuleAge_FlatFiles(t *testing.T) {
	// Distro CRS layout: rule files live directly in the rule dir.
	dir := t.TempDir()
	oldFile := filepath.Join(dir, "REQUEST-901-INITIALIZATION.conf")
	if err := os.WriteFile(oldFile, []byte("SecRule ..."), 0644); err != nil {
		t.Fatal(err)
	}
	// Backdate the file to 45 days ago so it clears the 30-day threshold.
	old := time.Now().Add(-45 * 24 * time.Hour)
	if err := os.Chtimes(oldFile, old, old); err != nil {
		t.Fatal(err)
	}

	age := checkRuleAge([]string{dir})
	if age < 30 {
		t.Errorf("checkRuleAge on flat dir = %d, want >=30", age)
	}
}

func TestCheckRuleAge_IgnoresReadme(t *testing.T) {
	// A dir with only non-rule files should not be flagged as stale.
	dir := t.TempDir()
	readme := filepath.Join(dir, "README.md")
	if err := os.WriteFile(readme, []byte("docs"), 0644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-365 * 24 * time.Hour)
	if err := os.Chtimes(readme, old, old); err != nil {
		t.Fatal(err)
	}

	if age := checkRuleAge([]string{dir}); age != 0 {
		t.Errorf("non-rule files should not trigger stale alert, got age=%d", age)
	}
}

func TestCheckRuleAge_CPanelVendorLayout(t *testing.T) {
	// cPanel layout: ruleDir/VENDOR_NAME/*.conf
	dir := t.TempDir()
	vendorDir := filepath.Join(dir, "OWASP")
	if err := os.Mkdir(vendorDir, 0755); err != nil {
		t.Fatal(err)
	}
	rule := filepath.Join(vendorDir, "REQUEST-920-PROTOCOL-ENFORCEMENT.conf")
	if err := os.WriteFile(rule, []byte("SecRule ..."), 0644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-60 * 24 * time.Hour)
	if err := os.Chtimes(rule, old, old); err != nil {
		t.Fatal(err)
	}

	age := checkRuleAge([]string{dir})
	if age < 30 {
		t.Errorf("cPanel vendor layout: checkRuleAge = %d, want >=30", age)
	}
}

func TestCheckRuleAge_FreshRules(t *testing.T) {
	dir := t.TempDir()
	rule := filepath.Join(dir, "REQUEST-901-INITIALIZATION.conf")
	if err := os.WriteFile(rule, []byte("SecRule ..."), 0644); err != nil {
		t.Fatal(err)
	}
	// File defaults to current mtime, which is <30 days.
	if age := checkRuleAge([]string{dir}); age != 0 {
		t.Errorf("fresh rules should not be stale, got age=%d", age)
	}
}

func TestHasRuleArtifacts_IgnoresDocsOnly(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("docs"), 0644); err != nil {
		t.Fatal(err)
	}
	if hasRuleArtifacts([]string{dir}) {
		t.Fatal("README-only directory should not count as WAF rules")
	}
}

func TestHasRuleArtifacts_DetectsRuleFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "REQUEST-901-INITIALIZATION.conf"), []byte("SecRule ..."), 0644); err != nil {
		t.Fatal(err)
	}
	if !hasRuleArtifacts([]string{dir}) {
		t.Fatal("rule directory should count as WAF rules")
	}
}

func TestModsecConfigCandidates_ApacheDebian(t *testing.T) {
	info := platform.Info{OS: platform.OSUbuntu, WebServer: platform.WSApache, ApacheConfigDir: "/etc/apache2"}
	paths := modsecConfigCandidates(info)

	want := []string{
		"/etc/apache2/mods-enabled/security2.conf",
		"/etc/apache2/conf-enabled/security2.conf",
		"/etc/apache2/conf.d/modsec2.conf",
		"/etc/apache2/conf.d/*.conf",
	}
	if !containsAll(paths, want) {
		t.Errorf("Debian+Apache candidates missing expected paths\ngot: %v", paths)
	}
}

func TestModsecConfigCandidates_ApacheRHEL(t *testing.T) {
	info := platform.Info{OS: platform.OSAlma, WebServer: platform.WSApache, ApacheConfigDir: "/etc/httpd"}
	paths := modsecConfigCandidates(info)

	want := []string{
		"/etc/httpd/conf.d/mod_security.conf",
		"/etc/httpd/conf.modules.d/10-mod_security.conf",
		"/etc/httpd/conf.d/*.conf",
	}
	for _, p := range want {
		if !contains(paths, p) {
			t.Errorf("RHEL+Apache candidates missing %q", p)
		}
	}
}

func TestModsecConfigCandidates_Nginx(t *testing.T) {
	info := platform.Info{OS: platform.OSUbuntu, WebServer: platform.WSNginx, NginxConfigDir: "/etc/nginx"}
	paths := modsecConfigCandidates(info)

	want := []string{
		"/etc/nginx/nginx.conf",
		"/etc/nginx/modules-enabled/*.conf",
		"/etc/nginx/sites-enabled/*",
	}
	for _, p := range want {
		if !contains(paths, p) {
			t.Errorf("Nginx candidates missing %q", p)
		}
	}
	// Should NOT contain Apache paths.
	for _, p := range paths {
		if strings.Contains(p, "apache2") || strings.Contains(p, "httpd") {
			t.Errorf("Nginx candidates should not contain Apache path: %q", p)
		}
	}
}

func TestModsecActivationCandidates_NginxSkipsModuleLoaderOnlyPaths(t *testing.T) {
	info := platform.Info{OS: platform.OSUbuntu, WebServer: platform.WSNginx, NginxConfigDir: "/etc/nginx"}
	paths := modsecActivationCandidates(info)
	if contains(paths, "/etc/nginx/modules-enabled/*.conf") {
		t.Fatalf("activation candidates should not include module loader paths: %v", paths)
	}
}

func TestModsecEnabledInConfig_NginxRequiresEnabledDirective(t *testing.T) {
	info := platform.Info{OS: platform.OSUbuntu, WebServer: platform.WSNginx}
	if modsecEnabledInConfig(info, "load_module modules/ngx_http_modsecurity_module.so;") {
		t.Fatal("module loader alone should not count as active ModSecurity")
	}
	if !modsecEnabledInConfig(info, "modsecurity on;\nmodsecurity_rules_file /etc/nginx/modsec/main.conf;") {
		t.Fatal("nginx ModSecurity directives should count as active ModSecurity")
	}
}

func TestModsecEnabledInConfig_ApacheRecognizesLoadModuleAndEngine(t *testing.T) {
	info := platform.Info{OS: platform.OSUbuntu, WebServer: platform.WSApache}
	if !modsecEnabledInConfig(info, "LoadModule security2_module modules/mod_security2.so") {
		t.Fatal("LoadModule security2_module should count as active ModSecurity")
	}
	if !modsecEnabledInConfig(info, "SecRuleEngine On") {
		t.Fatal("SecRuleEngine On should count as active ModSecurity")
	}
}

func TestModsecRuleDirs_DebianApache(t *testing.T) {
	info := platform.Info{OS: platform.OSUbuntu, WebServer: platform.WSApache}
	dirs := modsecRuleDirs(info)
	want := []string{
		"/etc/modsecurity/",
		"/usr/share/modsecurity-crs/rules/",
	}
	for _, d := range want {
		if !contains(dirs, d) {
			t.Errorf("Debian+Apache rule dirs missing %q; got %v", d, dirs)
		}
	}
}

func TestModsecRuleDirs_AlmaApache(t *testing.T) {
	info := platform.Info{OS: platform.OSAlma, WebServer: platform.WSApache}
	dirs := modsecRuleDirs(info)
	if !contains(dirs, "/etc/httpd/modsecurity.d/") {
		t.Errorf("Alma+Apache rule dirs missing /etc/httpd/modsecurity.d/; got %v", dirs)
	}
}

func TestModsecRuleDirs_Nginx(t *testing.T) {
	info := platform.Info{OS: platform.OSUbuntu, WebServer: platform.WSNginx}
	dirs := modsecRuleDirs(info)
	if !contains(dirs, "/etc/nginx/modsec/") {
		t.Errorf("Nginx rule dirs missing /etc/nginx/modsec/; got %v", dirs)
	}
}

func TestModsecRuleDirs_UnknownWebServer(t *testing.T) {
	info := platform.Info{OS: platform.OSUbuntu, WebServer: platform.WSNone}
	dirs := modsecRuleDirs(info)
	if len(dirs) != 0 {
		t.Errorf("no web server should yield empty dirs, got %v", dirs)
	}
}

func TestModsecRuleDirs_CPanelLiteSpeed(t *testing.T) {
	// cPanel's modsec_assemble job writes vendor rules to the apache2
	// tree even when the front-end web server is LiteSpeed. Without this
	// branch, waf_status has no filesystem evidence of rules on
	// cPanel+LiteSpeed hosts and must rely entirely on a single whmapi1
	// call, which false-alarms during nightly vendor reassembly.
	info := platform.Info{
		OS:        platform.OSCloudLinux,
		Panel:     platform.PanelCPanel,
		WebServer: platform.WSLiteSpeed,
	}
	dirs := modsecRuleDirs(info)
	want := []string{
		"/etc/apache2/conf.d/modsec_vendor_configs/",
		"/usr/local/apache/conf/modsec_vendor_configs/",
	}
	for _, d := range want {
		if !contains(dirs, d) {
			t.Errorf("cPanel+LiteSpeed rule dirs missing %q; got %v", d, dirs)
		}
	}
}

func TestModsecRuleDirs_PlainLiteSpeed(t *testing.T) {
	// Plain LiteSpeed without cPanel has no conventional vendor dir.
	// We return an empty slice rather than guess a path that could
	// produce false negatives; operators will either install the cPanel
	// layout or configure their own scanner elsewhere.
	info := platform.Info{
		OS:        platform.OSUbuntu,
		Panel:     platform.PanelNone,
		WebServer: platform.WSLiteSpeed,
	}
	dirs := modsecRuleDirs(info)
	if len(dirs) != 0 {
		t.Errorf("plain LiteSpeed should yield empty dirs, got %v", dirs)
	}
}

func TestWafInstallHint_Differentiates(t *testing.T) {
	tests := []struct {
		name     string
		info     platform.Info
		contains string
	}{
		{
			name:     "cPanel",
			info:     platform.Info{Panel: platform.PanelCPanel},
			contains: "WHM > Security Center",
		},
		{
			name:     "Ubuntu+Nginx",
			info:     platform.Info{OS: platform.OSUbuntu, WebServer: platform.WSNginx},
			contains: "apt install libnginx-mod-http-modsecurity",
		},
		{
			name:     "Ubuntu+Apache",
			info:     platform.Info{OS: platform.OSUbuntu, WebServer: platform.WSApache},
			contains: "apt install libapache2-mod-security2",
		},
		{
			name:     "Alma+Apache",
			info:     platform.Info{OS: platform.OSAlma, WebServer: platform.WSApache},
			contains: "epel-release",
		},
		{
			name:     "Alma+Nginx",
			info:     platform.Info{OS: platform.OSAlma, WebServer: platform.WSNginx},
			contains: "nginx-mod-http-modsecurity",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := wafInstallHint(tt.info)
			if !strings.Contains(got, tt.contains) {
				t.Errorf("wafInstallHint() = %q, want substring %q", got, tt.contains)
			}
		})
	}
}

func TestWafRulesHint_Differentiates(t *testing.T) {
	tests := []struct {
		name     string
		info     platform.Info
		contains string
	}{
		{"cPanel", platform.Info{Panel: platform.PanelCPanel}, "WHM > Security Center"},
		{"Debian", platform.Info{OS: platform.OSUbuntu}, "apt install modsecurity-crs"},
		{"RHEL", platform.Info{OS: platform.OSAlma}, "modsecurity-crs"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := wafRulesHint(tt.info)
			if !strings.Contains(got, tt.contains) {
				t.Errorf("wafRulesHint() = %q, want substring %q", got, tt.contains)
			}
		})
	}
}

func TestWafRulesStaleHint_Differentiates(t *testing.T) {
	tests := []struct {
		name     string
		info     platform.Info
		contains string
	}{
		{"cPanel", platform.Info{Panel: platform.PanelCPanel}, "WHM > Security Center"},
		{"Debian", platform.Info{OS: platform.OSUbuntu}, "apt update"},
		{"RHEL", platform.Info{OS: platform.OSAlma}, "dnf upgrade"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := wafRulesStaleHint(tt.info)
			if !strings.Contains(got, tt.contains) {
				t.Errorf("wafRulesStaleHint() = %q, want substring %q", got, tt.contains)
			}
		})
	}
}

// --- helpers ---

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

func containsAll(haystack, needles []string) bool {
	for _, n := range needles {
		if !contains(haystack, n) {
			return false
		}
	}
	return true
}
