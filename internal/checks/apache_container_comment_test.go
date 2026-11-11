package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/platform"
)

// httpd ends a section tag at the line's last '>' and ignores the rest, so
// a comment after a tag leaves the section intact.
func TestApacheContainerTagIgnoresTextAfterTag(t *testing.T) {
	for _, tc := range []struct {
		line, name, label string
		closing           bool
	}{
		{"<VirtualHost *:80> # main site", "VirtualHost", "VirtualHost *:80", false},
		{"</VirtualHost> # end", "VirtualHost", "VirtualHost", true},
		{"<IfModule mod_security2.c> # waf", "IfModule", "IfModule mod_security2.c", false},
		{`<If "%{REQUEST_URI} > 5"> # check`, "If", `If "%{REQUEST_URI} > 5"`, false},
	} {
		tag, isContainer, valid := parseApacheContainerTag(tc.line)
		if !isContainer || !valid || tag.name != tc.name || tag.label != tc.label || tag.closing != tc.closing {
			t.Errorf("parseApacheContainerTag(%q) = %+v, %v, %v; want %s %q closing %v", tc.line, tag, isContainer, valid, tc.name, tc.label, tc.closing)
		}
	}
	if _, isContainer, valid := parseApacheContainerTag("<VirtualHost *:80 # unterminated"); !isContainer || valid {
		t.Errorf("a tag without '>' = container %v valid %v, want an invalid container", isContainer, valid)
	}
}

func TestRewriteOffShieldSeesCommentedTag(t *testing.T) {
	body := "RewriteEngine Off\n<FilesMatch \"^()$\"> # assets\nAllow from all\n</FilesMatch>\n"
	if got := len(detectRewriteOffShield([]byte(body), ".htaccess")); got != 2 {
		t.Fatalf("rewrite-off shield findings = %d, want 2", got)
	}
}

func TestEngineModeSeesCommentedIfModule(t *testing.T) {
	mode, known, err := parseEngineDirectives(strings.NewReader("<IfModule mod_security2.c> # waf\nSecRuleEngine DetectionOnly\n</IfModule> # end\n"))
	if err != nil || !known || mode != "detectiononly" {
		t.Fatalf("mode = %q known %v err %v, want detectiononly", mode, known, err)
	}
}

func TestApacheAuditReadsCommentedSectionTags(t *testing.T) {
	main := filepath.Join(t.TempDir(), "httpd.conf")
	writeApacheConf(t, main, "ServerTokens Prod\n<VirtualHost *:80> # main site\n  ServerName www.example.com\n</VirtualHost> # end\n")
	got, ok := auditByName(auditApacheDirectives(main), "web_server_tokens")
	if !ok || got.Status != "pass" {
		t.Fatalf("web_server_tokens = %+v, want pass", got)
	}
}

func TestHTTPRewriteApacheCommentedSectionTags(t *testing.T) {
	dir := t.TempDir()
	direct := writeRewriteFile(t, dir, "direct.conf", "<VirtualHost *:80> # main site\n  ServerName www.example.com\n</VirtualHost> # end\n")
	requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSApache, apacheConfig: direct}), RewriteNone, "", "")
	active := writeRewriteFile(t, dir, "active.conf", "<IfModule remoteip_module> # CDN\n  RemoteIPHeader X-Real-IP\n</IfModule>\n")
	requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSApache, apacheConfig: active}),
		RewriteActive, "RemoteIPHeader X-Real-IP", active)
}

// A php-fpm package creates an Apache snippet directory on nginx hosts too;
// with no Apache main file there, nothing Apache is audited.
func TestFindWebServerConfigPathSkipsAbsentApacheBesideOtherServers(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "conf-available"), 0o755); err != nil {
		t.Fatal(err)
	}
	info := platform.Info{OS: platform.OSUbuntu, WebServer: platform.WSNginx, ApacheConfigDir: root}
	if got := findWebServerConfigPath(info); got != "" {
		t.Fatalf("findWebServerConfigPath = %q, want none", got)
	}
	main := filepath.Join(root, "apache2.conf")
	writeApacheConf(t, main, "ServerTokens Prod\n")
	if got := findWebServerConfigPath(info); got != main {
		t.Fatalf("findWebServerConfigPath = %q, want the Apache main file beside nginx %q", got, main)
	}
	apache := platform.Info{OS: platform.OSUbuntu, WebServer: platform.WSApache, ApacheConfigDir: filepath.Join(root, "missing")}
	if got := findWebServerConfigPath(apache); got != filepath.Join(root, "missing", "apache2.conf") {
		t.Fatalf("findWebServerConfigPath = %q, want the selected Apache root even when absent", got)
	}
}
