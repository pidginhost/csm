package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/platform"
)

// Core opening sections ignore text after the last argument delimiter;
// ordinary closing sections ignore text after their directive token.
func TestApacheContainerTagIgnoresTextAfterTag(t *testing.T) {
	for _, tc := range []struct {
		line, name, label string
		closing           bool
	}{
		{"<VirtualHost *:80> # main site", "VirtualHost", "VirtualHost *:80", false},
		{"</VirtualHost> # end", "VirtualHost", "VirtualHost", true},
		{"<IfModule mod_security2.c> # waf", "IfModule", "IfModule mod_security2.c", false},
		{"<Else > # fallback", "Else", "Else", false},
		{"<IfVersion >= 2.0>", "IfVersion", "IfVersion >= 2.0", false},
		{"</If> # end > here", "If", "If", true},
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
	for _, close := range []string{"</FilesMatch>", "</FilesMatch> # end > here"} {
		grant := "<FilesMatch \"^()$\"> # assets\nAllow from all\n" + close
		body := "RewriteEngine Off\n" + grant + "\n"
		matches := detectRewriteOffShield([]byte(body), ".htaccess")
		if len(matches) != 2 {
			t.Fatalf("rewrite-off shield findings = %d, want 2", len(matches))
		}
		for i, want := range []string{"RewriteEngine Off", grant} {
			span := matches[i].Range
			if got := body[span.Start:span.End]; got != want {
				t.Errorf("shield range %d = %q, want %q", i, got, want)
			}
		}
	}
}

func TestEngineModeSeesCommentedIfModule(t *testing.T) {
	mode, known, err := parseEngineDirectives(strings.NewReader("<IfModule mod_security2.c> # waf\nSecRuleEngine DetectionOnly\n</IfModule>\n"))
	if err != nil || !known || mode != "detectiononly" {
		t.Fatalf("mode = %q known %v err %v, want detectiononly", mode, known, err)
	}
}

// Apache's active read-time sections require the closing line itself to
// match. A trailing comment is allowed on their opening line only.
func TestEngineModeRejectsCommentedActiveIfModuleClose(t *testing.T) {
	mode, known, err := parseEngineDirectives(strings.NewReader("<IfModule mod_security2.c> # waf\nSecRuleEngine DetectionOnly\n</IfModule> # end\n"))
	if err != nil || known || mode != "" {
		t.Fatalf("mode = %q known %v err %v, want unknown", mode, known, err)
	}
}

func TestApacheContainerTagSuffixSyntax(t *testing.T) {
	for _, line := range []string{
		"</VirtualHost> # end > here",
		"</VirtualHost> # \"unterminated quote",
	} {
		tag, isContainer, valid := parseApacheContainerTag(line)
		if !isContainer || !valid || !tag.closing || tag.name != "VirtualHost" || tag.label != "VirtualHost" {
			t.Errorf("parseApacheContainerTag(%q) = %+v, %v, %v; want VirtualHost close", line, tag, isContainer, valid)
		}
	}
	for _, line := range []string{
		"</VirtualHost>junk",
		"</VirtualHost>#comment",
		"</VirtualHost > # end",
		"<Else> # missing argument delimiter",
		"<Else>#comment",
		"<IfVersion >= 2.0> # version",
		"</IfModule> # end",
		"</IfDefine> # end",
		"</IfFile> # end",
		"</IfDirective> # end",
		"</IfSection> # end",
		"</IfVersion> # end",
	} {
		if _, isContainer, valid := parseApacheContainerTag(line); !isContainer || valid {
			t.Errorf("parseApacheContainerTag(%q) = container %v valid %v, want invalid container", line, isContainer, valid)
		}
	}
}

func TestApacheCommentedTagsIgnoreSuffixQuotes(t *testing.T) {
	for _, suffix := range []string{` # "site`, ` # 'site`, ` "site`} {
		t.Run(suffix, func(t *testing.T) {
			dir := t.TempDir()
			main := writeRewriteFile(t, dir, "httpd.conf", "ServerTokens Prod\n<VirtualHost *:80>"+suffix+"\nInclude site.conf\n</VirtualHost>"+suffix+"\n")
			included := writeRewriteFile(t, dir, "site.conf", "ServerName www.example.com\n")
			requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSApache, apacheConfig: main}), RewriteNone, "", "")
			if got, ok := auditByName(auditApacheDirectives(main), "web_server_tokens"); !ok || got.Status != "pass" {
				t.Errorf("web_server_tokens = %+v, want pass", got)
			}
			writeApacheConf(t, included, "Include missing.conf\n")
			requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSApache, apacheConfig: main}), RewriteUnknown, "", "")
			writeApacheConf(t, included, "Include missing.conf\nRemoteIPHeader X-Real-IP\n")
			requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSApache, apacheConfig: main}), RewriteActive, "RemoteIPHeader X-Real-IP", included)
		})
	}
}

func TestHTTPRewriteApacheInvalidTagSuffixIsUnknown(t *testing.T) {
	for _, body := range []string{
		"<VirtualHost *:80>\n</VirtualHost>junk\n",
		"<IfModule core_module>\n</IfModule> # end\n",
		"<IfVersion >= 2.0> # version\n</IfVersion>\n",
		"<If \"true\">\n</If>\n<Else> # end\n</Else>\n",
		"<${SECTION} *:80>\n</${SECTION}>\n",
	} {
		t.Run(body, func(t *testing.T) {
			main := writeRewriteFile(t, t.TempDir(), "httpd.conf", "ServerTokens Prod\n"+body)
			requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSApache, apacheConfig: main}), RewriteUnknown, "", "")
			if got, ok := auditByName(auditApacheDirectives(main), "web_server_tokens"); !ok || got.Status != "warn" {
				t.Errorf("web_server_tokens = %+v, want warn", got)
			}
			writeApacheConf(t, main, body+"RemoteIPHeader X-Real-IP\n")
			requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSApache, apacheConfig: main}), RewriteActive, "RemoteIPHeader X-Real-IP", main)
		})
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
