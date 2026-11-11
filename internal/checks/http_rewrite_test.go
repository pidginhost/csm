package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/platform"
)

func writeRewriteFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func requireRewrite(t *testing.T, got HTTPRewrite, state RewriteState, directive, file string) {
	t.Helper()
	if got.State != state || got.Directive != directive || got.File != file {
		t.Fatalf("rewrite = %+v, want state %d, directive %q in %q", got, state, directive, file)
	}
	if state == RewriteUnknown && got.Reason == "" {
		t.Fatalf("unknown rewrite state %+v names no reason", got)
	}
}

// Apache rewrites when a RemoteIPHeader or an enabled RemoteIPProxyProtocol
// is configured in any scope, including inside IfModule or a virtual host.
func TestDetectHTTPRewriteReadsApacheRemoteIP(t *testing.T) {
	dir := t.TempDir()
	conf := writeRewriteFile(t, dir, "conf.d/remoteip.conf", "<IfModule remoteip_module>\n  RemoteIPHeader CF-Connecting-IP\n  RemoteIPTrustedProxy 192.0.2.0/24\n</IfModule>\n")
	main := writeRewriteFile(t, dir, "httpd.conf", "ServerRoot "+dir+"\nLoadModule remoteip_module modules/mod_remoteip.so\nIncludeOptional conf.d/*.conf\n")
	requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSApache, apacheConfig: main}),
		RewriteActive, "RemoteIPHeader CF-Connecting-IP", conf)

	vhost := writeRewriteFile(t, dir, "proxy.conf", "<VirtualHost *:443>\n  RemoteIPProxyProtocol On\n</VirtualHost>\n")
	requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSApache, apacheConfig: vhost}),
		RewriteActive, "RemoteIPProxyProtocol On", vhost)

	continued := writeRewriteFile(t, dir, "continued.conf", "RemoteIPHeader \\\n    X-Real-IP\n")
	requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSApache, apacheConfig: continued}),
		RewriteActive, "RemoteIPHeader X-Real-IP", continued)

	commented := writeRewriteFile(t, dir, "commented.conf", "RemoteIPHeader X-Real-IP # the CDN header\n")
	requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSApache, apacheConfig: commented}),
		RewriteUnknown, "", "")

	off := writeRewriteFile(t, dir, "off.conf", "RemoteIPProxyProtocol Off\n# RemoteIPHeader X-Forwarded-For\nLogFormat \"%h %l %u %t\" common\n")
	requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSApache, apacheConfig: off}), RewriteNone, "", "")
}

// Apache only recognizes comments at the start of a line and quotes at the
// start of an argument. Include names must retain their literal bytes.
func TestHTTPRewriteApacheLiteralIncludeNames(t *testing.T) {
	for _, name := range []string{"conf#edge/remoteip.conf", "conf'edge'/remoteip.conf", `conf\edge/remoteip.conf`} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			included := writeRewriteFile(t, dir, name, "RemoteIPHeader X-Real-IP\n")
			main := writeRewriteFile(t, dir, "httpd.conf", "IncludeOptional "+name+"\n")
			requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSApache, apacheConfig: main}),
				RewriteActive, "RemoteIPHeader X-Real-IP", included)
		})
	}
}

// APR keeps backslashes in path components with no unescaped wildcard,
// even when a later component uses a glob.
func TestHTTPRewriteApacheGlobLiteralDirectory(t *testing.T) {
	for _, name := range []string{`conf\edge`, `conf\*edge`} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			included := writeRewriteFile(t, dir, name+"/remoteip.conf", "RemoteIPHeader X-Real-IP\n")
			main := writeRewriteFile(t, dir, "httpd.conf", "IncludeOptional "+name+"/remote*.conf\n")
			requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSApache, apacheConfig: main}),
				RewriteActive, "RemoteIPHeader X-Real-IP", included)
		})
	}
}

func TestHTTPRewriteApacheLogicalLines(t *testing.T) {
	for name, tc := range map[string]struct{ body, directive string }{
		"final continuation": {"RemoteIPHeader X-Real-IP\\\n", "RemoteIPHeader X-Real-IP"},
		"final backslash":    {"RemoteIPHeader X-Real-IP\\", "RemoteIPHeader X-Real-IP\\"},
		"hash in header":     {"RemoteIPHeader X#Client\n", "RemoteIPHeader X#Client"},
		"form feed":          {"RemoteIPHeader\fX-Real-IP\n", "RemoteIPHeader X-Real-IP"},
		"vertical tab":       {"RemoteIPHeader\vX-Real-IP\n", "RemoteIPHeader X-Real-IP"},
	} {
		t.Run(name, func(t *testing.T) {
			main := writeRewriteFile(t, t.TempDir(), "httpd.conf", tc.body)
			requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSApache, apacheConfig: main}),
				RewriteActive, tc.directive, main)
		})
	}
}

// The daemon cannot resolve Apache's process environment or Define values
// in directive names. It must not mistake an unexpanded name for no rewrite.
func TestHTTPRewriteApacheUnresolvedDirectiveName(t *testing.T) {
	dir := t.TempDir()
	main := writeRewriteFile(t, dir, "httpd.conf", "Define rewrite RemoteIPHeader\n${rewrite} X-Real-IP\n")
	requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSApache, apacheConfig: main}), RewriteUnknown, "", "")
	main = writeRewriteFile(t, dir, "httpd.conf", "${rewrite} X-Real-IP\nRemoteIPProxyProtocol On\n")
	requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSApache, apacheConfig: main}), RewriteActive, "RemoteIPProxyProtocol On", main)
}

// Configuration globs use shell bracket negation, not Go's interpretation
// of a leading exclamation mark as a literal member of the class.
func TestHTTPRewriteIncludeGlobNegation(t *testing.T) {
	for _, server := range []platform.WebServer{platform.WSApache, platform.WSNginx} {
		t.Run(string(server), func(t *testing.T) {
			dir := t.TempDir()
			body, directive := "IncludeOptional conf.d/[!a]*.conf\n", "RemoteIPHeader X-Real-IP"
			if server == platform.WSNginx {
				body, directive = "include conf.d/[!a]*.conf;\n", "set_real_ip_from 192.0.2.0/24;"
			}
			included := writeRewriteFile(t, dir, "conf.d/remoteip.conf", directive+"\n")
			writeRewriteFile(t, dir, "conf.d/a.conf", "# no rewrite\n")
			main := writeRewriteFile(t, dir, "main.conf", body)
			src := rewriteSources{server: server, apacheConfig: main}
			if server == platform.WSNginx {
				src.apacheConfig, src.nginxConfig = "", main
			}
			requireRewrite(t, detectHTTPRewrite(src), RewriteActive, strings.TrimSuffix(directive, ";"), included)
		})
	}
}

func TestHTTPRewriteIncludeGlobBoundaries(t *testing.T) {
	for _, server := range []platform.WebServer{platform.WSApache, platform.WSNginx} {
		for _, tc := range []struct {
			pattern, name string
			state         RewriteState
		}{
			{"*.conf", ".remoteip.conf", RewriteNone},
			{".*.conf", ".remoteip.conf", RewriteActive},
			{"[]a]*.conf", "]remoteip.conf", RewriteActive},
			{"[-a]*.conf", "-remoteip.conf", RewriteActive},
			{"[a-]*.conf", "-remoteip.conf", RewriteActive},
			// Named classes depend on the server's glob implementation and locale.
			{"[[:alpha:]]*.conf", "remoteip.conf", RewriteUnknown},
		} {
			t.Run(string(server)+"/"+tc.pattern, func(t *testing.T) {
				dir := t.TempDir()
				body, directive := "IncludeOptional conf.d/"+tc.pattern+"\n", "RemoteIPHeader X-Real-IP"
				if server == platform.WSNginx {
					body, directive = "include conf.d/"+tc.pattern+";\n", "set_real_ip_from 192.0.2.0/24;"
				}
				included := writeRewriteFile(t, dir, "conf.d/"+tc.name, directive+"\n")
				main := writeRewriteFile(t, dir, "main.conf", body)
				src := rewriteSources{server: server, apacheConfig: main}
				if server == platform.WSNginx {
					src.apacheConfig, src.nginxConfig = "", main
				}
				if tc.state != RewriteActive {
					directive, included = "", ""
				}
				requireRewrite(t, detectHTTPRewrite(src), tc.state, strings.TrimSuffix(directive, ";"), included)
			})
		}
	}
}

// nginx leaves parent components to the filesystem; Apache's APR path merge
// cleans them first. Each reader must select the same tree as its server.
func TestHTTPRewriteIncludePreservesSymlinkParent(t *testing.T) {
	for _, server := range []platform.WebServer{platform.WSApache, platform.WSNginx} {
		for _, kind := range []string{"literal", "glob", "absolute"} {
			t.Run(string(server)+"/"+kind, func(t *testing.T) {
				dir := t.TempDir()
				if err := os.MkdirAll(filepath.Join(dir, "other/child"), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("other/child", filepath.Join(dir, "link")); err != nil {
					t.Fatal(err)
				}
				target := "link/../remoteip.conf"
				switch kind {
				case "glob":
					target = "link/../remote*.conf"
				case "absolute":
					target = dir + "/" + target
				}
				body, directive := "IncludeOptional "+target+"\n", "RemoteIPHeader X-Real-IP"
				if server == platform.WSNginx {
					body, directive = "include "+target+";\n", "set_real_ip_from 192.0.2.0/24;"
				}
				writeRewriteFile(t, dir, "other/remoteip.conf", directive+"\n")
				writeRewriteFile(t, dir, "remoteip.conf", "# another configuration\n")
				main := writeRewriteFile(t, dir, "main.conf", body)
				src := rewriteSources{server: server, apacheConfig: main}
				if server == platform.WSNginx {
					src.apacheConfig, src.nginxConfig = "", main
				}
				if server == platform.WSApache {
					requireRewrite(t, detectHTTPRewrite(src), RewriteNone, "", "")
				} else {
					requireRewrite(t, detectHTTPRewrite(src), RewriteActive, strings.TrimSuffix(directive, ";"), dir+"/link/../remoteip.conf")
				}
			})
		}
	}
}

func TestHTTPRewriteNginxDistinctPathsAreNotACycle(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "other/child"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("other/child", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	writeRewriteFile(t, dir, "other/main.conf", "set_real_ip_from 192.0.2.0/24;\n")
	main := writeRewriteFile(t, dir, "main.conf", "include link/../main.conf;\n")
	requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSNginx, nginxConfig: main}),
		RewriteActive, "set_real_ip_from 192.0.2.0/24", dir+"/link/../main.conf")
}

func TestHTTPRewriteNginxRootPreservesSymlinkParent(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "other/child"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("other/child", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	writeRewriteFile(t, dir, "other/nginx.conf", "include realip.conf;\n")
	writeRewriteFile(t, dir, "other/realip.conf", "set_real_ip_from 192.0.2.0/24;\n")
	writeRewriteFile(t, dir, "nginx.conf", "# another configuration\n")
	requireRewrite(t, DetectHTTPRewrite(platform.Info{WebServer: platform.WSNginx, NginxConfigDir: dir + "/link/.."}),
		RewriteActive, "set_real_ip_from 192.0.2.0/24", dir+"/link/../realip.conf")
}

// A fully read active setting remains evidence when later XML is broken.
func TestHTTPRewriteLiteSpeedPreservesActiveBeforeError(t *testing.T) {
	for _, suffix := range []string{"<broken", "", "</httpServerConfig>junk", "<useIpInProxyHeader>0</useIpInProxyHeader></httpServerConfig>"} {
		t.Run(suffix, func(t *testing.T) {
			conf := writeRewriteFile(t, t.TempDir(), "httpd_config.xml", "<httpServerConfig><useIpInProxyHeader>2</useIpInProxyHeader>"+suffix)
			requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSLiteSpeed, lswsConfig: conf}), RewriteActive, "useIpInProxyHeader 2", conf)
		})
	}
}

// Apache joins continued bytes without adding a separator. A split name
// or include target must not hide a rewrite from the reader.
func TestHTTPRewriteApacheContinuationBoundaries(t *testing.T) {
	for name, body := range map[string]string{
		"header name":            "RemoteIP\\\nHeader X-Real-IP\n",
		"comment trailing space": "# comment\\ \nRemoteIPHeader X-Real-IP\n",
		"comment trailing tab":   "# comment\\\t\nRemoteIPHeader X-Real-IP\n",
		"header CRLF":            "RemoteIP\\\r\nHeader X-Real-IP\r\n",
		"continued comment":      "# comment\\\\\nRemoteIPHeader X-Real-IP\n",
		"protocol name":          "RemoteIPProxy\\\nProtocol On\n",
		"include name":           "IncludeOp\\\ntional remoteip.conf\n",
		"include target":         "IncludeOptional remote\\\nip.conf\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			included := writeRewriteFile(t, dir, "remoteip.conf", "RemoteIPHeader X-Real-IP\n")
			main := writeRewriteFile(t, dir, "httpd.conf", body)
			if name == "continued comment" {
				requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSApache, apacheConfig: main}), RewriteNone, "", "")
				return
			}
			directive, file := "RemoteIPHeader X-Real-IP", main
			if strings.HasPrefix(name, "include") {
				file = included
			} else if name == "protocol name" {
				directive = "RemoteIPProxyProtocol On"
			}
			requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSApache, apacheConfig: main}), RewriteActive, directive, file)
		})
	}
}

// An Apache tree CSM cannot read completely names no direct state; a
// rewrite it did find still counts.
func TestDetectHTTPRewriteRefusesUnreadableApacheConfig(t *testing.T) {
	dir := t.TempDir()
	requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSApache, apacheConfig: filepath.Join(dir, "missing.conf")}), RewriteUnknown, "", "")
	requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSApache, apacheRequired: true}), RewriteUnknown, "", "")
	broken := writeRewriteFile(t, dir, "broken.conf", "Include "+filepath.Join(dir, "absent.conf")+"\n")
	requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSApache, apacheConfig: broken}), RewriteUnknown, "", "")
	found := writeRewriteFile(t, dir, "found.conf", "RemoteIPHeader X-Real-IP\nInclude "+filepath.Join(dir, "absent.conf")+"\n")
	requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSApache, apacheConfig: found}), RewriteActive, "RemoteIPHeader X-Real-IP", found)
}

// nginx rewrites wherever set_real_ip_from trusts a source, from
// real_ip_header or its X-Real-IP default.
func TestDetectHTTPRewriteReadsNginxRealIP(t *testing.T) {
	dir := t.TempDir()
	realip := writeRewriteFile(t, dir, "conf.d/realip.conf", "set_real_ip_from 192.0.2.0/24;\nset_real_ip_from 2001:db8::/32;\nreal_ip_header CF-Connecting-IP;\n")
	main := writeRewriteFile(t, dir, "nginx.conf", "events {}\nhttp {\n  include conf.d/*.conf;\n  include sites-enabled/*;\n  server { access_log /var/log/nginx/site.log combined; }\n}\n")
	requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSNginx, nginxConfig: main}),
		RewriteActive, "set_real_ip_from 192.0.2.0/24", realip)

	byDefault := writeRewriteFile(t, dir, "default.conf", "http { server { location / { set_real_ip_from 198.51.100.0/24; } } }\n")
	requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSNginx, nginxConfig: byDefault}),
		RewriteActive, "set_real_ip_from 198.51.100.0/24", byDefault)

	split := writeRewriteFile(t, dir, "split.conf", "http {\n  real_ip_header   # the CDN header\n    \"X-Forwarded-For\";\n  set_real_ip_from\n    192.0.2.0/24; # edge\n}\n")
	requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSNginx, nginxConfig: split}),
		RewriteActive, "set_real_ip_from 192.0.2.0/24", split)

	direct := writeRewriteFile(t, dir, "direct.conf", "http {\n  # set_real_ip_from 192.0.2.0/24;\n  log_format peer '$remote_addr set_real_ip_from;';\n  real_ip_header X-Forwarded-For;\n}\n")
	requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSNginx, nginxConfig: direct}), RewriteNone, "", "")
}

func TestDetectHTTPRewriteRefusesUnreadableNginxConfig(t *testing.T) {
	dir := t.TempDir()
	requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSNginx, nginxConfig: filepath.Join(dir, "nginx.conf")}), RewriteUnknown, "", "")
	missing := writeRewriteFile(t, dir, "missing.conf", "http { include extra/realip.conf; }\n")
	requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSNginx, nginxConfig: missing}), RewriteUnknown, "", "")
	unbalanced := writeRewriteFile(t, dir, "unbalanced.conf", "http { server {\n")
	requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSNginx, nginxConfig: unbalanced}), RewriteUnknown, "", "")
	loop := writeRewriteFile(t, dir, "loop.conf", "include loop.conf;\n")
	requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSNginx, nginxConfig: loop}), RewriteUnknown, "", "")
}

// LiteSpeed rewrites when "Use Client IP in Header" is on in its own
// configuration, and on cPanel also from the Apache tree it loads.
func TestDetectHTTPRewriteReadsLiteSpeed(t *testing.T) {
	dir := t.TempDir()
	on := writeRewriteFile(t, dir, "on.xml", "<?xml version=\"1.0\"?>\n<httpServerConfig>\n  <useIpInProxyHeader>2</useIpInProxyHeader>\n</httpServerConfig>\n")
	requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSLiteSpeed, lswsConfig: on}), RewriteActive, "useIpInProxyHeader 2", on)

	off := writeRewriteFile(t, dir, "off.xml", "<httpServerConfig><useIpInProxyHeader>0</useIpInProxyHeader></httpServerConfig>")
	requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSLiteSpeed, lswsConfig: off}), RewriteNone, "", "")
	absent := writeRewriteFile(t, dir, "absent.xml", "<httpServerConfig><serverName>web</serverName></httpServerConfig>")
	requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSLiteSpeed, lswsConfig: absent}), RewriteNone, "", "")

	apache := writeRewriteFile(t, dir, "httpd.conf", "RemoteIPHeader CF-Connecting-IP\n")
	requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSLiteSpeed, lswsConfig: off, apacheConfig: apache}),
		RewriteActive, "RemoteIPHeader CF-Connecting-IP", apache)

	broken := writeRewriteFile(t, dir, "broken.xml", "<httpServerConfig><useIpInProxyHeader>2")
	requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSLiteSpeed, lswsConfig: broken}), RewriteUnknown, "", "")
	requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSLiteSpeed, lswsConfig: filepath.Join(dir, "none.xml")}), RewriteUnknown, "", "")
}

// A host without a web server has no web logs to rewrite.
func TestDetectHTTPRewriteWithoutAWebServer(t *testing.T) {
	requireRewrite(t, DetectHTTPRewrite(platform.Info{}), RewriteNone, "", "")
	requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WebServer("caddy")}), RewriteUnknown, "", "")
}

// deniedOS refuses reads of the listed paths with a permission error, which
// a test running as root could not get from file modes.
type deniedOS struct {
	OS
	deny map[string]bool
}

func (d deniedOS) refused(name string) error {
	if d.deny[filepath.Clean(name)] {
		return &os.PathError{Op: "open", Path: name, Err: os.ErrPermission}
	}
	return nil
}

func (d deniedOS) ReadDir(name string) ([]os.DirEntry, error) {
	if err := d.refused(name); err != nil {
		return nil, err
	}
	return d.OS.ReadDir(name)
}

func (d deniedOS) ReadFile(name string) ([]byte, error) {
	if err := d.refused(name); err != nil {
		return nil, err
	}
	return d.OS.ReadFile(name)
}

func (d deniedOS) Open(name string) (*os.File, error) {
	if err := d.refused(name); err != nil {
		return nil, err
	}
	return d.OS.Open(name)
}

func withDeniedPaths(t *testing.T, paths ...string) {
	t.Helper()
	prev := osFS
	deny := make(map[string]bool)
	for _, p := range paths {
		deny[filepath.Clean(p)] = true
	}
	SetOS(deniedOS{OS: prev, deny: deny})
	t.Cleanup(func() { SetOS(prev) })
}

// A directory CSM cannot list is not an empty one: filepath.Glob drops the
// error, so an include there must leave the tree unknown, not direct. A
// rewrite found elsewhere still counts, and an absent optional glob or an
// empty directory stays direct.
func TestHTTPRewriteUnreadableIncludeDirectories(t *testing.T) {
	type tree struct {
		files   map[string]string
		dirs    []string
		links   map[string]string
		deny    []string
		src     func(dir string) rewriteSources
		state   RewriteState
		dirFile string
	}
	nginx := func(dir string) rewriteSources {
		return rewriteSources{server: platform.WSNginx, nginxConfig: filepath.Join(dir, "nginx.conf")}
	}
	apache := func(dir string) rewriteSources {
		return rewriteSources{server: platform.WSApache, apacheConfig: filepath.Join(dir, "httpd.conf"), apacheRequired: true}
	}
	const realip = "set_real_ip_from 192.0.2.0/24;\n"
	for name, tc := range map[string]tree{
		"nginx glob": {files: map[string]string{"nginx.conf": "http { include conf.d/*.conf; }\n", "conf.d/realip.conf": realip},
			deny: []string{"conf.d"}, src: nginx, state: RewriteUnknown},
		"apache optional glob": {files: map[string]string{"httpd.conf": "IncludeOptional conf.d/*.conf\n", "conf.d/remoteip.conf": "RemoteIPHeader X-Real-IP\n"},
			deny: []string{"conf.d"}, src: apache, state: RewriteUnknown},
		"apache directory": {files: map[string]string{"httpd.conf": "Include conf.d\n", "conf.d/remoteip.conf": "RemoteIPHeader X-Real-IP\n"},
			deny: []string{"conf.d"}, src: apache, state: RewriteUnknown},
		"wildcard parent": {files: map[string]string{"nginx.conf": "include sites-*/conf.d/*.conf;\n", "sites-a/conf.d/realip.conf": realip},
			deny: []string{"sites-a/conf.d"}, src: nginx, state: RewriteUnknown},
		"unreadable matched file": {files: map[string]string{"nginx.conf": "include conf.d/*.conf;\n", "conf.d/realip.conf": realip},
			deny: []string{"conf.d/realip.conf"}, src: nginx, state: RewriteUnknown},
		"apache unreadable matched file": {files: map[string]string{"httpd.conf": "IncludeOptional conf.d/*.conf\n", "conf.d/remoteip.conf": "RemoteIPHeader X-Real-IP\n"},
			deny: []string{"conf.d/remoteip.conf"}, src: apache, state: RewriteUnknown},
		"broken symlink": {files: map[string]string{"nginx.conf": "include conf.d/*.conf;\n"},
			links: map[string]string{"conf.d/gone.conf": "absent.conf"}, src: nginx, state: RewriteUnknown},
		"apache broken symlink": {files: map[string]string{"httpd.conf": "IncludeOptional conf.d/*.conf\n"},
			links: map[string]string{"conf.d/gone.conf": "absent.conf"}, src: apache, state: RewriteUnknown},
		"invalid glob":          {files: map[string]string{"nginx.conf": "include conf.d/[.conf;\n"}, dirs: []string{"conf.d"}, src: nginx, state: RewriteUnknown},
		"nginx directory match": {files: map[string]string{"nginx.conf": "include conf.d/*;\n", "conf.d/sub/x.conf": realip}, src: nginx, state: RewriteUnknown},
		"rewrite beside an unreadable directory": {files: map[string]string{"nginx.conf": "include conf.d/*.conf;\ninclude extra.conf;\n", "conf.d/a.conf": "x;\n", "extra.conf": realip},
			deny: []string{"conf.d"}, src: nginx, state: RewriteActive, dirFile: "extra.conf"},
		"nginx absent glob":           {files: map[string]string{"nginx.conf": "include missing/*.conf;\n"}, src: nginx, state: RewriteNone},
		"apache absent optional glob": {files: map[string]string{"httpd.conf": "IncludeOptional missing/*.conf\n"}, src: apache, state: RewriteNone},
		"readable empty directory":    {files: map[string]string{"nginx.conf": "include conf.d/*.conf;\n"}, dirs: []string{"conf.d"}, src: nginx, state: RewriteNone},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			for p, body := range tc.files {
				writeRewriteFile(t, dir, p, body)
			}
			for _, d := range tc.dirs {
				if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			for p, target := range tc.links {
				if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, p)), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, filepath.Join(dir, p)); err != nil {
					t.Fatal(err)
				}
			}
			var deny []string
			for _, p := range tc.deny {
				deny = append(deny, filepath.Join(dir, p))
			}
			withDeniedPaths(t, deny...)
			got := detectHTTPRewrite(tc.src(dir))
			if got.State != tc.state {
				t.Fatalf("rewrite = %+v, want state %d", got, tc.state)
			}
			if tc.dirFile != "" && got.File != filepath.Join(dir, tc.dirFile) {
				t.Fatalf("rewrite names %q, want %q", got.File, filepath.Join(dir, tc.dirFile))
			}
		})
	}
}

// Apache refuses a bare or invalid mod_remoteip directive, so the running
// server is not the one the file describes: unknown, unless a valid
// rewrite appears elsewhere.
func TestHTTPRewriteMalformedApacheDirective(t *testing.T) {
	dir := t.TempDir()
	for _, body := range []string{"RemoteIPHeader\n", "RemoteIPHeader X-Real-IP CF-Connecting-IP\n", "RemoteIPProxyProtocol\n", "RemoteIPProxyProtocol Maybe\n"} {
		conf := writeRewriteFile(t, dir, "bad.conf", body)
		requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSApache, apacheConfig: conf}), RewriteUnknown, "", "")
	}
	both := writeRewriteFile(t, dir, "both.conf", "RemoteIPHeader\nRemoteIPHeader X-Real-IP\n")
	requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSApache, apacheConfig: both}), RewriteActive, "RemoteIPHeader X-Real-IP", both)
}

// Only one well-formed httpServerConfig document with at most one plain
// setting is readable; the whole value counts, wherever comments or CDATA
// split it.
func TestHTTPRewriteLiteSpeedDocumentBoundaries(t *testing.T) {
	doc := func(inner string) string { return "<httpServerConfig>" + inner + "</httpServerConfig>" }
	setting := func(v string) string { return doc("<useIpInProxyHeader>" + v + "</useIpInProxyHeader>") }
	for name, tc := range map[string]struct {
		body      string
		state     RewriteState
		directive string
	}{
		"empty":            {"", RewriteUnknown, ""},
		"whitespace":       {"  \n", RewriteUnknown, ""},
		"comment only":     {"<!-- c -->", RewriteUnknown, ""},
		"wrong root":       {"<virtualHostConfig/>", RewriteUnknown, ""},
		"leading text":     {"junk" + doc(""), RewriteUnknown, ""},
		"trailing text":    {doc("") + "junk", RewriteUnknown, ""},
		"non XML space":    {doc("") + "\u00a0", RewriteUnknown, ""},
		"outer whitespace": {" 	\r\n" + doc("") + "\n<!-- end -->", RewriteNone, ""},
		"two roots":        {doc("") + doc(""), RewriteUnknown, ""},
		"truncated":        {"<httpServerConfig><useIpInProxyHeader>2", RewriteUnknown, ""},
		"empty setting":    {setting(""), RewriteUnknown, ""},
		"nested setting":   {setting("<x/>2"), RewriteUnknown, ""},
		"duplicate":        {doc("<useIpInProxyHeader>0</useIpInProxyHeader><useIpInProxyHeader>2</useIpInProxyHeader>"), RewriteUnknown, ""},
		"broken after":     {"<httpServerConfig><useIpInProxyHeader>0</useIpInProxyHeader><broken", RewriteUnknown, ""},
		"absent":           {doc("<serverName>web</serverName>"), RewriteNone, ""},
		"zero":             {setting(" 0 "), RewriteNone, ""},
		"one":              {setting("1"), RewriteActive, "useIpInProxyHeader 1"},
		"two":              {setting("2"), RewriteActive, "useIpInProxyHeader 2"},
		"three":            {setting("3"), RewriteActive, "useIpInProxyHeader 3"},
		"comment split":    {setting("0<!-- split -->2"), RewriteActive, "useIpInProxyHeader 02"},
		"cdata continues":  {setting("0<![CDATA[2]]>"), RewriteActive, "useIpInProxyHeader 02"},
	} {
		t.Run(name, func(t *testing.T) {
			conf := writeRewriteFile(t, t.TempDir(), "httpd_config.xml", tc.body)
			file := ""
			if tc.state == RewriteActive {
				file = conf
			}
			requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSLiteSpeed, lswsConfig: conf}), tc.state, tc.directive, file)
		})
	}
	dir := t.TempDir()
	broken := writeRewriteFile(t, dir, "broken.xml", "<httpServerConfig>")
	apache := writeRewriteFile(t, dir, "httpd.conf", "RemoteIPHeader CF-Connecting-IP\n")
	requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSLiteSpeed, lswsConfig: broken, apacheConfig: apache, apacheRequired: true}),
		RewriteActive, "RemoteIPHeader CF-Connecting-IP", apache)
}

// nginx starts a comment only at a token boundary, so a hash inside a word
// does not hide the directives after it; an escaped include name reads the
// file nginx would read.
func TestHTTPRewriteNginxTokenBoundaries(t *testing.T) {
	dir := t.TempDir()
	hash := writeRewriteFile(t, dir, "hash.conf", "http {\n  log_format peer foo#bar; set_real_ip_from 192.0.2.0/24;\n  access_log /var/log/nginx/site.log peer;\n}\n")
	requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSNginx, nginxConfig: hash}), RewriteActive, "set_real_ip_from 192.0.2.0/24", hash)

	// nginx decodes \" in a name, but keeps a backslash before a space.
	quote := writeRewriteFile(t, dir, `a"b.conf`, "set_real_ip_from 198.51.100.0/24;\n")
	writeRewriteFile(t, dir, `a\"b.conf`, "listen 80;\n")
	escapedQuote := writeRewriteFile(t, dir, "quote.conf", `http { include "a\"b.conf"; }`+"\n")
	requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSNginx, nginxConfig: escapedQuote}), RewriteActive, "set_real_ip_from 198.51.100.0/24", quote)
	space := writeRewriteFile(t, dir, `c\ d.conf`, "set_real_ip_from 203.0.113.0/24;\n")
	writeRewriteFile(t, dir, "c d.conf", "listen 80;\n")
	escapedSpace := writeRewriteFile(t, dir, "space.conf", `http { include c\ d.conf; }`+"\n")
	requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSNginx, nginxConfig: escapedSpace}), RewriteActive, "set_real_ip_from 203.0.113.0/24", space)

	quoted := writeRewriteFile(t, dir, "quoted.conf", "http { log_format x \"${remote_addr} set_real_ip_from 192.0.2.0/24;\" 'set_real_ip_from;'; }\n")
	requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSNginx, nginxConfig: quoted}), RewriteNone, "", "")
}

// An nginx host whose only set_real_ip_from sits beside an unrelated
// real_ip_header names the trust setting, not the header.
func TestHTTPRewriteNginxUnrelatedHeader(t *testing.T) {
	dir := t.TempDir()
	trust := writeRewriteFile(t, dir, "trust.conf", "set_real_ip_from 192.0.2.0/24;\n")
	main := writeRewriteFile(t, dir, "nginx.conf", "http {\n  server { real_ip_header CF-Connecting-IP; }\n  server { include trust.conf; }\n}\n")
	requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSNginx, nginxConfig: main}), RewriteActive, "set_real_ip_from 192.0.2.0/24", trust)
}

// rootedOS serves absolute paths from a test directory and refuses the
// listed ones, so the public entry point reads platform-owned locations
// without touching the machine's configuration.
type rootedOS struct {
	OS
	root string
	deny map[string]bool
}

func (r rootedOS) at(name string) (string, error) {
	if r.deny[name] {
		return "", &os.PathError{Op: "open", Path: name, Err: os.ErrPermission}
	}
	if !filepath.IsAbs(name) {
		return "", &os.PathError{Op: "open", Path: name, Err: os.ErrNotExist}
	}
	return filepath.Join(r.root, name), nil
}

func (r rootedOS) ReadFile(name string) ([]byte, error) {
	p, err := r.at(name)
	if err != nil {
		return nil, err
	}
	return r.OS.ReadFile(p)
}

func (r rootedOS) ReadDir(name string) ([]os.DirEntry, error) {
	p, err := r.at(name)
	if err != nil {
		return nil, err
	}
	return r.OS.ReadDir(p)
}

func (r rootedOS) Stat(name string) (os.FileInfo, error) {
	p, err := r.at(name)
	if err != nil {
		return nil, err
	}
	return r.OS.Stat(p)
}

func (r rootedOS) Lstat(name string) (os.FileInfo, error) {
	p, err := r.at(name)
	if err != nil {
		return nil, err
	}
	return r.OS.Lstat(p)
}

func (r rootedOS) Open(name string) (*os.File, error) {
	p, err := r.at(name)
	if err != nil {
		return nil, err
	}
	return r.OS.Open(p)
}

func (r rootedOS) Glob(pattern string) ([]string, error) {
	matches, err := r.OS.Glob(filepath.Join(r.root, pattern))
	for i, m := range matches {
		matches[i] = strings.TrimPrefix(m, r.root)
	}
	return matches, err
}

// DetectHTTPRewrite reads the files each platform layout names: the Apache
// main file per family and panel, the nginx root including a configured
// one, and LiteSpeed's XML with the Apache tree only on cPanel.
func TestDetectHTTPRewriteUsesPlatformSources(t *testing.T) {
	const (
		remoteip = "RemoteIPHeader CF-Connecting-IP\n"
		lswsOff  = "<httpServerConfig><useIpInProxyHeader>0</useIpInProxyHeader></httpServerConfig>"
		lswsOn   = "<httpServerConfig><useIpInProxyHeader>2</useIpInProxyHeader></httpServerConfig>"
	)
	for name, tc := range map[string]struct {
		info      platform.Info
		files     map[string]string
		deny      []string
		state     RewriteState
		directive string
		file      string
	}{
		"debian apache": {platform.Info{OS: platform.OSDebian, WebServer: platform.WSApache, ApacheConfigDir: "/etc/apache2"},
			map[string]string{"/etc/apache2/apache2.conf": "IncludeOptional conf-enabled/*.conf\n", "/etc/apache2/conf-enabled/remoteip.conf": remoteip}, nil,
			RewriteActive, "RemoteIPHeader CF-Connecting-IP", "/etc/apache2/conf-enabled/remoteip.conf"},
		"rhel apache": {platform.Info{OS: platform.OSAlma, WebServer: platform.WSApache, ApacheConfigDir: "/etc/httpd"},
			map[string]string{"/etc/httpd/conf/httpd.conf": "ServerTokens Prod\n"}, nil, RewriteNone, "", ""},
		"cpanel apache": {platform.Info{Panel: platform.PanelCPanel, WebServer: platform.WSApache},
			map[string]string{"/etc/apache2/conf/httpd.conf": "Include /etc/apache2/conf.d/includes/*.conf\n", "/etc/apache2/conf.d/includes/cloudflare.conf": remoteip}, nil,
			RewriteActive, "RemoteIPHeader CF-Connecting-IP", "/etc/apache2/conf.d/includes/cloudflare.conf"},
		"missing apache root": {platform.Info{OS: platform.OSDebian, WebServer: platform.WSApache, ApacheConfigDir: "/srv/apache"},
			map[string]string{"/etc/apache2/apache2.conf": "ServerTokens Prod\n"}, nil, RewriteUnknown, "", ""},
		"missing cpanel tree beside distro tree": {platform.Info{OS: platform.OSAlma, Panel: platform.PanelCPanel, WebServer: platform.WSLiteSpeed},
			map[string]string{platform.LiteSpeedConfigPath: lswsOff, "/etc/httpd/conf/httpd.conf": "ServerTokens Prod\n"}, nil, RewriteUnknown, "", ""},
		"cpanel custom root": {platform.Info{Panel: platform.PanelCPanel, WebServer: platform.WSLiteSpeed, ApacheConfigDir: "/srv/apache"},
			map[string]string{platform.LiteSpeedConfigPath: lswsOff, "/srv/apache/conf/httpd.conf": remoteip, "/etc/apache2/conf/httpd.conf": "ServerTokens Prod\n"}, nil,
			RewriteActive, "RemoteIPHeader CF-Connecting-IP", "/srv/apache/conf/httpd.conf"},
		"cpanel legacy conf directory": {platform.Info{Panel: platform.PanelCPanel, WebServer: platform.WSLiteSpeed, ApacheConfigDir: "/usr/local/apache/conf"},
			map[string]string{platform.LiteSpeedConfigPath: lswsOff, "/usr/local/apache/conf/httpd.conf": remoteip}, nil,
			RewriteActive, "RemoteIPHeader CF-Connecting-IP", "/usr/local/apache/conf/httpd.conf"},
		"nginx custom root": {platform.Info{WebServer: platform.WSNginx, NginxConfigDir: "/srv/nginx"},
			map[string]string{"/srv/nginx/nginx.conf": "http { include conf.d/*.conf; }\n", "/srv/nginx/conf.d/realip.conf": "set_real_ip_from 192.0.2.0/24;\n", "/etc/nginx/nginx.conf": "http {}\n"}, nil,
			RewriteActive, "set_real_ip_from 192.0.2.0/24", "/srv/nginx/conf.d/realip.conf"},
		"nginx default root": {platform.Info{WebServer: platform.WSNginx},
			map[string]string{"/etc/nginx/nginx.conf": "http { set_real_ip_from 198.51.100.0/24; }\n"}, nil,
			RewriteActive, "set_real_ip_from 198.51.100.0/24", "/etc/nginx/nginx.conf"},
		"native litespeed": {platform.Info{WebServer: platform.WSLiteSpeed},
			map[string]string{platform.LiteSpeedConfigPath: lswsOff, "/etc/apache2/conf/httpd.conf": remoteip}, nil, RewriteNone, "", ""},
		"native litespeed on": {platform.Info{WebServer: platform.WSLiteSpeed},
			map[string]string{platform.LiteSpeedConfigPath: lswsOn}, nil, RewriteActive, "useIpInProxyHeader 2", platform.LiteSpeedConfigPath},
		"cpanel litespeed": {platform.Info{Panel: platform.PanelCPanel, WebServer: platform.WSLiteSpeed},
			map[string]string{platform.LiteSpeedConfigPath: lswsOff, "/etc/apache2/conf/httpd.conf": remoteip}, nil,
			RewriteActive, "RemoteIPHeader CF-Connecting-IP", "/etc/apache2/conf/httpd.conf"},
		"cpanel missing apache": {platform.Info{Panel: platform.PanelCPanel, WebServer: platform.WSLiteSpeed},
			map[string]string{platform.LiteSpeedConfigPath: lswsOff}, nil, RewriteUnknown, "", ""},
		"cpanel unreadable apache": {platform.Info{Panel: platform.PanelCPanel, WebServer: platform.WSLiteSpeed},
			map[string]string{platform.LiteSpeedConfigPath: lswsOff, "/etc/apache2/conf/httpd.conf": remoteip}, []string{"/etc/apache2/conf/httpd.conf"}, RewriteUnknown, "", ""},
		"cpanel unreadable apache, header on": {platform.Info{Panel: platform.PanelCPanel, WebServer: platform.WSLiteSpeed},
			map[string]string{platform.LiteSpeedConfigPath: lswsOn, "/etc/apache2/conf/httpd.conf": remoteip}, []string{"/etc/apache2/conf/httpd.conf"},
			RewriteActive, "useIpInProxyHeader 2", platform.LiteSpeedConfigPath},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			for p, body := range tc.files {
				writeRewriteFile(t, root, p, body)
			}
			deny := make(map[string]bool)
			for _, p := range tc.deny {
				deny[p] = true
			}
			prev := osFS
			SetOS(rootedOS{OS: prev, root: root, deny: deny})
			t.Cleanup(func() { SetOS(prev) })
			got := DetectHTTPRewrite(tc.info)
			if got.Server != tc.info.WebServer {
				t.Fatalf("rewrite = %+v names another server", got)
			}
			requireRewrite(t, got, tc.state, tc.directive, tc.file)
		})
	}
}
