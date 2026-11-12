package checks

import (
	"testing"

	"github.com/pidginhost/csm/internal/platform"
)

// mod_cloudflare replaces the client address as soon as it is loaded, from
// its built-in Cloudflare ranges; mod_rpaf only once it is enabled. Either
// counts in any scope, like mod_remoteip.
func TestHTTPRewriteApacheLegacyProxyModules(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name, body string
		state      RewriteState
		directive  string
	}{
		{"unresolved module symbol", "Define proxy_module cloudflare_module\nLoadModule ${proxy_module} modules/mod_cloudflare.so\n", RewriteUnknown, ""},
		{"cloudflare missing module path", "LoadModule cloudflare_module\n", RewriteUnknown, ""},
		{"cloudflare extra module argument", "LoadModule cloudflare_module modules/mod_cloudflare.so extra\n", RewriteUnknown, ""},
		{"cloudflare loaded", "LoadModule cloudflare_module modules/mod_cloudflare.so\n", RewriteActive, "LoadModule cloudflare_module modules/mod_cloudflare.so"},
		{"cloudflare header", "<IfModule mod_cloudflare.c>\n  CloudFlareRemoteIPHeader X-Forwarded-For\n</IfModule>\n", RewriteActive, "CloudFlareRemoteIPHeader X-Forwarded-For"},
		{"cloudflare proxies", "<VirtualHost *:443>\n  cloudflareremoteiptrustedproxy 192.0.2.0/24 198.51.100.7\n</VirtualHost>\n", RewriteActive, "cloudflareremoteiptrustedproxy 192.0.2.0/24 198.51.100.7"},
		{"rpaf enabled", "<IfModule rpaf_module>\n  RPAF_Enable On\n  RPAF_ProxyIPs 192.0.2.10\n</IfModule>\n", RewriteActive, "RPAF_Enable On"},
		{"old rpaf enabled", "rpafenable on\nRPAFproxy_ips 192.0.2.10\n", RewriteActive, "rpafenable on"},
		{"rpaf disabled", "LoadModule rpaf_module modules/mod_rpaf.so\nRPAF_Enable Off\nRPAF_ProxyIPs 192.0.2.10\nRPAF_Header X-Forwarded-For\n", RewriteNone, ""},
		{"rpaf loaded only", "LoadModule rpaf_module modules/mod_rpaf.so\nRPAFheader X-Forwarded-For\n", RewriteNone, ""},
		{"commented", "# LoadModule cloudflare_module modules/mod_cloudflare.so\n#RPAF_Enable On\n", RewriteNone, ""},
		{"other module", "LoadModule cloudflare_status_module modules/mod_cfstatus.so\n", RewriteNone, ""},
		{"bare rpaf", "RPAF_Enable\n", RewriteUnknown, ""},
		{"invalid rpaf", "RPAFenable Maybe\n", RewriteUnknown, ""},
		{"two rpaf values", "RPAF_Enable On Off\n", RewriteUnknown, ""},
		{"bare cloudflare header", "CloudFlareRemoteIPHeader\n", RewriteUnknown, ""},
		{"two cloudflare headers", "CloudFlareRemoteIPHeader X-Real-IP CF-Connecting-IP\n", RewriteUnknown, ""},
		{"bare cloudflare proxies", "CloudFlareRemoteIPTrustedProxy\n", RewriteUnknown, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			conf := writeRewriteFile(t, dir, c.name+".conf", c.body)
			file := conf
			if c.state != RewriteActive {
				file = ""
			}
			requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSApache, apacheConfig: conf}), c.state, c.directive, file)
		})
	}
}

// cPanel LiteSpeed applies the Apache tree it loads, legacy modules
// included.
func TestHTTPRewriteLiteSpeedReadsApacheLegacyModules(t *testing.T) {
	dir := t.TempDir()
	off := writeRewriteFile(t, dir, "httpd_config.xml", "<httpServerConfig><useIpInProxyHeader>0</useIpInProxyHeader></httpServerConfig>")
	apache := writeRewriteFile(t, dir, "httpd.conf", "Include modules.conf\n")
	modules := writeRewriteFile(t, dir, "modules.conf", "LoadModule cloudflare_module modules/mod_cloudflare.so\n")
	requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSLiteSpeed, lswsConfig: off, apacheConfig: apache, apacheRequired: true}),
		RewriteActive, "LoadModule cloudflare_module modules/mod_cloudflare.so", modules)
}
