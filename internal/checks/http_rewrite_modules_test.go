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
		{"empty cloudflare header", "CloudFlareRemoteIPHeader \"\"\n", RewriteUnknown, ""},
		{"empty cloudflare proxies", "CloudFlareRemoteIPTrustedProxy ''\n", RewriteUnknown, ""},
		{"empty first cloudflare proxy", "CloudFlareRemoteIPTrustedProxy '' 192.0.2.10\n", RewriteUnknown, ""},
		{"cloudflare access restriction", "<IfModule mod_cloudflare.c>\nDenyAllButCloudFlare\n</IfModule>\n", RewriteActive, "DenyAllButCloudFlare"},
		{"mixed case cloudflare access restriction", "<VirtualHost *:443>\ndEnYaLlBuTcLoUdFlArE\n</VirtualHost>\n", RewriteActive, "dEnYaLlBuTcLoUdFlArE"},
		{"cloudflare access restriction argument", "DenyAllButCloudFlare On\n", RewriteUnknown, ""},
		{"cloudflare access restriction empty argument", "DenyAllButCloudFlare ''\n", RewriteUnknown, ""},
		{"cloudflare access restriction comment", "DenyAllButCloudFlare # comment\n", RewriteUnknown, ""},
		{"bare module", "LoadModule\n", RewriteUnknown, ""},
		{"empty module symbol", "LoadModule '' modules/mod_cloudflare.so\n", RewriteUnknown, ""},
		{"cloudflare empty module path", "LoadModule cloudflare_module ''\n", RewriteUnknown, ""},
		{"rpaf missing module path", "LoadModule rpaf_module\nRPAF_Enable Off\n", RewriteUnknown, ""},
		{"rpaf empty module path", "LoadModule rpaf_module ''\n", RewriteUnknown, ""},
		{"rpaf extra module argument", "LoadModule rpaf_module modules/mod_rpaf.so extra\n", RewriteUnknown, ""},
		{"mixed case load directive", "lOaDmOdUlE cloudflare_module modules/mod_cloudflare.so\n", RewriteActive, "lOaDmOdUlE cloudflare_module modules/mod_cloudflare.so"},
		{"module symbols are case sensitive", "LoadModule Cloudflare_module modules/mod_cloudflare.so\n", RewriteNone, ""},
		{"module filename is not a symbol", "LoadModule other_module modules/mod_cloudflare.so\n", RewriteNone, ""},
		{"similar cloudflare directive", "CloudFlareRemoteIPHeaderExtra X-Real-IP\n", RewriteNone, ""},
		{"similar rpaf directive", "RPAF_EnableExtra On\n", RewriteNone, ""},
		{"mixed case rpaf enable", "<VirtualHost *:443>\nrPaF_eNaBlE oN\n</VirtualHost>\n", RewriteActive, "rPaF_eNaBlE oN"},
		{"old rpaf disabled", "rPaFeNaBlE oFf\n", RewriteNone, ""},
		{"quoted rpaf disabled", "RPAF_Enable 'Off'\n", RewriteNone, ""},
		{"empty rpaf enable", "RPAF_Enable ''\n", RewriteUnknown, ""},
		{"unresolved rpaf enable", "RPAFenable ${enabled}\n", RewriteUnknown, ""},
		{"invalid rpaf disable", "RPAF_Enable Off extra\n", RewriteUnknown, ""},
		{"invalid cloudflare proxy address", "CloudFlareRemoteIPTrustedProxy 192.0.2.999\n", RewriteUnknown, ""},
		{"invalid cloudflare proxy mask", "CloudFlareRemoteIPTrustedProxy 192.0.2.0/33\n", RewriteUnknown, ""},
		{"invalid cloudflare ipv6 mask", "CloudFlareRemoteIPTrustedProxy 2001:db8::/129\n", RewriteUnknown, ""},
		{"zero cloudflare prefix", "CloudFlareRemoteIPTrustedProxy 192.0.2.0/0\n", RewriteUnknown, ""},
		{"empty cloudflare mask", "CloudFlareRemoteIPTrustedProxy 192.0.2.0/\n", RewriteUnknown, ""},
		{"mapped cloudflare proxy", "CloudFlareRemoteIPTrustedProxy ::ffff:192.0.2.1\n", RewriteUnknown, ""},
		{"scoped cloudflare proxy", "CloudFlareRemoteIPTrustedProxy 2001:db8::1%eth0\n", RewriteUnknown, ""},
		{"invalid second cloudflare proxy", "CloudFlareRemoteIPTrustedProxy 192.0.2.1 2001:db8::bad::1\n", RewriteUnknown, ""},
		{"unresolved cloudflare proxy", "CloudFlareRemoteIPTrustedProxy ${proxy}\n", RewriteUnknown, ""},
		{"cloudflare proxy needs dns", "CloudFlareRemoteIPTrustedProxy proxy.invalid\n", RewriteUnknown, ""},
		{"cloudflare hostname with mask", "CloudFlareRemoteIPTrustedProxy proxy.example/24\n", RewriteUnknown, ""},
		{"cloudflare ipv6 proxy", "CloudFlareRemoteIPTrustedProxy 2001:db8::/32\n", RewriteActive, "CloudFlareRemoteIPTrustedProxy 2001:db8::/32"},
		{"cloudflare dotted mask", "CloudFlareRemoteIPTrustedProxy 192.0.2.0/255.255.255.0\n", RewriteActive, "CloudFlareRemoteIPTrustedProxy 192.0.2.0/255.255.255.0"},
		{"cloudflare legacy network", "CloudFlareRemoteIPTrustedProxy 192.0.2.\n", RewriteActive, "CloudFlareRemoteIPTrustedProxy 192.0.2."},
		{"cloudflare quoted positive mask", "CloudFlareRemoteIPTrustedProxy '192.0.2.0/ +24'\n", RewriteActive, "CloudFlareRemoteIPTrustedProxy 192.0.2.0/ +24"},
		{"cloudflare proxy list terminator", "CloudFlareRemoteIPTrustedProxy 192.0.2.1 '' ignored\n", RewriteActive, "CloudFlareRemoteIPTrustedProxy 192.0.2.1  ignored"},
		{"cloudflare missing legacy octet", "CloudFlareRemoteIPTrustedProxy 192..2\n", RewriteUnknown, ""},
		{"cloudflare too many octets", "CloudFlareRemoteIPTrustedProxy 192.0.2.1.2\n", RewriteUnknown, ""},
		{"cloudflare oversized octet", "CloudFlareRemoteIPTrustedProxy 192.0000000000000.2\n", RewriteUnknown, ""},
		{"cloudflare masked legacy network", "CloudFlareRemoteIPTrustedProxy 192.0.2/24\n", RewriteUnknown, ""},
		{"cloudflare ipv6 dotted mask", "CloudFlareRemoteIPTrustedProxy 2001:db8::/255.255.255.0\n", RewriteUnknown, ""},
		{"cloudflare noncontiguous dotted mask", "CloudFlareRemoteIPTrustedProxy 192.0.2.0/255.0.255.0\n", RewriteActive, "CloudFlareRemoteIPTrustedProxy 192.0.2.0/255.0.255.0"},
		{"cloudflare leading zero legacy network", "CloudFlareRemoteIPTrustedProxy 192.000.002\n", RewriteActive, "CloudFlareRemoteIPTrustedProxy 192.000.002"},
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
	for _, tc := range []struct {
		body      string
		state     RewriteState
		directive string
	}{
		{"LoadModule cloudflare_module modules/mod_cloudflare.so", RewriteActive, "LoadModule cloudflare_module modules/mod_cloudflare.so"},
		{"DenyAllButCloudFlare", RewriteActive, "DenyAllButCloudFlare"},
		{"RPAF_Enable On", RewriteActive, "RPAF_Enable On"},
		{"RPAFenable On", RewriteActive, "RPAFenable On"},
		{"LoadModule rpaf_module modules/mod_rpaf.so\nRPAF_Enable Off", RewriteNone, ""},
		{"LoadModule rpaf_module", RewriteUnknown, ""},
		{"CloudFlareRemoteIPTrustedProxy 192.0.2.999", RewriteUnknown, ""},
	} {
		t.Run(tc.body, func(t *testing.T) {
			root := t.TempDir()
			writeRewriteFile(t, root, platform.LiteSpeedConfigPath, "<httpServerConfig><useIpInProxyHeader>0</useIpInProxyHeader></httpServerConfig>")
			writeRewriteFile(t, root, "/etc/apache2/conf/httpd.conf", "Include /etc/apache2/conf/modules.conf\n")
			const modules = "/etc/apache2/conf/modules.conf"
			writeRewriteFile(t, root, modules, tc.body+"\n")
			prev := osFS
			SetOS(rootedOS{OS: prev, root: root})
			t.Cleanup(func() { SetOS(prev) })
			file := ""
			if tc.state == RewriteActive {
				file = modules
			}
			requireRewrite(t, DetectHTTPRewrite(platform.Info{Panel: platform.PanelCPanel, WebServer: platform.WSLiteSpeed}),
				tc.state, tc.directive, file)
		})
	}
}

func TestHTTPRewriteApacheLegacyModulesPreserveActiveBesideErrors(t *testing.T) {
	for _, active := range []string{"DenyAllButCloudFlare", "RPAF_Enable On", "RPAFenable On"} {
		for _, broken := range []string{"LoadModule rpaf_module", "CloudFlareRemoteIPTrustedProxy 192.0.2.999", "RPAF_Enable Maybe"} {
			for _, body := range []string{broken + "\n" + active + "\n", active + "\n" + broken + "\n"} {
				t.Run(body, func(t *testing.T) {
					conf := writeRewriteFile(t, t.TempDir(), "httpd.conf", body)
					requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSApache, apacheConfig: conf}),
						RewriteActive, active, conf)
				})
			}
		}
	}
}
