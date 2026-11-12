package checks

import (
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/platform"
)

func TestHTTPRewriteApacheFormatFallbacks(t *testing.T) {
	cases := []struct {
		name, body string
		state      RewriteState
	}{
		{
			"inline format shadowed in another virtual host",
			"CustomLog logs/access \"%{X-Client}i %t\"\n<VirtualHost *:80>\nLogFormat \"%h %t\" \"%{X-Client}i %t\"\n</VirtualHost>\n",
			RewriteActive,
		},
		{
			"default inline format shadowed in another virtual host",
			"LogFormat \"%{X-Client}i %t\"\nTransferLog logs/access\n<VirtualHost *:80>\nLogFormat \"%h %t\" \"%{X-Client}i %t\"\n</VirtualHost>\n",
			RewriteActive,
		},
		{
			"virtual host default does not replace main common format",
			"TransferLog \"|splitlogs\"\n<VirtualHost *:80>\nLogFormat \"%v %a %t\"\n</VirtualHost>\n",
			RewriteActive,
		},
		{
			"conditional default does not replace common format",
			"<IfModule absent_module>\nLogFormat \"%v %a %t\"\n</IfModule>\nTransferLog \"|splitlogs\"\n",
			RewriteActive,
		},
		{
			"unconditional main default is inherited",
			"LogFormat \"%v %a %t\"\n<VirtualHost *:80>\nTransferLog \"|splitlogs\"\n</VirtualHost>\n",
			RewriteNone,
		},
		{
			"virtual host uses its own default",
			"<VirtualHost *:80>\nLogFormat \"%v %a %t\"\nTransferLog \"|splitlogs\"\n</VirtualHost>\n",
			RewriteNone,
		},
		{
			"nickname defined in the same scope replaces inline format",
			"<VirtualHost *:80>\nLogFormat \"%h %t\" \"%{X-Client}i %t\"\nCustomLog logs/access \"%{X-Client}i %t\"\n</VirtualHost>\n",
			RewriteNone,
		},
		{
			"conditional log uses the default in its own condition",
			"<IfModule log_config_module>\nLogFormat \"%v %a %t\"\nTransferLog \"|splitlogs\"\n</IfModule>\n",
			RewriteNone,
		},
		{
			"conditional nickname replaces inline format in nested condition",
			"<IfModule log_config_module>\nLogFormat \"%h %t\" \"%{X-Client}i %t\"\n<IfDefine LOGGING>\nCustomLog logs/access \"%{X-Client}i %t\"\n</IfDefine>\n</IfModule>\n",
			RewriteNone,
		},
		{
			"nickname does not hide invalid inline syntax",
			"LogFormat \"%h %t\" \"%Q\"\nCustomLog logs/access \"%Q\"\n",
			RewriteUnknown,
		},
		{
			"invalid logging condition",
			"CustomLog logs/access \"%h %t\" invalid\n",
			RewriteUnknown,
		},
		{
			"empty logging environment condition",
			"CustomLog logs/access \"%h %t\" env=!\n",
			RewriteUnknown,
		},
		{
			"missing logging environment name",
			"CustomLog logs/access \"%h %t\" env=\n",
			RewriteUnknown,
		},
		{
			"empty logging expression",
			"CustomLog logs/access \"%h %t\" expr=\n",
			RewriteUnknown,
		},
		{
			"blank logging expression",
			"CustomLog logs/access \"%h %t\" \"expr= \t \"\n",
			RewriteUnknown,
		},
		{
			"logging expression",
			"LogFormat \"%h %l %u %t \\\"%r\\\" %>s %b\" common\nCustomLog logs/access common \"expr=%{REQUEST_URI} !~ m#^/health#\"\n",
			RewriteNone,
		},
		{
			"logging expression keeps the format",
			"CustomLog logs/access \"%{X-Client}i %t\" \"expr=%{REQUEST_URI} !~ m#^/health#\"\n",
			RewriteActive,
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			conf := writeRewriteFile(t, t.TempDir(), "httpd.conf", tt.body)
			for _, server := range []platform.WebServer{platform.WSApache, platform.WSLiteSpeed} {
				got := detectHTTPRewrite(rewriteSources{server: server, apacheConfig: conf})
				if got.State != tt.state {
					t.Errorf("server %s: rewrite = %+v, want %v", server, got, tt.state)
				}
			}
		})
	}
}

func TestHTTPRewriteLiteSpeedFormatDialect(t *testing.T) {
	cases := []struct {
		name, format string
		state        RewriteState
	}{
		{"escaped leading space", `\ %{X-Client}i %t`, RewriteUnknown},
		{"escaped opening bracket", `\[%{X-Client}i] %t`, RewriteUnknown},
		{"request variable in time item", `%{SERVER_NAME}t %t`, RewriteUnknown},
		{"request variable in virtual host item", `%{REMOTE_USER}v %t`, RewriteUnknown},
		{"empty custom time item", `%{}t %{X-Client}i %t`, RewriteUnknown},
		{"unsupported status modifier", `%200h %{X-Client}i %t`, RewriteUnknown},
		{"unsupported item before header", `%L %{X-Client}i %t`, RewriteUnknown},
		{"ordinary header first", `%{X-Client}i %t`, RewriteActive},
		{"ordinary direct format", `%h %l %u %t "%r" %>s %b`, RewriteNone},
		{"ordinary time format", `%{%Y-%m-%d}t %{X-Client}i`, RewriteNone},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			for _, apache := range []bool{false, true} {
				src := rewriteSources{server: platform.WSLiteSpeed}
				if apache {
					format := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(tt.format)
					src.apacheConfig = writeRewriteFile(t, t.TempDir(), "httpd.conf", "CustomLog logs/access \""+format+"\"\n")
				} else {
					format := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(tt.format)
					xml := "<httpServerConfig><logFormat>" + format + "</logFormat></httpServerConfig>"
					src.lswsConfig = writeRewriteFile(t, t.TempDir(), "httpd_config.xml", xml)
				}
				got := detectHTTPRewrite(src)
				if got.State != tt.state {
					t.Errorf("Apache configuration=%v: rewrite = %+v, want %v", apache, got, tt.state)
				}
			}
		})
	}
}

func TestHTTPRewriteSplitlogsLeadingWhitespace(t *testing.T) {
	for _, prefix := range []string{" ", "   ", `\t `, "%v %h %t\\n "} {
		format := prefix + `%v %{X-Client}i %t`
		conf := writeRewriteFile(t, t.TempDir(), "httpd.conf", "CustomLog \"|splitlogs\" \""+format+"\"\n")
		got := detectHTTPRewrite(rewriteSources{server: platform.WSApache, apacheConfig: conf})
		if got.State != RewriteActive {
			t.Errorf("format %q: rewrite = %+v, want active", format, got)
		}
	}
}

func TestHTTPRewriteStockAccessFormats(t *testing.T) {
	debian := `LogFormat "%h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" combined
LogFormat "%{Referer}i -> %U" referer
LogFormat "%{User-agent}i" agent
<VirtualHost *:80>
CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
`
	for _, server := range []platform.WebServer{platform.WSApache, platform.WSLiteSpeed} {
		for _, body := range []string{cpanelLogConfig, debian} {
			conf := writeRewriteFile(t, t.TempDir(), "httpd.conf", body)
			got := detectHTTPRewrite(rewriteSources{server: server, apacheConfig: conf})
			if got.State != RewriteNone {
				t.Errorf("server %s: stock logging = %+v, want direct", server, got)
			}
		}
	}
}

// mod_macro substitutes its parameters before Apache parses a line, so a
// parameter can supply any format, nickname, symbol or directive name.
func TestHTTPRewriteApacheMacroParameters(t *testing.T) {
	combined := "LogFormat \"%h %l %u %t \\\"%r\\\" %>s %b \\\"%{Referer}i\\\" \\\"%{User-Agent}i\\\"\" combined\n"
	cases := []struct {
		name, body string
		state      RewriteState
	}{
		{"format parameter", "<Macro Logged $fmt>\nCustomLog logs/access_log \"$fmt\"\n</Macro>\nUse Logged \"%{X-Forwarded-For}i %t\"\n", RewriteUnknown},
		{"nickname parameter", "LogFormat \"%{X-Client}i %t\" proxied\n<Macro V $name>\nCustomLog logs/x $name\n</Macro>\nUse V proxied\n", RewriteUnknown},
		{"module parameter", "<Macro M $sym>\nLoadModule $sym modules/mod_x.so\n</Macro>\nUse M cloudflare_module\n", RewriteUnknown},
		{"directive parameter", "<Macro D $directive>\n$directive X-Forwarded-For\n</Macro>\nUse D RemoteIPHeader\n", RewriteUnknown},
		{"servername directive parameter", "<Macro D ServerName>\nServerName X-Forwarded-For\n</Macro>\nUse D RemoteIPHeader\n", RewriteUnknown},
		{"servername directive substring parameter", "<Macro D Server>\nServerName X-Forwarded-For\n</Macro>\nUse D RemoteIP\n", RewriteUnknown},
		{"pipe parameter", "<Macro P $pipe>\nCustomLog \"|$pipe\" \"%v %{X-Client}i %t\"\n</Macro>\nUse P /usr/bin/logger\n", RewriteUnknown},
		{"longest target parameter first", "<Macro P $dir $dir/access>\nCustomLog $dir/access \"%h %t\"\n</Macro>\nUse P /var/log \"|splitlogs\"\n", RewriteUnknown},
		{"percent parameter", "<macro P %fmt>\nCustomLog logs/x \"%fmt\"\n</macro>\n", RewriteUnknown},
		{"macro name contains spaces", combined + "<Macro \"Logging combined\" $path>\nCustomLog \"/var/log/$path\" combined\n</Macro>\nUse \"Logging combined\" access\n", RewriteNone},
		{"quoted parameter preserves spaces", combined + "<Macro Logging \"$path combined\">\nCustomLog logs/access combined\n</Macro>\nUse Logging unused\n", RewriteNone},
		{"macro inside virtual host", "<VirtualHost *:80>\n<Macro Logged $fmt>\nCustomLog logs/access_log \"$fmt\"\n</Macro>\nUse Logged \"%{X-Client}i %t\"\n</VirtualHost>\n", RewriteUnknown},
		{"log file parameter", combined + "<Macro VHost $name $domain>\n<VirtualHost *:80>\nServerName $domain\nCustomLog \"/var/log/httpd/$name.access_log\" combined\n</VirtualHost>\n</Macro>\nUse VHost example example.com\n", RewriteNone},
		{"literal macro body", "<Macro Plain $x>\nCustomLog logs/x \"%{X-Client}i %t\"\n</Macro>\n", RewriteActive},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			conf := writeRewriteFile(t, t.TempDir(), "httpd.conf", tt.body)
			for _, server := range []platform.WebServer{platform.WSApache, platform.WSLiteSpeed} {
				got := detectHTTPRewrite(rewriteSources{server: server, apacheConfig: conf})
				if got.State != tt.state {
					t.Errorf("server %s: rewrite = %+v, want %v", server, got, tt.state)
				}
			}
		})
	}
}

// With HostnameLookups On, %h logs the name the client's own reverse DNS
// returns, unverified, and that name can spell another address. Double
// logs the address when the forward check fails.
func TestHTTPRewriteApacheHostnameLookups(t *testing.T) {
	common := "LogFormat \"%h %l %u %t \\\"%r\\\" %>s %b\" common\nCustomLog logs/access_log common\n"
	cases := []struct {
		name, body string
		state      RewriteState
	}{
		{"lookups on", "HostnameLookups On\n" + common, RewriteActive},
		{"lookups on after format use", common + "HostnameLookups On\n", RewriteActive},
		{"directory lookups survive later off", "<Directory /var/www/html>\nHostnameLookups On\n</Directory>\nHostnameLookups Off\n" + common, RewriteActive},
		{"lookups on in a virtual host", "<VirtualHost *:80>\nhostnamelookups on\n</VirtualHost>\nCustomLog logs/access_log \"%{c}h %t\"\n", RewriteActive},
		{"lookups on behind splitlogs", "HostnameLookups On\nCustomLog \"|/usr/local/cpanel/bin/splitlogs --main=x\" \"%v %h %t\"\n", RewriteActive},
		{"lookups on after the read field", "HostnameLookups On\nCustomLog logs/access_log \"%a %h %t\"\n", RewriteNone},
		{"lookups double", "HostnameLookups Double\n" + common, RewriteNone},
		{"lookups off", "HostnameLookups off\n" + common, RewriteNone},
		{"invalid lookups", "HostnameLookups Maybe\n" + common, RewriteUnknown},
		{"bare lookups", "HostnameLookups\n" + common, RewriteUnknown},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			conf := writeRewriteFile(t, t.TempDir(), "httpd.conf", tt.body)
			for _, server := range []platform.WebServer{platform.WSApache, platform.WSLiteSpeed} {
				got := detectHTTPRewrite(rewriteSources{server: server, apacheConfig: conf})
				if got.State != tt.state {
					t.Errorf("server %s: rewrite = %+v, want %v", server, got, tt.state)
				}
			}
		})
	}
}
