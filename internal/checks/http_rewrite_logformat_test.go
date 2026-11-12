package checks

import (
	"testing"

	"github.com/pidginhost/csm/internal/clientaddr"
	"github.com/pidginhost/csm/internal/platform"
)

// cpanelLogConfig is the shape of cPanel's stock Apache logging: unused
// header-first formats, and splitlogs pipes that strip the virtual host.
const cpanelLogConfig = `LogFormat "%v:%{local}p %a %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"" combined
LogFormat "%v:%{local}p %a %l %u %t \"%r\" %>s %b" common
LogFormat "%{Referer}i -> %U" referer
LogFormat "%{User-agent}i" agent
LogFormat "%v %{%s}t %I .\n%v %{%s}t %O ." bytesvhost
LogFormat "apache-traffic.log %{%F}t %H %{SSL_PROTOCOL}x %{Host}i %I %O %{c}a %a" trafficlog
CustomLog "|/usr/local/cpanel/bin/splitlogs --dir=/etc/apache2/logs/domlogs --main=server.example.net --suffix=-bytes_log" bytesvhost env=!isproxyrequest
CustomLog "|/usr/local/cpanel/bin/splitlogs --main=apache-traffic.log --mainout=/var/log/cpanel-server-traffic/web/traffic-apache.log" trafficlog env=!isproxyrequest
CustomLog "|/usr/local/cpanel/bin/splitlogs --dir=/etc/apache2/logs/domlogs --main=server.example.net --mainout=/etc/apache2/logs/access_log" combined env=!isproxyrequest
`

// An Apache log format that writes a value the request chooses where CSM
// reads the client logs a client-chosen address. CSM reads the first field
// of an access line, or the second after splitlogs strips the virtual
// host, and the error-log text before the message. Only formats a log
// uses count; every definition of a nickname counts, in any scope.
func TestHTTPRewriteApacheLogFormats(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name, body string
		state      RewriteState
		directive  string
	}{
		{"cPanel stock logging", cpanelLogConfig, RewriteNone, ""},
		{"unresolved format text", "Define client_format \"%{X-Client}i %t\"\nLogFormat \"${client_format}\" proxy\nCustomLog logs/access proxy\n", RewriteUnknown, ""},
		{"unresolved inline format", "Define client_format \"%{X-Client}i %t\"\nCustomLog logs/access \"${client_format}\"\n", RewriteUnknown, ""},
		{"unresolved nickname", "Define format_name proxy\nLogFormat \"%{X-Client}i %t\" ${format_name}\nCustomLog logs/access proxy\n", RewriteUnknown, ""},
		{"unresolved pipe target", "Define log_target \"|splitlogs\"\nCustomLog \"${log_target}\" \"%v %{X-Client}i %t\"\n", RewriteUnknown, ""},
		{"unresolved error prefix", "Define error_prefix \"[client %{X-Client}i]\"\nErrorLogFormat \"${error_prefix} %M\"\n", RewriteUnknown, ""},
		{"unresolved canonical name", "Define canonical_name \"\"\nServerName \"${canonical_name}:80\"\nCustomLog logs/access \"%v %{X-Client}i %t\"\n", RewriteUnknown, ""},
		{"log directory variable", "LogFormat \"%h %l %u %t\" combined\nCustomLog ${APACHE_LOG_DIR}/access.log combined\n", RewriteNone, ""},
		{"variable in log file name", "CustomLog logs/${site}_access_log \"%h %t\"\n", RewriteNone, ""},
		{"unresolved pipe command", "CustomLog \"|${splitter} --main=x\" \"%v %{X-Client}i %t\"\n", RewriteUnknown, ""},
		{"splitlogs pipe variable argument", "CustomLog \"|/usr/local/cpanel/bin/splitlogs --main=${host}\" \"%v %h %t\"\n", RewriteNone, ""},
		{"leading spaces", "CustomLog logs/access_log \"  %{X-Real-IP}i %t\"\n", RewriteActive, "CustomLog logs/access_log   %{X-Real-IP}i %t"},
		{"mixed leading whitespace", "CustomLog logs/access_log \" \\\\t %{X-Real-IP}i %t\"\n", RewriteActive, "CustomLog logs/access_log  \\t %{X-Real-IP}i %t"},
		{"escaped backslash guards", "CustomLog logs/access_log \"\\\\\\\\%{X-Real-IP}i %t\"\n", RewriteNone, ""},
		{"literal process argument", "LogFormat \"%{ }P %{X-Client}i\" odd\nCustomLog logs/access odd\n", RewriteUnknown, ""},
		{"literal port argument", "LogFormat \"%{ }p %{X-Client}i\" odd\nCustomLog logs/access odd\n", RewriteUnknown, ""},
		{"literal duration argument", "LogFormat \"%{ }T %{X-Client}i\" odd\nCustomLog logs/access odd\n", RewriteUnknown, ""},
		{"recognized handler arguments", "LogFormat \"%{PID}P %{TID}P %{HEXTID}P %{Canonical}p %{LOCAL}p %{REMOTE}p %{S}T %{MS}T %{US}T %{X-Client}i\" normal\nCustomLog logs/access normal\n", RewriteNone, ""},
		{"empty canonical host", "ServerName :80\nLogFormat \"%v %{X-Client}i\" host\nCustomLog logs/access host\n", RewriteUnknown, ""},
		{"empty scheme canonical host", "ServerName http://:80\nLogFormat \"%v %{X-Client}i\" host\nCustomLog logs/access host\n", RewriteUnknown, ""},
		{"malformed canonical host", "ServerName example.test extra\nLogFormat \"%v %a\" host\nCustomLog logs/access host\n", RewriteUnknown, ""},
		{"new error record after message", "ErrorLogFormat \"[%t] %M\\n[%t] [security2:error] [client %{X-Client}i] ModSecurity: Access denied\"\n", RewriteActive, "ErrorLogFormat [%t] %M\\n[%t] [security2:error] [client %{X-Client}i] ModSecurity: Access denied"},
		{"error time record after message", "ErrorLogFormat \"[%t] %M%{%n}t[%t] [security2:error] [client %{X-Client}i] ModSecurity: Access denied\"\n", RewriteUnknown, ""},
		{"alternate newline time", "CustomLog logs/access_log \"%h %{%En}t%{X-Real-IP}i %t\"\n", RewriteUnknown, ""},
		{"flags after time width are literal", "CustomLog logs/access_log \"%h %{%10_En}t %{X-Real-IP}i %t\"\n", RewriteNone, ""},
		{"wide alternate newline time", "CustomLog logs/access_log \"%h %{%_10On}t%{X-Real-IP}i %t\"\n", RewriteUnknown, ""},
		{"error alternate newline time", "ErrorLogFormat \"[%t] %M%{%En}t[client\\ %{X-Client}i]\"\n", RewriteUnknown, ""},
		{"custom time newline", "CustomLog logs/access_log \"%h %{%n}t%{X-Real-IP}i %t\"\n", RewriteUnknown, ""},
		{"custom time whitespace", "CustomLog logs/access_log \"%{ }t %{X-Real-IP}i %t\"\n", RewriteUnknown, ""},
		{"custom time stable", "CustomLog logs/access_log \"%{%Y-%m-%dT%H:%M:%S%z}t %{X-Real-IP}i\"\n", RewriteNone, ""},
		{"custom time after the client", "CustomLog logs/access_log \"%h %l %u [%{%d/%b/%Y %T}t.%{msec_frac}t %{%z}t] \\\"%r\\\"\"\n", RewriteNone, ""},
		{"padded newline time", "CustomLog logs/access_log \"%h %{%_n}t%{X-Real-IP}i %t\"\n", RewriteUnknown, ""},
		{"unproven time first", "CustomLog logs/access_log \"%{%Z}t%{X-Real-IP}i %t\"\n", RewriteUnknown, ""},
		{"literal percent before n", "CustomLog logs/access_log \"%h %{%%n}t %t\"\n", RewriteNone, ""},
		{"literal argument after the client", "CustomLog logs/access_log \"%h %{ }p %t\"\n", RewriteNone, ""},
		{"error custom time", "ErrorLogFormat \"[%{%Y-%m-%d %H:%M:%S}t] [client\\ %a] %M\"\n", RewriteNone, ""},
		{"unknown handler after peer", "CustomLog logs/access_log \"%h %Q\"\n", RewriteUnknown, ""},
		{"unknown extended handler", "CustomLog logs/access_log \"%h %^zz\"\n", RewriteUnknown, ""},
		{"nickname folds case", "LogFormat \"%{X-Real-IP}i %t\" Mixed\nCustomLog logs/access_log MIXED\n", RewriteActive, "LogFormat %{X-Real-IP}i %t Mixed"},
		{"default nickname folds case", "LogFormat \"%{X-Real-IP}i %t\" Mixed\nLogFormat MIXED\nTransferLog logs/access_log\n", RewriteActive, "LogFormat %{X-Real-IP}i %t Mixed"},
		{"spaces after stripped field", "CustomLog \"|splitlogs\" \"%v   %{X-Real-IP}i %t\"\n", RewriteActive, "CustomLog |splitlogs %v   %{X-Real-IP}i %t"},
		{"builtin common nickname", "CustomLog logs/access CLF\n", RewriteNone, ""},
		{"stripped builtin common nickname", "CustomLog \"|splitlogs\" cLf\n", RewriteActive, "CustomLog |splitlogs cLf"},
		{"default builtin common nickname", "LogFormat clf\nTransferLog \"|splitlogs\"\n", RewriteActive, "LogFormat clf"},
		{"builtin common across scopes", "LogFormat \"%v %a %t\" CLF\n<VirtualHost *:80>\nCustomLog \"|splitlogs\" CLF\n</VirtualHost>\n", RewriteActive, "CustomLog |splitlogs CLF"},
		{"splitlogs common default", "TransferLog \"|splitlogs\"\n", RewriteActive, "TransferLog |splitlogs"},
		{"escaped message marker", "ErrorLogFormat \"\\\\%M [client\\\\ %{X-Real-IP}i] %M\"\n", RewriteActive, "ErrorLogFormat \\%M [client\\ %{X-Real-IP}i] %M"},
		{"erased error message", "ErrorLogFormat \"[%t] %M%{X-Missing}i% [client\\ %{X-Client}i]\\ ModSecurity:\\ Access\\ denied\"\n", RewriteActive, `ErrorLogFormat [%t] %M%{X-Missing}i% [client\ %{X-Client}i]\ ModSecurity:\ Access\ denied`},
		{"message in skipped field", "ErrorLogFormat \"[%t] %E%M% %{X-Also-Missing}i% [client\\ %{X-Client}i]\\ ModSecurity:\\ Access\\ denied\"\n", RewriteActive, `ErrorLogFormat [%t] %E%M% %{X-Also-Missing}i% [client\ %{X-Client}i]\ ModSecurity:\ Access\ denied`},
		{"escaped space keeps message field", "ErrorLogFormat \"[%t] %M\\ %{X-Missing}i% [client\\ %{X-Client}i]\\ ModSecurity:\\ Access\\ denied\"\n", RewriteActive, `ErrorLogFormat [%t] %M\ %{X-Missing}i% [client\ %{X-Client}i]\ ModSecurity:\ Access\ denied`},
		{"tab keeps message field", "ErrorLogFormat \"[%t] %M\\t%{X-Missing}i% [client\\ %{X-Client}i]\\ ModSecurity:\\ Access\\ denied\"\n", RewriteActive, `ErrorLogFormat [%t] %M\t%{X-Missing}i% [client\ %{X-Client}i]\ ModSecurity:\ Access\ denied`},
		{"explicit message field boundary", "ErrorLogFormat \"[%t] %M% [client\\ %{X-Client}i]\"\n", RewriteNone, ""},
		{"ordinary message field boundary", "ErrorLogFormat \"[%t] %M [client\\ %{X-Client}i]\"\n", RewriteNone, ""},
		{"literal percent in message field", "ErrorLogFormat \"[%t] %M%% [client\\ %{X-Client}i]\"\n", RewriteNone, ""},
		{"conditional message marker", "ErrorLogFormat \"%1M [client\\\\ %{X-Real-IP}i] %M\"\n", RewriteActive, "ErrorLogFormat %1M [client\\ %{X-Real-IP}i] %M"},
		{"missing error message", "ErrorLogFormat \"[client %a]\"\n", RewriteUnknown, ""},
		{"required main error item", "ErrorLogFormat \"%+a %M\"\n", RewriteUnknown, ""},
		{"huge error level", "ErrorLogFormat \"%18446744073709551616a %M\"\n", RewriteUnknown, ""},
		{"out of range error level", "ErrorLogFormat \"%16a %M\"\n", RewriteUnknown, ""},
		{"unknown error handler", "ErrorLogFormat \"[client %a] %Q %M\"\n", RewriteUnknown, ""},
		{"scoped message is invalid", "ErrorLogFormat request \"%M\"\n", RewriteUnknown, ""},
		{"scoped level is invalid", "ErrorLogFormat connection \"%1a\"\n", RewriteUnknown, ""},
		{"scoped required header", "ErrorLogFormat request \"%+{X-Real-IP}i\"\n", RewriteActive, "ErrorLogFormat request %+{X-Real-IP}i"},
		{"header first", "LogFormat \"%{X-Forwarded-For}i %l %u %t \\\"%r\\\" %>s %b\" proxy\nCustomLog logs/access_log proxy\n", RewriteActive, `LogFormat %{X-Forwarded-For}i %l %u %t "%r" %>s %b proxy`},
		{"unused header format", "LogFormat \"%{X-Forwarded-For}i %t\" proxy\nLogFormat \"%h %t\" plain\nCustomLog logs/access_log plain\n", RewriteNone, ""},
		{"inline header format", "CustomLog logs/access_log \"%{X-Real-IP}i %t \\\"%r\\\"\"\n", RewriteActive, `CustomLog logs/access_log %{X-Real-IP}i %t "%r"`},
		{"header after the address", "CustomLog logs/access_log \"%h %{X-Forwarded-For}i %t\"\n", RewriteNone, ""},
		{"connection peer", "CustomLog logs/access_log \"%>{c}h:%<{c}a %t\"\n", RewriteNone, ""},
		{"cookie first", "CustomLog logs/access_log \"%{ip}C %t\"\n", RewriteActive, "CustomLog logs/access_log %{ip}C %t"},
		{"environment first", "CustomLog logs/access_log \"%{CLIENT}e %t\"\n", RewriteActive, "CustomLog logs/access_log %{CLIENT}e %t"},
		{"user first", "CustomLog logs/access_log \"%u %h %t\"\n", RewriteActive, "CustomLog logs/access_log %u %h %t"},
		{"request host first", "CustomLog logs/access_log \"%V %h %t\"\n", RewriteActive, "CustomLog logs/access_log %V %h %t"},
		{"header glued to the address", "CustomLog logs/access_log \"%h,%{X-Forwarded-For}i %t\"\n", RewriteActive, "CustomLog logs/access_log %h,%{X-Forwarded-For}i %t"},
		{"conditional header", "CustomLog logs/access_log \"%!200,304{X-Forwarded-For}i %t\"\n", RewriteActive, "CustomLog logs/access_log %!200,304{X-Forwarded-For}i %t"},
		{"trailer first", "CustomLog logs/access_log \"%{X-Client}^ti %t\"\n", RewriteActive, "CustomLog logs/access_log %{X-Client}^ti %t"},
		{"second line", "CustomLog logs/access_log \"%h %t\\n%{X-Forwarded-For}i %t\"\n", RewriteActive, `CustomLog logs/access_log %h %t\n%{X-Forwarded-For}i %t`},
		{"bracketed IPv6 header", "CustomLog logs/access_log \"[%{X-Real-IP}i] %t\"\n", RewriteActive, "CustomLog logs/access_log [%{X-Real-IP}i] %t"},
		{"bracketed IPv6 header with port", "CustomLog logs/access_log \"[%{X-Real-IP}i]:443 %t\"\n", RewriteActive, "CustomLog logs/access_log [%{X-Real-IP}i]:443 %t"},
		{"quoted header first", "CustomLog logs/access_log \"\\\"%{X-Forwarded-For}i\\\" %t\"\n", RewriteNone, ""},
		{"header after a prefix", "CustomLog logs/access_log \"ip=%{X-Forwarded-For}i %t\"\n", RewriteNone, ""},
		{"header after a hex prefix", "CustomLog logs/access_log \"f%{X-Forwarded-For}i %t\"\n", RewriteActive, "CustomLog logs/access_log f%{X-Forwarded-For}i %t"},
		{"tab before the header", "CustomLog logs/access_log \"\\t%{X-Forwarded-For}i %t\"\n", RewriteActive, `CustomLog logs/access_log \t%{X-Forwarded-For}i %t`},
		{"header before a suffix", "CustomLog logs/access_log \"%{X-Forwarded-For}i] %t\"\n", RewriteActive, "CustomLog logs/access_log %{X-Forwarded-For}i] %t"},
		{"virtual host first", "CustomLog logs/access_log \"%v:%p %{X-Forwarded-For}i %t\"\n", RewriteNone, ""},
		{"virtual host stripped", "LogFormat \"%v:%p %{X-Forwarded-For}i %t\" vhost\nCustomLog \"||/usr/local/cpanel/bin/splitlogs --main=server.example.net\" vhost\n", RewriteActive, "LogFormat %v:%p %{X-Forwarded-For}i %t vhost"},
		{"stripped field shifts", "LogFormat \"[%{X-Forwarded-For}i] %h %t\" vhost\nCustomLog \"|splitlogs --main=server.example.net\" vhost\n", RewriteActive, "LogFormat [%{X-Forwarded-For}i] %h %t vhost"},
		{"quoted after the stripped field", "LogFormat \"%v \\\"%{X-Forwarded-For}i\\\" %t\" vhost\nCustomLog \"|$ splitlogs --main=server.example.net\" vhost\n", RewriteNone, ""},
		{"wrapped splitlogs", "LogFormat \"%v %{X-Forwarded-For}i %t\" vhost\nCustomLog \"|exec /usr/local/cpanel/bin/splitlogs --main=server.example.net\" vhost\n", RewriteActive, "LogFormat %v %{X-Forwarded-For}i %t vhost"},
		{"other pipe keeps the first field", "CustomLog \"|/usr/bin/rotatelogs /var/log/httpd/access_log 86400\" \"%v %{X-Forwarded-For}i %t\"\n", RewriteNone, ""},
		{"default format", "LogFormat \"%{X-Forwarded-For}i %t\"\nTransferLog logs/access_log\n", RewriteActive, "LogFormat %{X-Forwarded-For}i %t"},
		{"default nickname", "LogFormat \"%{X-Forwarded-For}i %t\" proxy\nLogFormat proxy\nTransferLog logs/access_log\n", RewriteActive, "LogFormat %{X-Forwarded-For}i %t proxy"},
		{"unused default format", "LogFormat \"%{X-Forwarded-For}i %t\"\nCustomLog logs/access_log \"%h %t\"\n", RewriteNone, ""},
		{"common log format", "TransferLog logs/access_log\n", RewriteNone, ""},
		{"global log", "GlobalLog logs/access_log \"%{X-Forwarded-For}i %t\"\n", RewriteActive, "GlobalLog logs/access_log %{X-Forwarded-For}i %t"},
		{"any definition counts", "LogFormat \"%h %t\" main\n<VirtualHost *:80>\n  LogFormat \"%{X-Forwarded-For}i %t\" main\n</VirtualHost>\nCustomLog logs/access_log main\n", RewriteActive, "LogFormat %{X-Forwarded-For}i %t main"},
		{"error request note", "ErrorLogFormat \"[client %{CLIENT}n] %M\"\n", RewriteActive, "ErrorLogFormat [client %{CLIENT}n] %M"},
		{"error client header", "ErrorLogFormat \"[%t] [%l] [client\\ %{X-Forwarded-For}i] %M\"\n", RewriteActive, `ErrorLogFormat [%t] [%l] [client\ %{X-Forwarded-For}i] %M`},
		{"error header before the message", "ErrorLogFormat \"[%t] %{X-Forwarded-For}i [client %a] %M\"\n", RewriteActive, "ErrorLogFormat [%t] %{X-Forwarded-For}i [client %a] %M"},
		{"error header after the message", "ErrorLogFormat \"[%{u}t] [%-m:%l] [pid %P:tid %T] %7F: %E: [client\\ %a] %M% ,\\ referer\\ %{Referer}i\"\n", RewriteNone, ""},
		{"error connection peer", "ErrorLogFormat connection \"[%{cu}t] [peer\\ %{c}a]\"\n", RewriteNone, ""},
		{"unterminated argument", "LogFormat \"%h %{X-Forwarded-For\" proxy\n", RewriteUnknown, ""},
		{"dangling percent", "LogFormat \"%h %\" proxy\n", RewriteUnknown, ""},
		{"bare log format", "LogFormat\n", RewriteUnknown, ""},
		{"extra log format argument", "LogFormat \"%h\" proxy extra\n", RewriteUnknown, ""},
		{"bare custom log", "CustomLog logs/access_log\n", RewriteUnknown, ""},
		{"extra custom log argument", "CustomLog logs/access_log combined env=a extra\n", RewriteUnknown, ""},
		{"bare transfer log", "TransferLog\n", RewriteUnknown, ""},
		{"bare error format", "ErrorLogFormat\n", RewriteUnknown, ""},
		{"unknown error format scope", "ErrorLogFormat server \"[client %a]\"\n", RewriteUnknown, ""},
		{"unterminated error argument", "ErrorLogFormat \"[%t] [client %{X\"\n", RewriteUnknown, ""},
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

// Scheduled scans resolve bracketed IPv6 peers, including peers with ports.
// A bracket therefore cannot protect a request-selected access-log field.
func TestHTTPRewriteBracketedClientReader(t *testing.T) {
	for _, token := range []string{"[2001:db8::7]", "[2001:db8::7]:443"} {
		t.Run(token, func(t *testing.T) {
			line := token + ` - - [02/Jan/2006:15:04:05 +0000] "GET / HTTP/1.1" 200 0 "-" "-"`
			rec, ok := parseAccessLogRecord(line)
			if !ok || rec.RemoteIP != token {
				t.Fatalf("record peer = %q, parsed = %v, want %q", rec.RemoteIP, ok, token)
			}
			resolved, err := recordClient(rec, clientaddr.Trusted{})
			if err != nil || resolved.Client.String() != "2001:db8::7" || resolved.Chained {
				t.Fatalf("resolved client = %+v, error = %v, want direct IPv6 peer", resolved, err)
			}
			format := `[%{X-Real-IP}i] %t`
			if token[len(token)-1] != ']' {
				format = `[%{X-Real-IP}i]:443 %t`
			}
			conf := writeRewriteFile(t, t.TempDir(), "httpd.conf", "CustomLog logs/access \""+format+"\"\n")
			requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSApache, apacheConfig: conf}),
				RewriteActive, "CustomLog logs/access "+format, conf)
		})
	}
}

// A format defined in one file and used from another names its definition.
func TestHTTPRewriteApacheLogFormatAcrossFiles(t *testing.T) {
	dir := t.TempDir()
	formats := writeRewriteFile(t, dir, "conf.d/formats.conf", "LogFormat \"%{X-Forwarded-For}i %t\" proxy\n")
	main := writeRewriteFile(t, dir, "httpd.conf", "ServerRoot "+dir+"\nIncludeOptional conf.d/*.conf\n<VirtualHost *:80>\n  CustomLog logs/site_log proxy\n</VirtualHost>\n")
	requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSApache, apacheConfig: main}),
		RewriteActive, "LogFormat %{X-Forwarded-For}i %t proxy", formats)
}

// LiteSpeed's own access log format follows Apache's syntax; every
// logFormat element counts, whatever the accessLog that holds it.
func TestHTTPRewriteLiteSpeedLogFormat(t *testing.T) {
	dir := t.TempDir()
	doc := func(body string) string {
		return "<httpServerConfig><useIpInProxyHeader>0</useIpInProxyHeader><logging><accessLog>" + body + "</accessLog></logging></httpServerConfig>"
	}
	cases := []struct {
		name, body string
		state      RewriteState
		directive  string
	}{
		{"header first", doc("<logFormat>%{X-Forwarded-For}i %l %u %t &quot;%r&quot;</logFormat>"), RewriteActive, `logFormat %{X-Forwarded-For}i %l %u %t "%r"`},
		{"raw newline in time argument", doc("<logFormat>%h %{%&#10;}t%{X-Client}i %t</logFormat>"), RewriteUnknown, ""},
		{"split value", doc("<logFormat>%{X-Forwarded<!-- edge -->-For}i <![CDATA[%t]]></logFormat>"), RewriteActive, "logFormat %{X-Forwarded-For}i %t"},
		{"bracketed IPv6 header", doc("<logFormat>[%{X-Real-IP}i] %t</logFormat>"), RewriteActive, "logFormat [%{X-Real-IP}i] %t"},
		{"address first", doc("<logFormat>%h %l %u %t \"%r\" %{X-Forwarded-For}i</logFormat>"), RewriteNone, ""},
		{"no format", doc("<fileName>$SERVER_ROOT/logs/access.log</fileName>"), RewriteNone, ""},
		{"malformed format", doc("<logFormat>%h %{X-Forwarded-For</logFormat>"), RewriteUnknown, ""},
		{"nested element", doc("<logFormat>%h <b/></logFormat>"), RewriteUnknown, ""},
		{"active before an error", "<httpServerConfig><logFormat>%{X-Real-IP}i %t</logFormat><broken", RewriteActive, "logFormat %{X-Real-IP}i %t"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			conf := writeRewriteFile(t, dir, c.name+".xml", c.body)
			file := conf
			if c.state != RewriteActive {
				file = ""
			}
			requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSLiteSpeed, lswsConfig: conf}), c.state, c.directive, file)
		})
	}
}
