package checks

import (
	"fmt"
	"testing"

	"github.com/pidginhost/csm/internal/platform"
)

// nginx logs a client-chosen address when an access_log writes a format
// whose first field holds a variable other than the peer or a server
// value. The built-in combined format, access_log off and formats no
// access_log names do not count; nginx selects the first matching name.
func TestHTTPRewriteNginxLogFormats(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name, body string
		state      RewriteState
		directive  string
	}{
		{"stock combined", "http {\n  access_log /var/log/nginx/access.log;\n  server { access_log /var/log/nginx/site.log combined; }\n}\n", RewriteNone, ""},
		{"no access log", "events {}\nhttp { server { listen 80; } }\n", RewriteNone, ""},
		{"leading spaces", "http { log_format leading '  $http_x_real_ip $status'; access_log logs/access leading; }\n", RewriteActive, "log_format leading   $http_x_real_ip $status"},
		{"cookie first", `http { log_format cookie '$cookie_client $status'; access_log logs/access cookie; }`, RewriteActive, "log_format cookie $cookie_client $status"},
		{"argument first", `http { log_format query '${arg_client} $status'; access_log logs/access query; }`, RewriteActive, "log_format query ${arg_client} $status"},
		{"default quoted request", `http { log_format quoted escape=default '"$http_x_client" $status'; access_log logs/access quoted; }`, RewriteNone, ""},
		{"json quoted request", `http { log_format quoted escape=json '"$http_x_client" $status'; access_log logs/access quoted; }`, RewriteNone, ""},
		{"unescaped later value", "http { log_format raw escape=none '$remote_addr $request_body'; access_log logs/access raw; }\n", RewriteActive, "log_format raw escape=none $remote_addr $request_body"},
		{"unescaped quoted value", "http { log_format raw escape=none '\"$request_body\"'; access_log logs/access raw; }\n", RewriteActive, "log_format raw escape=none \"$request_body\""},
		{"invalid escape", "http { log_format bad escape=bogus '$remote_addr'; }\n", RewriteUnknown, ""},
		{"off extra argument", "http { access_log off combined; }\n", RewriteUnknown, ""},
		{"format name folds case", "http { log_format Mixed '$http_x_real_ip'; access_log logs/access MIXED; }\n", RewriteActive, "log_format Mixed $http_x_real_ip"},
		{"split variable name", "http { map $http_x_client $remote { default $http_x_client; } log_format split '$remote' '_addr $status'; access_log logs/access split; }\n", RewriteActive, "log_format split $remote _addr $status"},
		{"split dollar is invalid", "http { log_format split '$' 'remote_addr'; }\n", RewriteUnknown, ""},
		{"split brace is invalid", "http { log_format split '${remote_' 'addr}'; }\n", RewriteUnknown, ""},
		{"duplicate name", "http { log_format main '$remote_addr'; log_format main '$status'; }\n", RewriteUnknown, ""},
		{"binary field framing", "http { log_format binary '$binary_remote_addr $http_x_real_ip'; access_log logs/access binary; }\n", RewriteUnknown, ""},
		{"log outside a module", "log_format main '$remote_addr'; access_log logs/access main;\n", RewriteUnknown, ""},
		{"mapped optional peer variable", "http { map $http_x_client $RealIP_Remote_Addr { default $http_x_client; } log_format custom '$REALIP_REMOTE_ADDR $status'; access_log logs/access custom; }\n", RewriteActive, "log_format custom $REALIP_REMOTE_ADDR $status"},
		{"captured optional peer variable", `http { server { server_name ~^(?<realip_remote_addr>.*)$; } log_format custom '$realip_remote_addr $status'; access_log logs/access custom; }`, RewriteActive, "log_format custom $realip_remote_addr $status"},
		{"scripted optional peer variable", `http { js_set $realip_remote_addr client.address; log_format custom '$realip_remote_addr $status'; access_log logs/access custom; }`, RewriteActive, "log_format custom $realip_remote_addr $status"},
		{"captured optional peer port", `stream { map $proxy_protocol_addr $client { ~^(?<realip_remote_port>.*)$ $realip_remote_port; } log_format custom '$realip_remote_port $status'; access_log logs/access custom; }`, RewriteActive, "log_format custom $realip_remote_port $status"},
		{"captured version dependent stream name", `stream { map $proxy_protocol_addr $client { ~^(?<server_name>.*)$ $server_name; } log_format custom '$server_name'; access_log logs/access custom; }`, RewriteActive, "log_format custom $server_name"},
		{"set optional peer variable", "http { log_format custom '$realip_remote_addr $status'; server { set $realip_remote_addr $http_x_client; access_log logs/access custom; } }\n", RewriteActive, "log_format custom $realip_remote_addr $status"},
		{"geo optional peer variable", "http { geo $realip_remote_addr { default 203.0.113.7; } log_format custom '$realip_remote_addr $status'; access_log logs/access custom; }\n", RewriteActive, "log_format custom $realip_remote_addr $status"},
		{"split clients peer variable", "http { split_clients $http_x_client $realip_remote_addr { * 203.0.113.7; } log_format custom '$realip_remote_addr $status'; access_log logs/access custom; }\n", RewriteActive, "log_format custom $realip_remote_addr $status"},
		{"auth request peer variable", "http { auth_request_set $realip_remote_addr $upstream_http_x_client; log_format custom '$realip_remote_addr $status'; access_log logs/access custom; }\n", RewriteActive, "log_format custom $realip_remote_addr $status"},
		{"perl peer variable", "http { perl_set $realip_remote_addr 'sub { return shift->header(\"X-Client\"); }'; log_format custom '$realip_remote_addr $status'; access_log logs/access custom; }\n", RewriteActive, "log_format custom $realip_remote_addr $status"},
		{"malformed split clients declaration", "http { split_clients $realip_remote_addr {} access_log logs/access; }\n", RewriteUnknown, ""},
		{"malformed auth request declaration", "http { auth_request_set $realip_remote_addr; access_log logs/access; }\n", RewriteUnknown, ""},
		{"malformed perl declaration", "http { perl_set $realip_remote_addr; access_log logs/access; }\n", RewriteUnknown, ""},
		{"unused mapped variable", "http { map $http_x_client $realip_remote_addr { default $http_x_client; } log_format custom '$realip_remote_addr'; access_log logs/access; }\n", RewriteNone, ""},
		{"malformed map declaration", "http { map $realip_remote_addr {} access_log logs/access; }\n", RewriteUnknown, ""},
		{"malformed set declaration", "http { server { set $realip_remote_addr; } access_log logs/access; }\n", RewriteUnknown, ""},
		{"malformed geo declaration", "http { geo $a $b $c {} access_log logs/access; }\n", RewriteUnknown, ""},
		{"invalid variable destination", "http { map $http_x_client realip_remote_addr {} access_log logs/access; }\n", RewriteUnknown, ""},
		{"stream user variable shadows HTTP name", "stream { map $proxy_protocol_addr $request_time { default $proxy_protocol_addr; } log_format custom '$request_time $status'; server { access_log logs/stream custom; } }\n", RewriteActive, "log_format custom $request_time $status"},
		{"stream combined", "stream { log_format combined '$proxy_protocol_addr'; access_log logs/stream combined; }\n", RewriteActive, "log_format combined $proxy_protocol_addr"},
		{"stream direct combined", "stream { log_format combined '$remote_addr'; access_log logs/stream combined; }\n", RewriteNone, ""},
		{"stream needs a format", "stream { access_log logs/stream; }\n", RewriteUnknown, ""},
		{"stream logging off", "stream { access_log off; }\n", RewriteNone, ""},
		{"module namespaces", "http { log_format main '$remote_addr'; access_log logs/http main; } stream { log_format main '$proxy_protocol_addr'; }\n", RewriteNone, ""},
		{"escape only format", "http { log_format empty escape=json; access_log logs/access empty; }\n", RewriteNone, ""},
		{"forwarded first", "http {\n  log_format proxy '$http_x_forwarded_for - $remote_user [$time_local] \"$request\"';\n  access_log /var/log/nginx/access.log proxy;\n}\n", RewriteActive, `log_format proxy $http_x_forwarded_for - $remote_user [$time_local] "$request"`},
		{"unused format", "http {\n  log_format proxy '$http_x_forwarded_for $time_local';\n  access_log /var/log/nginx/access.log;\n}\n", RewriteNone, ""},
		{"logging off", "http {\n  log_format proxy '$http_x_real_ip $time_local';\n  access_log off;\n  server { access_log off; }\n}\n", RewriteNone, ""},
		{"forwarded after the address", "http {\n  log_format main '$remote_addr - $remote_user [$time_local] \"$request\" \"$http_x_forwarded_for\"';\n  access_log /var/log/nginx/access.log main buffer=32k;\n}\n", RewriteNone, ""},
		{"empty hostname", "http { log_format optional '$hostname $http_x_real_ip'; access_log logs/access optional; }\n", RewriteActive, "log_format optional $hostname $http_x_real_ip"},
		{"empty server name", "http { log_format optional '$server_name $http_x_real_ip'; access_log logs/access optional; }\n", RewriteActive, "log_format optional $server_name $http_x_real_ip"},
		{"empty remote port", "http { log_format optional '$remote_port $http_x_real_ip'; access_log logs/access optional; }\n", RewriteActive, "log_format optional $remote_port $http_x_real_ip"},
		{"empty original port", "http { log_format optional '$realip_remote_port $http_x_real_ip'; access_log logs/access optional; }\n", RewriteActive, "log_format optional $realip_remote_port $http_x_real_ip"},
		{"empty server port", "http { log_format optional '$server_port $http_x_real_ip'; access_log logs/access optional; }\n", RewriteActive, "log_format optional $server_port $http_x_real_ip"},
		{"empty field before peer", "http { log_format optional '$server_name $remote_addr $http_x_real_ip'; access_log logs/access optional; }\n", RewriteNone, ""},
		{"server values first", "http {\n  log_format timed '$msec:$pid $realip_remote_addr $http_x_forwarded_for';\n  access_log /var/log/nginx/access.log timed;\n}\n", RewriteNone, ""},
		{"host first", "http {\n  log_format vhosts '$host $remote_addr [$time_local]';\n  server { access_log /var/log/nginx/access.log vhosts; }\n}\n", RewriteActive, "log_format vhosts $host $remote_addr [$time_local]"},
		{"user variable first", "http {\n  map $http_x_forwarded_for $client { default $remote_addr; }\n  log_format mapped '$client [$time_local]';\n  access_log /var/log/nginx/access.log mapped;\n}\n", RewriteActive, "log_format mapped $client [$time_local]"},
		{"bracketed IPv6 header", "http { log_format bracketed '[$http_x_real_ip] $status'; access_log logs/access bracketed; }\n", RewriteActive, "log_format bracketed [$http_x_real_ip] $status"},
		{"bracketed variable", "http {\n  log_format braced '${http_x_real_ip}:$remote_port [$time_local]';\n  access_log /var/log/nginx/access.log braced;\n}\n", RewriteActive, "log_format braced ${http_x_real_ip}:$remote_port [$time_local]"},
		{"variable names fold case", "http {\n  log_format upper '$Remote_Addr [$time_local]';\n  access_log /var/log/nginx/access.log upper;\n}\n", RewriteNone, ""},
		{"literal guard across strings", "http { log_format split 'ip=' '$http_x_real_ip'; access_log logs/access split; }\n", RewriteNone, ""},
		{"strings join", "http {\n  log_format split '$time_local' '$http_x_real_ip' ' $status';\n  access_log /var/log/nginx/access.log split;\n}\n", RewriteActive, "log_format split $time_local $http_x_real_ip  $status"},
		{"escape parameter", "http {\n  log_format plain escape=none '$http_x_real_ip $status';\n  access_log /var/log/nginx/access.log plain;\n}\n", RewriteActive, "log_format plain escape=none $http_x_real_ip $status"},
		{"tab before the variable", "http {\n  log_format tabbed \"\\t$http_x_real_ip $status\";\n  access_log /var/log/nginx/access.log tabbed;\n}\n", RewriteActive, "log_format tabbed \t$http_x_real_ip $status"},
		{"json format", "http {\n  log_format json escape=json '{\"ip\":\"$remote_addr\",\"xff\":\"$http_x_forwarded_for\"}';\n  access_log /var/log/nginx/access.json json;\n}\n", RewriteNone, ""},
		{"second line", "http {\n  log_format two \"$remote_addr $status\\n$http_x_real_ip $status\";\n  access_log /var/log/nginx/access.log two;\n}\n", RewriteActive, "log_format two $remote_addr $status\n$http_x_real_ip $status"},
		{"stream log", "stream {\n  log_format tcp '$proxy_protocol_addr $status';\n  server { access_log /var/log/nginx/tcp.log tcp; }\n}\n", RewriteActive, "log_format tcp $proxy_protocol_addr $status"},
		{"unknown format name", "http { access_log /var/log/nginx/access.log missing; }\n", RewriteUnknown, ""},
		{"combined redefined", "http {\n  log_format combined '$remote_addr';\n  access_log /var/log/nginx/access.log;\n}\n", RewriteUnknown, ""},
		{"bare log format", "http { log_format main; }\n", RewriteUnknown, ""},
		{"bare access log", "http { access_log; }\n", RewriteUnknown, ""},
		{"dangling dollar", "http {\n  log_format broken '$ $remote_addr';\n  access_log /var/log/nginx/access.log;\n}\n", RewriteUnknown, ""},
		{"unterminated bracket", "http {\n  log_format broken '${remote_addr [$time_local]';\n  access_log /var/log/nginx/access.log;\n}\n", RewriteUnknown, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			conf := writeRewriteFile(t, dir, c.name+".conf", c.body)
			file := conf
			if c.state != RewriteActive {
				file = ""
			}
			requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSNginx, nginxConfig: conf}), c.state, c.directive, file)
		})
	}
}

func TestHTTPRewriteNginxFormatLookup(t *testing.T) {
	for _, module := range []string{"http", "stream"} {
		for _, tc := range []struct {
			name, body string
			state      RewriteState
			directive  string
		}{
			{"forward reference", `access_log logs/access later; log_format later '$remote_addr';`, RewriteUnknown, ""},
			{"format in server", `server { log_format main '$remote_addr'; access_log logs/access main; }`, RewriteUnknown, ""},
			{"format as block", `log_format main '$remote_addr' {} access_log logs/access main;`, RewriteUnknown, ""},
			{"access as block", `log_format main '$remote_addr'; access_log logs/access main {}`, RewriteUnknown, ""},
			{"access in upstream", `log_format main '$remote_addr'; upstream backend { access_log logs/access main; }`, RewriteUnknown, ""},
			{"unused case variant", `log_format main '$remote_addr'; log_format MAIN '$proxy_protocol_addr'; access_log logs/access MAIN;`, RewriteNone, ""},
			{"selected case variant", `log_format MAIN '$proxy_protocol_addr'; log_format main '$remote_addr'; access_log logs/access main;`, RewriteActive, "log_format MAIN $proxy_protocol_addr"},
			{"non ASCII name mismatch", "log_format trac\u212a '$remote_addr'; access_log logs/access track;", RewriteUnknown, ""},
			{"non ASCII name matches", "log_format trac\u212a '$remote_addr'; access_log logs/access TRAC\u212a;", RewriteNone, ""},
		} {
			t.Run(module+"/"+tc.name, func(t *testing.T) {
				conf := writeRewriteFile(t, t.TempDir(), "nginx.conf", module+" { "+tc.body+" }")
				file := ""
				if tc.state == RewriteActive {
					file = conf
				}
				requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSNginx, nginxConfig: conf}), tc.state, tc.directive, file)
			})
		}
	}
}

func TestHTTPRewriteNginxIncludeRequiresStatement(t *testing.T) {
	dir := t.TempDir()
	writeRewriteFile(t, dir, "formats.conf", `log_format main '$remote_addr';`)
	conf := writeRewriteFile(t, dir, "nginx.conf", `http { include formats.conf {} access_log logs/access main; }`)
	requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSNginx, nginxConfig: conf}), RewriteUnknown, "", "")
}

func TestHTTPRewriteNginxStreamServerVariables(t *testing.T) {
	for _, variable := range []string{"bytes_received", "session_time", "protocol"} {
		t.Run(variable, func(t *testing.T) {
			conf := writeRewriteFile(t, t.TempDir(), "nginx.conf", fmt.Sprintf(`stream {
    log_format main '$%s $proxy_protocol_addr';
    access_log logs/stream main;
}`, variable))
			requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSNginx, nginxConfig: conf}), RewriteNone, "", "")
			conf = writeRewriteFile(t, t.TempDir(), "nginx.conf", fmt.Sprintf(`http {
    map $http_x_client $%s { default $http_x_client; }
    log_format main '$%s $status';
    access_log logs/http main;
}`, variable, variable))
			requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSNginx, nginxConfig: conf}), RewriteActive, "log_format main $"+variable+" $status", conf)
		})
	}
}

// Map entries are values, even when their keys spell directive names.
// Includes inside a map retain the same data context.
func TestHTTPRewriteNginxMapEntries(t *testing.T) {
	for _, module := range []string{"http", "stream"} {
		for _, key := range []string{"log_format", "access_log", "map", "set", "geo", "split_clients", "auth_request_set", "perl_set"} {
			t.Run(module+"/"+key, func(t *testing.T) {
				dir := t.TempDir()
				writeRewriteFile(t, dir, "entries.conf", key+" allowed;\n")
				conf := writeRewriteFile(t, dir, "nginx.conf", module+` {
    map $remote_addr $label { include entries.conf; }
    log_format peer '$remote_addr';
    access_log logs/access peer;
}`)
				requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSNginx, nginxConfig: conf}), RewriteNone, "", "")
			})
		}
	}
}

// A format defined in an included file and used elsewhere names its
// definition; set_real_ip_from still names itself first.
func TestHTTPRewriteNginxLogFormatAcrossFiles(t *testing.T) {
	dir := t.TempDir()
	formats := writeRewriteFile(t, dir, "conf.d/formats.conf", "log_format proxy '$http_x_forwarded_for [$time_local]';\n")
	main := writeRewriteFile(t, dir, "nginx.conf", "http {\n  include conf.d/*.conf;\n  server { access_log /var/log/nginx/site.log proxy; }\n}\n")
	requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSNginx, nginxConfig: main}),
		RewriteActive, "log_format proxy $http_x_forwarded_for [$time_local]", formats)

	both := writeRewriteFile(t, dir, "both.conf", "http {\n  log_format proxy '$http_x_forwarded_for';\n  access_log /var/log/nginx/access.log proxy;\n  set_real_ip_from 192.0.2.0/24;\n}\n")
	requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSNginx, nginxConfig: both}),
		RewriteActive, "set_real_ip_from 192.0.2.0/24", both)

	streamFormat := writeRewriteFile(t, dir, "stream-format.conf", "log_format combined '$proxy_protocol_addr';\n")
	writeRewriteFile(t, dir, "stream-use.conf", "server { access_log logs/stream combined; }\n")
	streamMain := writeRewriteFile(t, dir, "stream.conf", "stream { include stream-format.conf; include stream-use.conf; }\nhttp { access_log logs/http; }\n")
	requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSNginx, nginxConfig: streamMain}),
		RewriteActive, "log_format combined $proxy_protocol_addr", streamFormat)

}

// nginx refuses to redefine a built-in variable, so a file that does is not
// the configuration nginx runs. A user definition never inherits the
// built-in's trust, whatever spelling or module defines it.
func TestHTTPRewriteNginxRedefinedBuiltins(t *testing.T) {
	for _, tc := range []struct{ name, body, directive string }{
		{"map", "http { map $http_x_client $Remote_Addr { default $http_x_client; } log_format custom '$REMOTE_ADDR $status'; access_log logs/access custom; }\n", "log_format custom $REMOTE_ADDR $status"},
		{"set", "http { log_format custom '$remote_addr $status'; server { set $remote_addr $http_x_client; access_log logs/access custom; } }\n", "log_format custom $remote_addr $status"},
		{"geo", "http { geo $remote_addr { default 203.0.113.7; } log_format custom '$remote_addr $status'; access_log logs/access custom; }\n", "log_format custom $remote_addr $status"},
		{"split_clients", "http { split_clients $http_x_client $remote_addr { * 203.0.113.7; } log_format custom '$remote_addr $status'; access_log logs/access custom; }\n", "log_format custom $remote_addr $status"},
		{"auth_request_set", "http { auth_request_set $remote_addr $upstream_http_x_client; log_format custom '$remote_addr $status'; access_log logs/access custom; }\n", "log_format custom $remote_addr $status"},
		{"perl_set", "http { perl_set $remote_addr 'sub { return shift->header(\"X-Client\"); }'; log_format custom '$remote_addr $status'; access_log logs/access custom; }\n", "log_format custom $remote_addr $status"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf := writeRewriteFile(t, t.TempDir(), "nginx.conf", tc.body)
			requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSNginx, nginxConfig: conf}), RewriteActive, tc.directive, conf)
		})
	}
}

// A stream format is never an HTTP format of the same name, even when it is
// declared before the HTTP log that names it.
func TestHTTPRewriteNginxStreamFormatBeforeHTTPUse(t *testing.T) {
	conf := writeRewriteFile(t, t.TempDir(), "nginx.conf", "stream { log_format main '$remote_addr'; } http { log_format other '$remote_addr'; access_log logs/http main; }\n")
	requireRewrite(t, detectHTTPRewrite(rewriteSources{server: platform.WSNginx, nginxConfig: conf}), RewriteUnknown, "", "")
}
