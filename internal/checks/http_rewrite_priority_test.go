package checks

import (
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/platform"
)

// Header trust cannot make a request-chosen log field safe to block.
func TestHTTPRewriteFormatTakesPriorityOverHeader(t *testing.T) {
	for _, tc := range []struct {
		name, header, format, directive string
		server                          platform.WebServer
	}{
		{"apache inline", "RemoteIPHeader X-Real-IP\n", "CustomLog logs/access_log \"%{X-Client}i %t\"\n", "CustomLog", platform.WSApache},
		{"apache named", "RemoteIPProxyProtocol On\n", "LogFormat \"%{X-Client}i %t\" client\nCustomLog logs/access_log client\n", "LogFormat", platform.WSApache},
		{"apache global", "LoadModule cloudflare_module modules/mod_cloudflare.so\n", "GlobalLog logs/access_log \"%{X-Client}i %t\"\n", "GlobalLog", platform.WSApache},
		{"apache default", "RPAF_Enable On\n", "LogFormat \"%{X-Client}i %t\"\nTransferLog logs/access_log\n", "LogFormat", platform.WSApache},
		{"apache transfer", "RPAFenable On\n", "HostnameLookups On\nTransferLog logs/access_log\n", "TransferLog", platform.WSApache},
		{"apache error", "CloudFlareRemoteIPHeader X-Real-IP\n", "ErrorLogFormat \"[client %{CLIENT}n] %M\"\n", "ErrorLogFormat", platform.WSApache},
		{"nginx", "set_real_ip_from 192.0.2.0/24;\n", "log_format client '$http_x_client $time_local';\naccess_log /var/log/nginx/access.log client;\n", "log_format", platform.WSNginx},
	} {
		for _, headerFirst := range []bool{true, false} {
			name := tc.name + "/format-first"
			body := tc.format + tc.header
			if headerFirst {
				name, body = tc.name+"/header-first", tc.header+tc.format
			}
			t.Run(name, func(t *testing.T) {
				if tc.server == platform.WSNginx {
					body = "http {\n" + body + "}\n"
				}
				path := writeRewriteFile(t, t.TempDir(), "server.conf", body)
				src := rewriteSources{server: tc.server, apacheConfig: path}
				if tc.server == platform.WSNginx {
					src.apacheConfig, src.nginxConfig = "", path
				}
				r := detectHTTPRewrite(src)
				if r.State != RewriteActive || !r.Format || !strings.HasPrefix(r.Directive, tc.directive+" ") || r.File != path {
					t.Fatalf("rewrite = %+v, want active %s format in %s", r, tc.directive, path)
				}
				withHTTPRewrite(t, r)
				a := withAdmission(t)
				a.executes = true
				f := alert.Finding{Check: "wp_login_bruteforce", SourceIP: "203.0.113.90", Attribution: admission.AttributionHTTPPeer}
				_, _, err := AdmissionEvidence(f)
				if admission.CauseOf(err) != admission.CauseRewrittenLog {
					t.Fatalf("mint refusal = %v, want rewritten log", err)
				}
				a.mintErr = err
				if taken, accepted := respond(admission.KindBlockIP, f, f.SourceIP, 0); !taken || accepted {
					t.Fatalf("direct refusal: taken %v, accepted %v", taken, accepted)
				}
				for _, ttl := range []time.Duration{0, time.Hour, 2 * time.Hour} {
					if !respondDerived(ApplyBlockRequest{IP: f.SourceIP, TTL: ttl, RootFinding: f, RootErr: err, Entry: admission.EntryIncident}, time.Hour) {
						t.Errorf("refused derived block with TTL %v was left to legacy", ttl)
					}
				}
				if calls := a.responses(); len(calls) != 0 {
					t.Fatalf("refused evidence submitted blocks: %+v", calls)
				}
			})
		}
	}
}

func TestHTTPRewriteHeaderExceptionWithoutUnsafeUsedFormat(t *testing.T) {
	for _, tc := range []struct {
		name, body, directive string
		server                platform.WebServer
	}{
		{"apache unused", "RemoteIPHeader X-Real-IP\nLogFormat \"%{X-Client}i %t\" unused\nCustomLog logs/access_log \"%a %t\"\n", "RemoteIPHeader X-Real-IP", platform.WSApache},
		{"apache unreadable include", "RemoteIPHeader X-Real-IP\nInclude missing.conf\n", "RemoteIPHeader X-Real-IP", platform.WSApache},
		{"nginx unused", "http { set_real_ip_from 192.0.2.0/24; log_format unused '$http_x_client'; access_log logs/access combined; }\n", "set_real_ip_from 192.0.2.0/24", platform.WSNginx},
		{"nginx unreadable include", "http { set_real_ip_from 192.0.2.0/24; include missing.conf; }\n", "set_real_ip_from 192.0.2.0/24", platform.WSNginx},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeRewriteFile(t, t.TempDir(), "server.conf", tc.body)
			src := rewriteSources{server: tc.server, apacheConfig: path}
			if tc.server == platform.WSNginx {
				src.apacheConfig, src.nginxConfig = "", path
			}
			r := detectHTTPRewrite(src)
			if r.State != RewriteActive || r.Format || r.Directive != tc.directive || r.File != path {
				t.Fatalf("rewrite = %+v, want header rewrite %q in %s", r, tc.directive, path)
			}
			withHTTPRewrite(t, r)
			if taken(true, admission.KindBlockIP, attributionRefusal(admission.CauseRewrittenLog), nil) {
				t.Fatal("header-only refusal was taken from legacy")
			}
		})
	}
}
