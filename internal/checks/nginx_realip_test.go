package checks

import (
	"net"
	"net/netip"
	"testing"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/netutil"
	"github.com/pidginhost/csm/internal/platform"
)

func withCloudflarePrefixes(t *testing.T, prefixes ...string) {
	t.Helper()
	var set []netip.Prefix
	for _, p := range prefixes {
		set = append(set, netip.MustParsePrefix(p))
	}
	t.Cleanup(SetCloudflarePrefixesForTest(set))
}

func withHostAddresses(t *testing.T, addrs ...string) {
	t.Helper()
	t.Cleanup(netutil.SetHostAddressLookup(func() ([]net.IP, error) {
		var out []net.IP
		for _, a := range addrs {
			out = append(out, net.ParseIP(a))
		}
		return out, nil
	}))
}

func nginxRewrite(t *testing.T, conf string) HTTPRewrite {
	t.Helper()
	main := writeRewriteFile(t, t.TempDir(), "nginx.conf", conf)
	return detectHTTPRewrite(rewriteSources{server: platform.WSNginx, nginxConfig: main})
}

// nginx logs only an address an edge vouched for when every real_ip_header
// is CF-Connecting-IP, which a Cloudflare edge sets itself, and every
// set_real_ip_from lies in Cloudflare's ranges; or every header is
// proxy_protocol, which the connecting proxy writes, from shipped edges or
// trusted proxies. Other headers, the X-Real-IP default, ranges that reach
// loopback or this host, other sources, and request data in the client field
// of a log all stay unverified.
func TestNginxRealIPVerifiedForCDNHeader(t *testing.T) {
	withCloudflarePrefixes(t, "198.51.100.0/24")
	withKnownProxyPrefixes(t, "198.51.100.0/24", "192.0.2.128/25")
	withHostAddresses(t, "203.0.113.50")
	trusted := []string{"203.0.113.0/24", "127.0.0.1"}
	for _, tc := range []struct {
		name, conf string
		want       bool
	}{
		{"cloudflare header and ranges", "http {\n  real_ip_header CF-Connecting-IP;\n  set_real_ip_from 198.51.100.0/24;\n  set_real_ip_from 198.51.100.64/26;\n}\n", true},
		{"proxy protocol from an edge", "http {\n  real_ip_header proxy_protocol;\n  set_real_ip_from 192.0.2.128/25;\n}\n", true},
		{"proxy protocol from a trusted proxy", "http {\n  real_ip_header proxy_protocol;\n  set_real_ip_from 203.0.113.10;\n}\n", true},
		{"forwarded-for header", "http {\n  real_ip_header X-Forwarded-For;\n  set_real_ip_from 198.51.100.0/24;\n}\n", false},
		{"real-ip header", "http {\n  real_ip_header X-Real-IP;\n  set_real_ip_from 198.51.100.0/24;\n}\n", false},
		{"default header", "http {\n  set_real_ip_from 198.51.100.0/24;\n}\n", false},
		{"mixed headers", "http {\n  real_ip_header CF-Connecting-IP;\n  server {\n    real_ip_header proxy_protocol;\n  }\n  set_real_ip_from 192.0.2.128/25;\n}\n", false},
		{"loopback", "http {\n  real_ip_header CF-Connecting-IP;\n  set_real_ip_from 127.0.0.1;\n}\n", false},
		{"loopback listed as trusted", "http {\n  real_ip_header proxy_protocol;\n  set_real_ip_from 127.0.0.1;\n}\n", false},
		{"every address", "http {\n  real_ip_header proxy_protocol;\n  set_real_ip_from 0.0.0.0/0;\n}\n", false},
		{"this host", "http {\n  real_ip_header proxy_protocol;\n  set_real_ip_from 203.0.113.50;\n}\n", false},
		{"outside the edges", "http {\n  real_ip_header CF-Connecting-IP;\n  set_real_ip_from 192.0.2.0/25;\n}\n", false},
		{"cloudflare header from another edge", "http {\n  real_ip_header CF-Connecting-IP;\n  set_real_ip_from 192.0.2.128/25;\n}\n", false},
		{"cloudflare header from a trusted proxy", "http {\n  real_ip_header CF-Connecting-IP;\n  set_real_ip_from 203.0.113.10;\n}\n", false},
		{"unix socket", "http {\n  real_ip_header proxy_protocol;\n  set_real_ip_from unix:;\n}\n", false},
		{"client-format log", "http {\n  log_format peer '$http_x_forwarded_for - $remote_user';\n  access_log /var/log/nginx/site.log peer;\n  real_ip_header CF-Connecting-IP;\n  set_real_ip_from 198.51.100.0/24;\n}\n", false},
	} {
		if got := NginxRealIPVerified(nginxRewrite(t, tc.conf), trusted); got != tc.want {
			t.Errorf("%s: NginxRealIPVerified = %v, want %v", tc.name, got, tc.want)
		}
	}
	if NginxRealIPVerified(HTTPRewrite{State: RewriteActive, Server: platform.WSApache, RealIP: &NginxRealIP{Headers: []string{"CF-Connecting-IP"}, From: []string{"198.51.100.0/24"}}}, nil) {
		t.Error("a non-nginx rewrite was verified")
	}
}

// A verified nginx host's HTTP findings mint as on a direct host; an
// unverified one keeps the rewritten_log refusal, and a CDN edge is still
// refused first.
func TestAdmissionEvidenceMintsOnAVerifiedNginxHost(t *testing.T) {
	withWebPeers(t, 500000)
	withCloudflarePrefixes(t, "198.51.100.0/24")
	withKnownProxyPrefixes(t, "198.51.100.0/24")
	withHostAddresses(t, "203.0.113.50")
	verified := HTTPRewrite{State: RewriteActive, Server: platform.WSNginx, Directive: "set_real_ip_from 198.51.100.0/24",
		RealIP: &NginxRealIP{Headers: []string{"CF-Connecting-IP"}, From: []string{"198.51.100.0/24"}}}
	withHTTPRewrite(t, verified)
	if producer, in, err := AdmissionEvidence(httpPeerFinding("203.0.113.70")); err != nil || producer != ProducerAccessLog || in.Attribution != admission.AttributionHTTPPeer {
		t.Fatalf("verified nginx host: %s %+v, %v; want the client minted", producer, in, err)
	}
	if _, _, err := AdmissionEvidence(httpPeerFinding("198.51.100.7")); admission.CauseOf(err) != admission.CauseProxyPeer {
		t.Fatalf("edge on a verified nginx host: %v, want proxy_peer", err)
	}
	unverified := verified
	unverified.RealIP = &NginxRealIP{Headers: []string{"X-Forwarded-For"}, From: []string{"198.51.100.0/24"}}
	withHTTPRewrite(t, unverified)
	if _, _, err := AdmissionEvidence(httpPeerFinding("203.0.113.70")); admission.CauseOf(err) != admission.CauseRewrittenLog {
		t.Fatalf("unverified nginx host: %v, want rewritten_log", err)
	}
}
