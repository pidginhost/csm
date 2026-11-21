package checks

import (
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/config"
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

// A header in one scope cannot prove the default or an override elsewhere.
// Includes must contribute their actual scope and cannot hide trust sources.
func TestNginxRealIPVerificationScopes(t *testing.T) {
	withWebPeers(t, 500000)
	prev := config.Active()
	t.Cleanup(func() { config.SetActive(prev) })
	cfg := &config.Config{}
	cfg.WebServer.TrustedProxies = []string{"203.0.113.0/24"}
	config.SetActive(cfg)
	withCloudflarePrefixes(t, "198.51.100.0/24")
	withKnownProxyPrefixes(t, "198.51.100.0/24")
	withHostAddresses(t, "203.0.113.50", "2001:db8::50")
	for _, tc := range []struct {
		name, conf, included string
		want                 bool
	}{
		{"server leaves sibling default", "http { set_real_ip_from 198.51.100.0/24; server { real_ip_header CF-Connecting-IP; } server { listen 8080; } }", "", false},
		{"location leaves server default", "http { set_real_ip_from 198.51.100.0/24; server { location / { real_ip_header CF-Connecting-IP; } } }", "", false},
		{"server changes safe header", "http { real_ip_header CF-Connecting-IP; set_real_ip_from 198.51.100.0/24; server { real_ip_header proxy_protocol; } }", "", false},
		{"location changes safe header", "http { real_ip_header proxy_protocol; set_real_ip_from 198.51.100.0/24; server { location / { real_ip_header CF-Connecting-IP; } } }", "", false},
		{"same header inherited", "http { real_ip_header CF-Connecting-IP; set_real_ip_from 198.51.100.0/24; server { location / { real_ip_header cf-connecting-ip; } } }", "", true},
		{"map entry is not a header", "http { map $uri $label { real_ip_header CF-Connecting-IP; } set_real_ip_from 198.51.100.0/24; }", "", false},
		{"header in wrong context", "real_ip_header CF-Connecting-IP; http { set_real_ip_from 198.51.100.0/24; }", "", false},
		{"header block", "http { real_ip_header CF-Connecting-IP {} set_real_ip_from 198.51.100.0/24; }", "", false},
		{"include safe header", "http { include extra.conf; set_real_ip_from 198.51.100.0/24; }", "real_ip_header CF-Connecting-IP;", true},
		{"include server header", "http { set_real_ip_from 198.51.100.0/24; server { include extra.conf; } server {} }", "real_ip_header CF-Connecting-IP;", false},
		{"include override", "http { real_ip_header CF-Connecting-IP; set_real_ip_from 198.51.100.0/24; server { include extra.conf; } }", "location / { real_ip_header X-Real-IP; }", false},
		{"include local trust", "http { real_ip_header proxy_protocol; set_real_ip_from 198.51.100.0/24; server { include extra.conf; } }", "location / { set_real_ip_from 203.0.113.50; }", false},
		{"include mapped trust", "http { real_ip_header proxy_protocol; set_real_ip_from 198.51.100.0/24; include extra.conf; }", "server { set_real_ip_from ::ffff:203.0.113.50; }", false},
		{"include hostname", "http { real_ip_header proxy_protocol; set_real_ip_from 198.51.100.0/24; include extra.conf; }", "server { set_real_ip_from proxy.example; }", false},
		{"missing include", "http { real_ip_header CF-Connecting-IP; set_real_ip_from 198.51.100.0/24; include missing.conf; }", "", false},
		{"incomplete tree", "http { real_ip_header CF-Connecting-IP; set_real_ip_from 198.51.100.0/24;", "", false},
		{"header variable", "http { real_ip_header $header; set_real_ip_from 198.51.100.0/24; }", "", false},
		{"source variable", "http { real_ip_header proxy_protocol; set_real_ip_from $proxy; }", "", false},
		{"include format injection", "http { real_ip_header CF-Connecting-IP; set_real_ip_from 198.51.100.0/24; include extra.conf; }", "log_format unsafe '$http_x_real_ip - -'; server { access_log /var/log/nginx/site.log unsafe; }", false},
		{"unresolved format", "http { real_ip_header CF-Connecting-IP; set_real_ip_from 198.51.100.0/24; access_log /var/log/nginx/site.log unknown; }", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			main := writeRewriteFile(t, root, "nginx.conf", tc.conf)
			if tc.included != "" {
				writeRewriteFile(t, root, "extra.conf", tc.included)
			}
			r := detectHTTPRewrite(rewriteSources{server: platform.WSNginx, nginxConfig: main})
			if got := NginxRealIPVerified(r, []string{"203.0.113.0/24"}); got != tc.want {
				t.Fatalf("verified = %v, want %v: %+v", got, tc.want, r)
			}
			withHTTPRewrite(t, r)
			_, _, err := AdmissionEvidence(httpPeerFinding("192.0.2.70"))
			if tc.want && err != nil || !tc.want && admission.CauseOf(err) != admission.CauseRewrittenLog {
				t.Fatalf("admission = %v, want verification %v", err, tc.want)
			}
		})
	}
}

func TestNginxRealIPVerificationLocalRanges(t *testing.T) {
	withKnownProxyPrefixes(t)
	withHostAddresses(t, "203.0.113.50", "2001:db8::50")
	for _, from := range []string{
		"127.0.0.0/8", "::1", "::ffff:127.0.0.1", "::ffff:127.0.0.0/104",
		"::ffff:0:0/80", "::/80", "::/96", "0.0.0.0", "::",
		"203.0.113.50", "203.0.113.0/24", "::ffff:203.0.113.50", "::ffff:203.0.113.0/120",
		"2001:db8::50", "2001:db8::/64", "proxy.example", "$proxy",
	} {
		t.Run(from, func(t *testing.T) {
			r := nginxRewrite(t, "http { real_ip_header proxy_protocol; set_real_ip_from "+from+"; }")
			if NginxRealIPVerified(r, []string{from}) {
				t.Fatal("local or unresolved source verified even though a tenant can forge the client")
			}
		})
	}
}

// Neither a previously successful lookup nor a prior configuration can
// authorize a later finding after the host or active trust list changes.
func TestAdmissionNginxVerificationUsesLiveTrust(t *testing.T) {
	withWebPeers(t, 500000)
	withKnownProxyPrefixes(t)
	prev := config.Active()
	t.Cleanup(func() { config.SetActive(prev) })
	cfg := &config.Config{}
	cfg.WebServer.TrustedProxies = []string{"203.0.113.10"}
	config.SetActive(cfg)
	host := "203.0.113.50"
	var lookupErr error
	t.Cleanup(netutil.SetHostAddressLookup(func() ([]net.IP, error) {
		return []net.IP{net.ParseIP(host)}, lookupErr
	}))
	withHTTPRewrite(t, nginxRewrite(t, "http { real_ip_header proxy_protocol; set_real_ip_from 203.0.113.10; }"))
	check := func(want admission.Cause) {
		t.Helper()
		_, in, err := AdmissionEvidence(httpPeerFinding("192.0.2.70"))
		if (want == 0 && err != nil) || admission.CauseOf(err) != want {
			t.Fatalf("admission: %v, want cause %v", err, want)
		}
		if want == 0 && in.Target.Prefix().Addr().String() != "192.0.2.70" {
			t.Fatalf("minted wrong target: %+v", in.Target)
		}
	}
	check(0)
	lookupErr = errors.New("interface lookup failed")
	check(admission.CauseRewrittenLog)
	lookupErr = nil
	host = "203.0.113.10"
	check(admission.CauseRewrittenLog)
	host = "203.0.113.50"
	check(0)
	config.SetActive(&config.Config{})
	check(admission.CauseRewrittenLog)
	config.SetActive(nil)
	check(admission.CauseRewrittenLog)
	config.SetActive(cfg)
	check(0)

	withCloudflarePrefixes(t, "198.51.100.0/24")
	withHTTPRewrite(t, nginxRewrite(t, "http { real_ip_header CF-Connecting-IP; set_real_ip_from 198.51.100.0/24; }"))
	config.SetActive(nil)
	check(0)
	lookupErr = errors.New("interface lookup failed")
	check(admission.CauseRewrittenLog)
}

func TestHTTPRewriteRealIPSnapshotIsolation(t *testing.T) {
	for _, mutateInput := range []bool{true, false} {
		t.Run(map[bool]string{true: "publisher", false: "reader"}[mutateInput], func(t *testing.T) {
			r := HTTPRewrite{State: RewriteActive, Server: platform.WSNginx,
				RealIP: &NginxRealIP{Headers: []string{"X-Real-IP"}, From: []string{"203.0.113.50"}}}
			withHTTPRewrite(t, r)
			if !mutateInput {
				r = CurrentHTTPRewrite()
			}
			r.RealIP.Headers[0] = "CF-Connecting-IP"
			r.RealIP.From[0] = "198.51.100.0/24"
			got := CurrentHTTPRewrite()
			if got.RealIP.Headers[0] != "X-Real-IP" || got.RealIP.From[0] != "203.0.113.50" {
				t.Fatalf("caller mutated published trust: %+v", got.RealIP)
			}
		})
	}
}

func TestHTTPRewriteEqualComparesTrustValues(t *testing.T) {
	a := HTTPRewrite{State: RewriteActive, Server: platform.WSNginx,
		RealIP: &NginxRealIP{Headers: []string{"CF-Connecting-IP"}, From: []string{"198.51.100.0/24"}}}
	withHTTPRewrite(t, a)
	b := CurrentHTTPRewrite()
	if !a.Equal(b) || !b.Equal(a) || !(HTTPRewrite{}).Equal(HTTPRewrite{}) {
		t.Fatal("equal settings compare differently after publication")
	}
	for _, change := range []func(*HTTPRewrite){
		func(r *HTTPRewrite) { r.State = RewriteUnknown },
		func(r *HTTPRewrite) { r.Server = platform.WSApache },
		func(r *HTTPRewrite) { r.Directive = "other" },
		func(r *HTTPRewrite) { r.File = "/other.conf" },
		func(r *HTTPRewrite) { r.Reason = "unreadable" },
		func(r *HTTPRewrite) { r.Format = true },
		func(r *HTTPRewrite) { r.RealIP = nil },
		func(r *HTTPRewrite) { r.RealIP.Headers[0] = "X-Real-IP" },
		func(r *HTTPRewrite) { r.RealIP.From[0] = "203.0.113.50" },
	} {
		b = CurrentHTTPRewrite()
		change(&b)
		if a.Equal(b) || b.Equal(a) {
			t.Fatalf("changed settings compare equal: %+v", b)
		}
	}
}
