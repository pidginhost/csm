package challenge

import (
	"testing"
)

// resolveTLSMaterial must prefer the per-service challenge.tls_cert /
// challenge.tls_key pair, fall back to the shared webui.tls_cert pair,
// and return empty strings only when neither is configured. The empty
// result is the signal Start() uses to decide between
// ListenAndServeTLS (https) and ListenAndServe (plain http + warning).
func TestResolveTLSMaterialPrefersChallengePair(t *testing.T) {
	cfg := baseCfg()
	cfg.Challenge.TLSCert = "/etc/csm/chal.crt"
	cfg.Challenge.TLSKey = "/etc/csm/chal.key"
	cfg.WebUI.TLSCert = "/etc/csm/webui.crt"
	cfg.WebUI.TLSKey = "/etc/csm/webui.key"

	s, _, _ := newTestServer(t, cfg)
	cert, key := s.resolveTLSMaterial()
	if cert != "/etc/csm/chal.crt" || key != "/etc/csm/chal.key" {
		t.Fatalf("got (%q, %q); want challenge pair", cert, key)
	}
}

func TestResolveTLSMaterialFallsBackToWebUI(t *testing.T) {
	cfg := baseCfg()
	cfg.WebUI.TLSCert = "/etc/csm/webui.crt"
	cfg.WebUI.TLSKey = "/etc/csm/webui.key"

	s, _, _ := newTestServer(t, cfg)
	cert, key := s.resolveTLSMaterial()
	if cert != "/etc/csm/webui.crt" || key != "/etc/csm/webui.key" {
		t.Fatalf("got (%q, %q); want webui pair", cert, key)
	}
}

func TestResolveTLSMaterialEmptyWhenNothingConfigured(t *testing.T) {
	cfg := baseCfg()
	s, _, _ := newTestServer(t, cfg)
	cert, key := s.resolveTLSMaterial()
	if cert != "" || key != "" {
		t.Fatalf("got (%q, %q); want empty pair", cert, key)
	}
}

// Partial pairs (only cert or only key) must fall through to the next
// resolution tier rather than crash ListenAndServeTLS. The order is
// preserved: challenge.cert without challenge.key falls back to webui;
// webui.cert without webui.key returns empty.
// Listener binds loopback by default so a misconfigured deployment
// does not accidentally expose the PoW listener to the internet.
// Operator must explicitly set listen_addr to opt-in to public exposure.
func TestServerBindsLoopbackByDefault(t *testing.T) {
	cfg := baseCfg()
	cfg.Challenge.ListenPort = 18439
	s, _, _ := newTestServer(t, cfg)
	if got := s.srv.Addr; got != "127.0.0.1:18439" {
		t.Fatalf("server bound to %q; want 127.0.0.1:18439 by default", got)
	}
}

func TestServerHonorsExplicitListenAddr(t *testing.T) {
	cfg := baseCfg()
	cfg.Challenge.ListenAddr = "0.0.0.0"
	cfg.Challenge.ListenPort = 18439
	s, _, _ := newTestServer(t, cfg)
	if got := s.srv.Addr; got != "0.0.0.0:18439" {
		t.Fatalf("server bound to %q; want 0.0.0.0:18439", got)
	}
}

func TestResolveTLSMaterialPartialChallengePairFallsBack(t *testing.T) {
	cfg := baseCfg()
	cfg.Challenge.TLSCert = "/etc/csm/chal.crt" // key missing
	cfg.WebUI.TLSCert = "/etc/csm/webui.crt"
	cfg.WebUI.TLSKey = "/etc/csm/webui.key"

	s, _, _ := newTestServer(t, cfg)
	cert, key := s.resolveTLSMaterial()
	if cert != "/etc/csm/webui.crt" || key != "/etc/csm/webui.key" {
		t.Fatalf("partial challenge pair must fall back to webui; got (%q, %q)", cert, key)
	}
}
