package checks

import "testing"

// probeHost decides which address the reachability probe dials. Forcing
// 127.0.0.1 fails on LiteSpeed, which returns 403 to loopback-originated
// requests even when the file is served (HTTP 200) to a real request on the
// vhost's public IP. The probe must therefore dial the vhost's serving IP.
func TestProbeHostPrefersServingIP(t *testing.T) {
	if got := probeHost(vhost{ip: "198.51.100.7"}); got != "198.51.100.7" {
		t.Errorf("probeHost with serving IP = %q, want 198.51.100.7", got)
	}
	if got := probeHost(vhost{ip: ""}); got != "127.0.0.1" {
		t.Errorf("probeHost without serving IP = %q, want loopback fallback", got)
	}
}

// A parked/IPv6/edge vhost whose serving IP failed to parse must still fall
// back to loopback rather than dialing an empty host.
func TestProbeHostBlankIPFallsBackToLoopback(t *testing.T) {
	if got := probeHost(vhost{domain: "example.com"}); got != "127.0.0.1" {
		t.Fatalf("probeHost = %q, want 127.0.0.1 fallback", got)
	}
}
