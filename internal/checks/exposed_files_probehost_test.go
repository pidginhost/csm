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
	if got := probeHost(vhost{ip: ""}); got != "" {
		t.Errorf("probeHost without serving IP = %q, want no probe target", got)
	}
}

// A missing or malformed serving address must not silently fall back to
// loopback or DNS. The caller skips the vhost and marks the scan incomplete.
func TestProbeHostRejectsUnusableAddresses(t *testing.T) {
	for _, ip := range []string{"", "origin.example", "127.0.0.1", "0.0.0.0", "[2001:db8::1]"} {
		if got := probeHost(vhost{domain: "example.com", ip: ip}); got != "" {
			t.Errorf("probeHost with %q = %q, want no probe target", ip, got)
		}
	}
}
