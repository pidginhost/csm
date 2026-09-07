package checks

import (
	"net"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/netutil"
)

// cPanel's nginx front end proxies to Apache over the machine's own public
// address rather than loopback (upstream "<host_v4>:81" / ":444"), so every
// proxied request is a non-root user connecting to that address. The check
// already ignores loopback destinations for exactly this reason; a packet that
// never leaves the machine is not an outbound connection whichever local
// address it is addressed to.
//
// This matters beyond noise: user_outbound_connection maps to AttackC2 in the
// attack database, so the proxy hop scored the host as command-and-control
// traffic and drove its own address to a critical local threat score.
func TestEvaluateConnectionIgnoresHostOwnAddressDestination(t *testing.T) {
	t.Cleanup(netutil.SetHostAddressLookup(func() ([]net.IP, error) {
		return []net.IP{
			net.ParseIP("203.0.113.10"),
			net.ParseIP("2001:db8::1"),
		}, nil
	}))

	cfg := &config.Config{}

	for _, tc := range []struct {
		name string
		dst  string
		port uint16
	}{
		{"apache http backend", "203.0.113.10", 81},
		{"apache https backend", "203.0.113.10", 444},
		{"host IPv6 backend", "2001:db8::1", 81},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, report := EvaluateConnection(cfg, 1001, net.ParseIP(tc.dst), tc.port, 40000, "tcp", "someuser")
			if report {
				t.Errorf("connection to the host's own %s:%d reported as an unusual outbound destination", tc.dst, tc.port)
			}
		})
	}
}

// The guard must not blunt the check it exists inside: a genuinely external
// destination on the same port is still a compromised-account signal.
func TestEvaluateConnectionStillReportsExternalDestination(t *testing.T) {
	t.Cleanup(netutil.SetHostAddressLookup(func() ([]net.IP, error) {
		return []net.IP{net.ParseIP("203.0.113.10")}, nil
	}))

	cfg := &config.Config{}

	f, report := EvaluateConnection(cfg, 1001, net.ParseIP("198.51.100.7"), 81, 40000, "tcp", "someuser")
	if !report {
		t.Fatal("external destination on port 81 must still be reported")
	}
	if f.Check != "user_outbound_connection" {
		t.Errorf("check = %q, want user_outbound_connection", f.Check)
	}

	// A different host's address is not this host's address.
	if _, report := EvaluateConnection(cfg, 1001, net.ParseIP("203.0.113.11"), 444, 40000, "tcp", "someuser"); !report {
		t.Error("a neighbouring address must not inherit the host's exemption")
	}
}

// A failed interface enumeration must not suppress outbound reporting.
func TestEvaluateConnectionReportsWhenHostLookupFails(t *testing.T) {
	t.Cleanup(netutil.SetHostAddressLookup(func() ([]net.IP, error) {
		return nil, net.UnknownNetworkError("boom")
	}))

	if _, report := EvaluateConnection(&config.Config{}, 1001, net.ParseIP("198.51.100.7"), 81, 40000, "tcp", "someuser"); !report {
		t.Error("lookup failure must fail open and keep reporting")
	}
}
