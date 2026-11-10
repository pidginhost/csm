package checks

import (
	"errors"
	"net"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/netutil"
)

func TestIsTrustedProxyRejectsUntrustedAddresses(t *testing.T) {
	// Config load refuses unreadable entries; see
	// config.TestLoadRejectsInvalidTrustedProxies.
	cfg := &config.Config{}
	cfg.WebServer.TrustedProxies = []string{"203.0.113.0/28", "2001:db8::10"}
	for _, addr := range []string{
		"",
		"198.51.100.7",
		"::ffff:198.51.100.7",
		"203.0.113.16",
		"2001:db8::11",
		"not-an-address",
		"203.0.113.5suffix",
		"198.51.100.7,203.0.113.5",
		"203.0.113.5,198.51.100.7",
		"198.51.100.7 203.0.113.5",
		"203.0.113.5\t198.51.100.7",
		"198.51.100.7%203.0.113.5",
		"2001:db8::11%2001:db8::10",
		"2001:db8::10%eth0",
		"::ffff:203.0.113.5%eth0",
		"203.0.113.5:443",
		"[2001:db8::10]:443",
		"[2001:db8::10]",
		"203.0.113.5/32",
		"203.000.113.5",
		`"203.0.113.5"`,
		"203.0.113.5\x00",
		" \t198.51.100.7\r\n",
	} {
		t.Run(addr, func(t *testing.T) {
			if IsTrustedProxy(addr, cfg) {
				t.Fatalf("untrusted or malformed address %q matched a trusted proxy", addr)
			}
		})
	}
}

// web_server.trusted_proxies and challenge.trusted_proxies are one list. A
// listed address stands for its visitors even where its header is not
// trusted: an address of this host, or any while the host's interfaces
// cannot be read.
func TestIsTrustedProxyReadsTheOneList(t *testing.T) {
	cfg := &config.Config{}
	cfg.WebServer.TrustedProxies = []string{"203.0.113.0/28", "127.0.0.1"}
	cfg.Challenge.TrustedProxies = []string{"2001:db8::10"}
	listed := []string{"203.0.113.5", "::ffff:203.0.113.5", " 203.0.113.5 ", "2001:db8::10", "127.0.0.1"}
	for _, addr := range listed {
		if !IsTrustedProxy(addr, cfg) {
			t.Errorf("IsTrustedProxy(%q) = false, want true", addr)
		}
	}
	t.Cleanup(netutil.SetHostAddressLookup(func() ([]net.IP, error) { return nil, errors.New("no interface list") }))
	for _, addr := range listed {
		if !IsTrustedProxy(addr, cfg) {
			t.Errorf("unread interface set: IsTrustedProxy(%q) = false, want true", addr)
		}
	}
	if IsTrustedProxy("198.51.100.7", cfg) || IsTrustedProxy("198.51.100.7", nil) {
		t.Error("an unlisted address is a trusted proxy")
	}
}
