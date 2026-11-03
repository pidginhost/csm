package sharedsenders

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/mailranges"
)

func TestProviderPrefix(t *testing.T) {
	policies := allProviders(map[string]mailranges.Policy{
		"google": {Nets: []*net.IPNet{mustNet(t, "203.0.113.0/24"), mustNet(t, "2001:db8::/32")}},
	})
	for _, tc := range []struct {
		name string
		g    *Guard
		now  time.Time
	}{
		{"ready", NewForTest(policies, testNow), testNow},
		{"missing", New(""), testNow},
		{"partial", NewForTest(map[string]mailranges.Policy{"google": policies["google"]}, testNow), testNow},
		{"expired", NewForTest(policies, testNow), testNow.Add(maxAge + time.Nanosecond)},
		{"future", NewForTest(policies, testNow.Add(time.Second)), testNow},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, ip := range []netip.Addr{
				netip.MustParseAddr("203.0.113.9"),
				netip.MustParseAddr("::ffff:203.0.113.9"),
				netip.MustParseAddr("2001:db8::9"),
			} {
				if got, want := tc.g.ProviderPrefix(ip, tc.now), tc.name == "ready"; got != want {
					t.Errorf("ProviderPrefix(%s) = %v, want %v", ip, got, want)
				}
			}
			for _, ip := range []netip.Addr{netip.MustParseAddr("198.51.100.7"), {}} {
				if tc.g.ProviderPrefix(ip, tc.now) {
					t.Errorf("ProviderPrefix(%s) = true for an unknown sender", ip)
				}
			}
		})
	}
}
