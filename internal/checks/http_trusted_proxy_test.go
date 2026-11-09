package checks

import "testing"

func TestIsTrustedProxyRejectsUntrustedAddresses(t *testing.T) {
	proxies := []string{"", "not-an-address", "203.0.113.0/28", "2001:db8::10"}
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
			if IsTrustedProxy(addr, proxies) {
				t.Fatalf("untrusted or malformed address %q matched a trusted proxy", addr)
			}
		})
	}
}
