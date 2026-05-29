package webui

import "testing"

func TestClientIPKey(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"ipv4 with port", "1.2.3.4:5678", "1.2.3.4"},
		{"bracketed ipv6 with port", "[2001:db8::1]:443", "2001:db8::1"},
		{"bracketed loopback ipv6", "[::1]:80", "::1"},
		{"no port falls back", "1.2.3.4", "1.2.3.4"},
		{"empty", "", ""},
	}
	for _, c := range cases {
		if got := clientIPKey(c.in); got != c.want {
			t.Errorf("%s: clientIPKey(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
}

// TestClientIPKeyIPv6NotCollapsed guards the rate-limit key: distinct IPv6
// clients must map to distinct keys, not a shared bucket.
func TestClientIPKeyIPv6NotCollapsed(t *testing.T) {
	a := clientIPKey("[2001:db8::1]:443")
	b := clientIPKey("[2001:db8::2]:443")
	if a == b {
		t.Errorf("distinct IPv6 clients collapsed to one key: %q == %q", a, b)
	}
}
