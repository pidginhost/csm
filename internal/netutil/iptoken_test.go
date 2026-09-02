package netutil

import "testing"

// Four log/message extractors trimmed a punctuation set that contained ':'
// from the end of an address token, which cut the trailing "::" off IPv6
// addresses; none re-validated the remnant, so the mangled address was
// looked up (burning reputation quota) and could never be blocked.
func TestParseIPToken(t *testing.T) {
	cases := []struct {
		token string
		want  string
		ok    bool
	}{
		{"2a01:4f8:1c17:abcd::,", "2a01:4f8:1c17:abcd::", true},
		{"2a01:4f8:1c17:abcd::", "2a01:4f8:1c17:abcd::", true},
		{"203.0.113.5:", "203.0.113.5", true},
		{"[203.0.113.5]", "203.0.113.5", true},
		{"2001:DB8::1:", "2001:db8::1", true},
		{"(203.0.113.5),", "203.0.113.5", true},
		{"203.0.113.5:8080", "203.0.113.5", true},
		{"[2001:DB8::1]:443", "2001:db8::1", true},
		{"[2001:db8::1]:443,", "2001:db8::1", true},
		{"\"[2001:db8::1]\"", "2001:db8::1", true},
		{"2001:db8::1.", "2001:db8::1", true},
		{"garbage", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		got, ok := ParseIPToken(c.token)
		if ok != c.ok || got != c.want {
			t.Errorf("ParseIPToken(%q) = %q, %v; want %q, %v", c.token, got, ok, c.want, c.ok)
		}
	}
}
