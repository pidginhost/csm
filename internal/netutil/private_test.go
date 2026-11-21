package netutil

import "testing"

// One answer for every caller: whether the address is private or loopback,
// and whether it parsed at all, so each caller states what an unparsable
// address means for it.
func TestPrivateOrLoopbackReportsValidity(t *testing.T) {
	for _, tc := range []struct {
		ip             string
		private, valid bool
	}{
		{"127.0.0.1", true, true},
		{"::1", true, true},
		{"10.0.0.1", true, true},
		{"172.16.0.1", true, true},
		{"192.168.1.1", true, true},
		{"fd00::1", true, true},
		{"::ffff:10.0.0.1", true, true},
		{"172.15.255.255", false, true},
		{"172.32.0.1", false, true},
		{"203.0.113.5", false, true},
		{"2001:db8::1", false, true},
		{"", false, false},
		{"invalid", false, false},
		{"fe80::1%eth0", false, false},
	} {
		if private, valid := PrivateOrLoopback(tc.ip); private != tc.private || valid != tc.valid {
			t.Errorf("PrivateOrLoopback(%q) = %v, %v; want %v, %v", tc.ip, private, valid, tc.private, tc.valid)
		}
	}
}
