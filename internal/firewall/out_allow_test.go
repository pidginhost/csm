package firewall

import (
	"bytes"
	"net"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestParseOutAllowDstNormalizesFamily(t *testing.T) {
	for _, tc := range []struct {
		dst, want string
		bytes     int
	}{
		{"0.0.0.0/0", "0.0.0.0/0", 4},
		{"::/0", "::/0", 16},
		{"203.0.113.155", "203.0.113.155/32", 4},
		{"2001:db8::1", "2001:db8::1/128", 16},
		{"::ffff:203.0.113.155", "203.0.113.155/32", 4},
		{"::ffff:203.0.113.155/120", "203.0.113.0/24", 4},
		{"::ffff:203.0.113.155/96", "0.0.0.0/0", 4},
		{"::ffff:203.0.113.155/128", "203.0.113.155/32", 4},
	} {
		t.Run(tc.dst, func(t *testing.T) {
			got, err := ParseOutAllowDst(tc.dst)
			if err != nil {
				t.Fatal(err)
			}
			_, want, err := net.ParseCIDR(tc.want)
			if err != nil {
				t.Fatal(err)
			}
			if !got.IP.Equal(want.IP) || !bytes.Equal(got.Mask, want.Mask) {
				t.Errorf("network bytes = %v/%v, want %v/%v", []byte(got.IP), []byte(got.Mask), []byte(want.IP), []byte(want.Mask))
			}
			if (got.IP.To4() != nil) != (tc.bytes == 4) || len(got.IP) != tc.bytes || len(got.Mask) != tc.bytes {
				t.Errorf("address family/width mismatch: IP=%v mask=%v, want %d bytes", []byte(got.IP), []byte(got.Mask), tc.bytes)
			}
		})
	}
}

// tcp_out_allow exists because tcp_out is []int and cannot express a port
// range: a range literal there fails the whole merged config decode. The
// range surviving a round-trip here is the entire reason for the key.
func TestTCPOutAllowParsesRange(t *testing.T) {
	const src = `
tcp_out_allow:
  - dst: 203.0.113.155/32
    port_start: 49152
    port_end: 65534
`
	var fc FirewallConfig
	if err := yaml.Unmarshal([]byte(src), &fc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(fc.TCPOutAllow) != 1 {
		t.Fatalf("want 1 rule, got %d", len(fc.TCPOutAllow))
	}
	got := fc.TCPOutAllow[0]
	want := OutAllowRule{Dst: "203.0.113.155/32", PortStart: 49152, PortEnd: 65534}
	if got != want {
		t.Errorf("round-trip lost data: got %+v want %+v", got, want)
	}
}
