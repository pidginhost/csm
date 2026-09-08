package firewall

import (
	"testing"

	"gopkg.in/yaml.v3"
)

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
