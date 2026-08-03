package firewall

import "testing"

// The input chain accepts Cloudflare edges on 80/443 before the blocked-IP
// drop, so blocking a CF-range IP is a silent no-op on those ports. The
// cover check powers the operator warning at block time.
func TestCloudflareRangesCover(t *testing.T) {
	v4 := []string{"198.51.100.0/24"}
	v6 := []string{"2001:db8:100::/48"}
	cases := []struct {
		ip   string
		want bool
	}{
		{"198.51.100.7", true},
		{"::ffff:198.51.100.7", true},
		{"203.0.113.7", false},
		{"2001:db8:100::9", true},
		{"2001:db8:200::9", false},
		{"not-an-ip", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := CloudflareRangesCover(v4, v6, tc.ip); got != tc.want {
			t.Errorf("CloudflareRangesCover(%q) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

func TestCloudflareRangesCoverSkipsMalformedCIDRs(t *testing.T) {
	if !CloudflareRangesCover([]string{"garbage", "198.51.100.0/24"}, nil, "198.51.100.7") {
		t.Error("a malformed CIDR must not stop matching against the rest")
	}
	if CloudflareRangesCover([]string{"garbage"}, nil, "198.51.100.7") {
		t.Error("only-malformed ranges cannot cover anything")
	}
}

func TestCloudflareRangesCoverUsesMatchingFamilyList(t *testing.T) {
	if CloudflareRangesCover(nil, []string{"198.51.100.0/24"}, "198.51.100.7") {
		t.Error("IPv4 target matched a range stored in the IPv6 list")
	}
	if CloudflareRangesCover([]string{"2001:db8:100::/48"}, nil, "2001:db8:100::7") {
		t.Error("IPv6 target matched a range stored in the IPv4 list")
	}
}
