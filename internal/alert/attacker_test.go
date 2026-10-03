package alert

import "testing"

// A subnet spray names its subnet in CIDRs; every other finding, and a spray
// without exactly one CIDR, names none.
func TestSubnetSprayCIDR(t *testing.T) {
	for _, c := range []struct {
		name string
		f    Finding
		want string
	}{
		{"mail spray", Finding{Check: "mail_subnet_spray", CIDRs: []string{"203.0.113.0/24"}}, "203.0.113.0/24"},
		{"smtp spray", Finding{Check: "smtp_subnet_spray", CIDRs: []string{"198.51.100.0/24"}}, "198.51.100.0/24"},
		{"spray without a subnet", Finding{Check: "mail_subnet_spray"}, ""},
		{"spray with two subnets", Finding{Check: "smtp_subnet_spray", CIDRs: []string{"192.0.2.0/24", "203.0.113.0/24"}}, ""},
		{"crawl subnets", Finding{Check: "http_asn_crawl", CIDRs: []string{"192.0.2.0/24"}}, ""},
	} {
		if got := SubnetSprayCIDR(c.f); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

// The attacker address is SourceIP when set, so a spray parked by an older
// daemon with its subnet in SourceIP reads the same as a new one.
func TestAttackerAddress(t *testing.T) {
	for _, c := range []struct {
		name string
		f    Finding
		want string
	}{
		{"address", Finding{Check: "mail_bruteforce", SourceIP: "192.0.2.5"}, "192.0.2.5"},
		{"structured spray", Finding{Check: "mail_subnet_spray", CIDRs: []string{"203.0.113.0/24"}}, "203.0.113.0/24"},
		{"older spray", Finding{Check: "smtp_subnet_spray", SourceIP: "198.51.100.0/24"}, "198.51.100.0/24"},
		{"SourceIP first", Finding{Check: "mail_subnet_spray", SourceIP: "198.51.100.0/24", CIDRs: []string{"203.0.113.0/24"}}, "198.51.100.0/24"},
		{"crawl", Finding{Check: "http_asn_crawl", CIDRs: []string{"192.0.2.0/24"}}, ""},
	} {
		if got := AttackerAddress(c.f); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}
