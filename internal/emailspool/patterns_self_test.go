package emailspool

import (
	"net"
	"testing"
)

func TestIsProxyIPTreatsLoopbackAsSelf(t *testing.T) {
	p := &Policies{}
	cases := []string{"127.0.0.1", "127.0.0.5", "::1"}
	for _, ip := range cases {
		if !p.IsProxyIP(ip) {
			t.Errorf("loopback %q must be treated as self/proxy", ip)
		}
	}
}

func TestRefreshSelfIPsPicksUpHostAddresses(t *testing.T) {
	old := hostIPsFunc
	hostIPsFunc = func() []net.IP {
		return []net.IP{
			net.ParseIP("176.124.111.130"),
			net.ParseIP("176.124.111.131"),
			net.ParseIP("2001:67c:744:5::2"),
		}
	}
	t.Cleanup(func() { hostIPsFunc = old })

	p := &Policies{}
	p.RefreshSelfIPs()

	for _, ip := range []string{"176.124.111.130", "176.124.111.131", "2001:67c:744:5::2"} {
		if !p.IsProxyIP(ip) {
			t.Errorf("self IP %q must be treated as proxy after RefreshSelfIPs", ip)
		}
	}
	if p.IsProxyIP("8.8.8.8") {
		t.Error("external IP must not be treated as self/proxy")
	}
}

func TestRefreshSelfIPsReplacesPreviousSet(t *testing.T) {
	old := hostIPsFunc
	hostIPsFunc = func() []net.IP { return []net.IP{net.ParseIP("10.0.0.1")} }
	t.Cleanup(func() { hostIPsFunc = old })

	p := &Policies{}
	p.RefreshSelfIPs()
	if !p.IsProxyIP("10.0.0.1") {
		t.Fatal("initial self IP must be active")
	}

	hostIPsFunc = func() []net.IP { return []net.IP{net.ParseIP("10.0.0.2")} }
	p.RefreshSelfIPs()
	if p.IsProxyIP("10.0.0.1") {
		t.Error("stale self IP must be dropped after refresh")
	}
	if !p.IsProxyIP("10.0.0.2") {
		t.Error("new self IP must be active after refresh")
	}
}

func TestIsProxyIPSelfDoesNotShadowConfiguredCIDR(t *testing.T) {
	old := hostIPsFunc
	hostIPsFunc = func() []net.IP { return nil }
	t.Cleanup(func() { hostIPsFunc = old })

	_, n, _ := net.ParseCIDR("173.245.48.0/20")
	p := &Policies{proxyNets: []*net.IPNet{n}}
	p.RefreshSelfIPs()
	if !p.IsProxyIP("173.245.48.10") {
		t.Error("operator-configured proxy CIDR must still match after self refresh")
	}
}
