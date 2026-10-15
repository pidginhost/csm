package daemon

import (
	"net"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
)

func TestCentralFirebreakTranslatedInfra(t *testing.T) {
	// Treat documentation IPv4 as public within this test so each assertion
	// exercises infra protection rather than the documentation guard.
	saved := documentationNets
	documentationNets = nil
	t.Cleanup(func() { documentationNets = saved })
	ipv4 := net.ParseIP("192.0.2.1").To4()
	for _, tc := range []struct {
		name   string
		prefix *net.IPNet
		offset int
	}{
		{"nat64", nat64Net, 12},
		{"6to4", sixToFourNet, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ip := append(net.IP(nil), tc.prefix.IP.To16()...)
			copy(ip[tc.offset:tc.offset+4], ipv4)
			if New(&config.Config{}, nil, nil, "").centralFirebreak()(ip.String()) {
				t.Fatal("unprotected translated fixture must be reportable")
			}
			for _, entry := range []string{ip.String(), tc.prefix.String(), ipv4.String()} {
				for _, firewallOnly := range []bool{false, true} {
					cfg := &config.Config{}
					if firewallOnly {
						cfg.Firewall = &firewall.FirewallConfig{InfraIPs: []string{entry}}
					} else {
						cfg.InfraIPs = []string{entry}
					}
					if !New(cfg, nil, nil, "").centralFirebreak()(ip.String()) {
						t.Errorf("translated source bypassed infra entry %s (firewall=%v)", entry, firewallOnly)
					}
				}
			}
		})
	}
}
