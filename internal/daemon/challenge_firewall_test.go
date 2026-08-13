package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
)

func TestEffectiveFirewallConfigAddsPublicChallengePort(t *testing.T) {
	cfg := &config.Config{}
	cfg.Challenge.Enabled = true
	cfg.Challenge.PortGate.Enabled = true
	cfg.Challenge.ListenAddr = "0.0.0.0"
	cfg.Challenge.ListenPort = 8439
	cfg.Firewall = &firewall.FirewallConfig{
		TCPIn:         []int{80, 443},
		RestrictedTCP: []int{8439, 9443},
	}

	fw := config.EffectiveFirewallConfig(cfg)

	if !hasPort(fw.TCPIn, 8439) {
		t.Fatalf("challenge listen port not added to TCPIn: %#v", fw.TCPIn)
	}
	if hasPort(fw.RestrictedTCP, 8439) {
		t.Fatalf("challenge listen port still restricted: %#v", fw.RestrictedTCP)
	}
	if hasPort(cfg.Firewall.TCPIn, 8439) || !hasPort(cfg.Firewall.RestrictedTCP, 8439) {
		t.Fatalf("source firewall config was mutated: %+v", cfg.Firewall)
	}
}

func TestEffectiveFirewallConfigSkipsLoopbackChallengePort(t *testing.T) {
	cfg := &config.Config{}
	cfg.Challenge.Enabled = true
	cfg.Challenge.PortGate.Enabled = true
	cfg.Challenge.ListenAddr = "127.0.0.1"
	cfg.Challenge.ListenPort = 8439
	cfg.Firewall = &firewall.FirewallConfig{TCPIn: []int{80, 443}}

	fw := config.EffectiveFirewallConfig(cfg)

	if hasPort(fw.TCPIn, 8439) {
		t.Fatalf("loopback challenge port was added to TCPIn: %#v", fw.TCPIn)
	}
}

func TestEffectiveFirewallConfigDoesNotDuplicateChallengePort(t *testing.T) {
	cfg := &config.Config{}
	cfg.Challenge.Enabled = true
	cfg.Challenge.PortGate.Enabled = true
	cfg.Challenge.ListenAddr = ":8439"
	cfg.Challenge.ListenPort = 8439
	cfg.Firewall = &firewall.FirewallConfig{TCPIn: []int{80, 8439}}

	fw := config.EffectiveFirewallConfig(cfg)

	count := 0
	for _, port := range fw.TCPIn {
		if port == 8439 {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("challenge listen port count = %d, want 1 in %#v", count, fw.TCPIn)
	}
}

func hasPort(ports []int, want int) bool {
	for _, port := range ports {
		if port == want {
			return true
		}
	}
	return false
}
