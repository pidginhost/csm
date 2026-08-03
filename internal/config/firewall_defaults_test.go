package config

import (
	"testing"

	"github.com/pidginhost/csm/internal/firewall"
)

// A partial firewall: block must not lose the unlisted defaults. Before
// per-field merging, "firewall:\n  enabled: true" produced an empty
// tcp_in/tcp_out on a DROP-policy chain - an instant lockout.
func TestPartialFirewallBlockKeepsDefaults(t *testing.T) {
	cfg, err := LoadBytes([]byte("firewall:\n  enabled: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	def := firewall.DefaultConfig()
	fc := cfg.Firewall
	if !fc.Enabled {
		t.Fatal("enabled lost")
	}
	if len(fc.TCPIn) == 0 || len(fc.TCPIn) != len(def.TCPIn) {
		t.Errorf("TCPIn = %v, want defaults %v", fc.TCPIn, def.TCPIn)
	}
	if len(fc.TCPOut) != len(def.TCPOut) {
		t.Errorf("TCPOut = %v, want defaults", fc.TCPOut)
	}
	if len(fc.UDPIn) != len(def.UDPIn) || len(fc.UDPOut) != len(def.UDPOut) {
		t.Errorf("UDP lists = %v/%v, want defaults", fc.UDPIn, fc.UDPOut)
	}
	if fc.ConnRateLimit != def.ConnRateLimit {
		t.Errorf("ConnRateLimit = %d, want %d", fc.ConnRateLimit, def.ConnRateLimit)
	}
	if !fc.SYNFloodProtection {
		t.Error("SYNFloodProtection default true lost")
	}
	if fc.ConnLimit != def.ConnLimit {
		t.Errorf("ConnLimit = %d, want %d", fc.ConnLimit, def.ConnLimit)
	}
	if len(fc.PortFlood) != len(def.PortFlood) {
		t.Errorf("PortFlood = %v, want defaults", fc.PortFlood)
	}
	if !fc.UDPFlood || fc.UDPFloodRate != def.UDPFloodRate || fc.UDPFloodBurst != def.UDPFloodBurst {
		t.Errorf("UDP flood = %v/%d/%d, want defaults", fc.UDPFlood, fc.UDPFloodRate, fc.UDPFloodBurst)
	}
	if len(fc.RestrictedTCP) != len(def.RestrictedTCP) {
		t.Errorf("RestrictedTCP = %v, want defaults", fc.RestrictedTCP)
	}
	if fc.PassiveFTPStart != def.PassiveFTPStart || fc.PassiveFTPEnd != def.PassiveFTPEnd {
		t.Errorf("passive FTP = %d-%d, want defaults", fc.PassiveFTPStart, fc.PassiveFTPEnd)
	}
	if len(fc.DropNoLog) != len(def.DropNoLog) {
		t.Errorf("DropNoLog = %v, want defaults", fc.DropNoLog)
	}
	if fc.DenyIPLimit != def.DenyIPLimit || fc.DenyTempIPLimit != def.DenyTempIPLimit {
		t.Errorf("deny limits = %d/%d, want defaults", fc.DenyIPLimit, fc.DenyTempIPLimit)
	}
	if len(fc.SMTPPorts) != len(def.SMTPPorts) {
		t.Errorf("SMTPPorts = %v, want defaults", fc.SMTPPorts)
	}
	if !fc.LogDropped || fc.LogRate != def.LogRate {
		t.Errorf("logging = %v/%d, want defaults", fc.LogDropped, fc.LogRate)
	}
}

// Explicit values - including empty lists, zeros, and false - must survive
// the per-field merge. An operator who writes tcp_in: [] means "no public
// ports", not "give me the defaults".
func TestPartialFirewallBlockKeepsExplicitValues(t *testing.T) {
	yaml := `firewall:
  enabled: true
  tcp_in: []
  syn_flood_protection: false
  udp_flood: false
  log_dropped: false
  conn_limit: 0
  deny_ip_limit: 0
  log_rate: 1
`
	cfg, err := LoadBytes([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	fc := cfg.Firewall
	if len(fc.TCPIn) != 0 {
		t.Errorf("explicit empty tcp_in overwritten: %v", fc.TCPIn)
	}
	if fc.SYNFloodProtection {
		t.Error("explicit syn_flood_protection: false overwritten")
	}
	if fc.UDPFlood {
		t.Error("explicit udp_flood: false overwritten")
	}
	if fc.LogDropped {
		t.Error("explicit log_dropped: false overwritten")
	}
	if fc.ConnLimit != 0 {
		t.Errorf("explicit conn_limit: 0 overwritten: %d", fc.ConnLimit)
	}
	if fc.DenyIPLimit != 0 {
		t.Errorf("explicit deny_ip_limit: 0 overwritten: %d", fc.DenyIPLimit)
	}
	if fc.LogRate != 1 {
		t.Errorf("explicit log_rate: 1 overwritten: %d", fc.LogRate)
	}
	// Unlisted keys still get defaults.
	def := firewall.DefaultConfig()
	if len(fc.TCPOut) != len(def.TCPOut) {
		t.Errorf("TCPOut = %v, want defaults", fc.TCPOut)
	}
}

// A missing firewall: block keeps the full DefaultConfig behaviour.
func TestMissingFirewallBlockGetsFullDefaults(t *testing.T) {
	cfg, err := LoadBytes([]byte("hostname: x\n"))
	if err != nil {
		t.Fatal(err)
	}
	def := firewall.DefaultConfig()
	if cfg.Firewall == nil || len(cfg.Firewall.TCPIn) != len(def.TCPIn) {
		t.Fatalf("nil firewall block should get DefaultConfig, got %+v", cfg.Firewall)
	}
	if cfg.Firewall.Enabled {
		t.Error("firewall must default to disabled")
	}
}
