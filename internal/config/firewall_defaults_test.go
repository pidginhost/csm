package config

import (
	"os"
	"path/filepath"
	"reflect"
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
	want := firewall.DefaultConfig()
	want.Enabled = true
	if !reflect.DeepEqual(cfg.Firewall, want) {
		t.Errorf("firewall = %#v, want %#v", cfg.Firewall, want)
	}
}

// Explicit values - including empty lists, zeros, and false - must survive
// the per-field merge. An operator who writes tcp_in: [] means "no public
// ports", not "give me the defaults".
func TestPartialFirewallBlockKeepsExplicitValues(t *testing.T) {
	yaml := `firewall:
  enabled: true
  tcp_in: []
  tcp_out: []
  udp_in: []
  udp_out: []
  restricted_tcp: []
  passive_ftp_start: 0
  passive_ftp_end: 0
  conn_rate_limit: 0
  syn_flood_protection: false
  conn_limit: 0
  port_flood: []
  udp_flood: false
  udp_flood_rate: 0
  udp_flood_burst: 0
  drop_nolog: []
  deny_ip_limit: 0
  deny_temp_ip_limit: 0
  smtp_ports: []
  log_dropped: false
  log_rate: 0
`
	cfg, err := LoadBytes([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	want := &firewall.FirewallConfig{
		Enabled:       true,
		TCPIn:         []int{},
		TCPOut:        []int{},
		UDPIn:         []int{},
		UDPOut:        []int{},
		RestrictedTCP: []int{},
		PortFlood:     []firewall.PortFloodRule{},
		DropNoLog:     []int{},
		SMTPPorts:     []int{},
	}
	if !reflect.DeepEqual(cfg.Firewall, want) {
		t.Errorf("firewall = %#v, want %#v", cfg.Firewall, want)
	}
}

// A missing firewall: block keeps the full DefaultConfig behaviour.
func TestMissingFirewallBlockGetsFullDefaults(t *testing.T) {
	cfg, err := LoadBytes([]byte("hostname: x\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := firewall.DefaultConfig()
	if !reflect.DeepEqual(cfg.Firewall, want) {
		t.Fatalf("firewall = %#v, want %#v", cfg.Firewall, want)
	}
}

func TestNullFirewallBlockGetsFullDefaults(t *testing.T) {
	for _, body := range []string{"firewall:\n", "firewall: null\n", "firewall: ~\n"} {
		cfg, err := LoadBytes([]byte(body))
		if err != nil {
			t.Fatalf("LoadBytes(%q): %v", body, err)
		}
		want := firewall.DefaultConfig()
		if !reflect.DeepEqual(cfg.Firewall, want) {
			t.Errorf("LoadBytes(%q) firewall = %#v, want %#v", body, cfg.Firewall, want)
		}
	}
}

func TestFirewallPresenceSupportsFlowStyleAndAliases(t *testing.T) {
	tests := map[string]string{
		"top-level alias": `<<: &base
  firewall: &policy {enabled: true, tcp_in: &empty [], tcp_out: *empty, syn_flood_protection: false, conn_limit: 0, log_rate: 0}
firewall: *policy
`,
		"nested flow merge": `firewall:
  <<: &policy {enabled: true, tcp_in: [], tcp_out: [], syn_flood_protection: false, conn_limit: 0, log_rate: 0}
`,
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			cfg, err := LoadBytes([]byte(body))
			if err != nil {
				t.Fatal(err)
			}
			want := firewall.DefaultConfig()
			want.Enabled = true
			want.TCPIn = []int{}
			want.TCPOut = []int{}
			want.SYNFloodProtection = false
			want.ConnLimit = 0
			want.LogRate = 0
			if !reflect.DeepEqual(cfg.Firewall, want) {
				t.Errorf("firewall = %#v, want %#v", cfg.Firewall, want)
			}
		})
	}
}

func TestFirewallPresenceIncludesAliasedDropInKeys(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "csm.yaml")
	confd := filepath.Join(dir, "conf.d")
	if err := os.Mkdir(confd, 0o755); err != nil {
		t.Fatal(err)
	}
	// Reverse the fragment's anchor/alias key order in the base. Aliases must be
	// resolved before DeepMerge or the merged YAML contains a forward alias.
	mainYAML := "hostname: 2026-08-03\nfirewall:\n  log_rate: &base_rate 5\n  conn_limit: *base_rate\n"
	if err := os.WriteFile(main, []byte(mainYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	fragment := `firewall: {enabled: true, tcp_in: &empty [], tcp_out: *empty, syn_flood_protection: false, conn_limit: &zero 0, log_rate: *zero}
`
	if err := os.WriteFile(filepath.Join(confd, "10-firewall.yaml"), []byte(fragment), 0o600); err != nil {
		t.Fatal(err)
	}

	first, err := LoadWithDir(main, confd)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadWithDir(main, confd)
	if err != nil {
		t.Fatal(err)
	}
	want := firewall.DefaultConfig()
	want.Enabled = true
	want.TCPIn = []int{}
	want.TCPOut = []int{}
	want.SYNFloodProtection = false
	want.ConnLimit = 0
	want.LogRate = 0
	if !reflect.DeepEqual(first.Firewall, want) {
		t.Errorf("firewall = %#v, want %#v", first.Firewall, want)
	}
	if first.Hostname != "2026-08-03" {
		t.Errorf("hostname = %q, want date-like string preserved verbatim", first.Hostname)
	}
	if !reflect.DeepEqual(first, second) {
		t.Errorf("repeated LoadWithDir changed defaults: first=%#v second=%#v", first.Firewall, second.Firewall)
	}
}

func TestFirewallPresenceIncludesEveryDropInKey(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "csm.yaml")
	confd := filepath.Join(dir, "conf.d")
	if err := os.Mkdir(confd, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(main, []byte("hostname: host.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fragment := `firewall: {enabled: true, tcp_in: [], tcp_out: [], udp_in: [], udp_out: [], restricted_tcp: [], passive_ftp_start: 0, passive_ftp_end: 0, conn_rate_limit: 0, syn_flood_protection: false, conn_limit: 0, port_flood: [], udp_flood: false, udp_flood_rate: 0, udp_flood_burst: 0, drop_nolog: [], deny_ip_limit: 0, deny_temp_ip_limit: 0, smtp_ports: [], log_dropped: false, log_rate: 0}
`
	if err := os.WriteFile(filepath.Join(confd, "10-firewall.yaml"), []byte(fragment), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadWithDir(main, confd)
	if err != nil {
		t.Fatal(err)
	}
	want := &firewall.FirewallConfig{
		Enabled:       true,
		TCPIn:         []int{},
		TCPOut:        []int{},
		UDPIn:         []int{},
		UDPOut:        []int{},
		RestrictedTCP: []int{},
		PortFlood:     []firewall.PortFloodRule{},
		DropNoLog:     []int{},
		SMTPPorts:     []int{},
	}
	if !reflect.DeepEqual(cfg.Firewall, want) {
		t.Errorf("firewall = %#v, want %#v", cfg.Firewall, want)
	}
}
