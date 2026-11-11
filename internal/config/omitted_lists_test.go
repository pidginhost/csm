package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

var (
	packagedBackdoorPorts  = []int{4444, 5555, 55553, 55555, 31337}
	packagedSMTPAllowUsers = []string{"cpanel", "mailman"}
)

// A config that leaves out the backdoor port list or the SMTP sender allow
// list gets the packaged lists; an explicit empty list still means none.
func TestOmittedListsGetPackagedValues(t *testing.T) {
	for _, tt := range []struct {
		name      string
		yaml      string
		backdoor  []int
		smtpUsers []string
	}{
		{"absent", "hostname: host.example\n", packagedBackdoorPorts, packagedSMTPAllowUsers},
		{"absent in a partial firewall block", "firewall:\n  smtp_block: true\n", packagedBackdoorPorts, packagedSMTPAllowUsers},
		{"null", "backdoor_ports:\nfirewall:\n  smtp_allow_users:\n", packagedBackdoorPorts, packagedSMTPAllowUsers},
		{"explicit empty", "backdoor_ports: []\nfirewall:\n  smtp_allow_users: []\n", []int{}, []string{}},
		{"explicit list", "backdoor_ports: [1234]\nfirewall:\n  smtp_allow_users: [alice]\n", []int{1234}, []string{"alice"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := LoadBytes([]byte(tt.yaml))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(cfg.BackdoorPorts, tt.backdoor) {
				t.Errorf("backdoor_ports = %#v, want %#v", cfg.BackdoorPorts, tt.backdoor)
			}
			if !reflect.DeepEqual(cfg.Firewall.SMTPAllowUsers, tt.smtpUsers) {
				t.Errorf("smtp_allow_users = %#v, want %#v", cfg.Firewall.SMTPAllowUsers, tt.smtpUsers)
			}
		})
	}
}

// A reload reads the file again through the same path, so both meanings
// survive it, including a key moved into a conf.d fragment.
func TestOmittedListsSurviveReload(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "csm.yaml")
	confd := filepath.Join(dir, "conf.d")
	if err := os.Mkdir(confd, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(path, body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	load := func() *Config {
		t.Helper()
		cfg, err := LoadWithDir(main, confd)
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}

	write(main, "hostname: host.example\n")
	first := load()
	if !reflect.DeepEqual(first.BackdoorPorts, packagedBackdoorPorts) ||
		!reflect.DeepEqual(first.Firewall.SMTPAllowUsers, packagedSMTPAllowUsers) {
		t.Fatalf("absent: backdoor_ports = %#v, smtp_allow_users = %#v", first.BackdoorPorts, first.Firewall.SMTPAllowUsers)
	}

	write(filepath.Join(confd, "10-lists.yaml"), "backdoor_ports: []\nfirewall:\n  smtp_allow_users: []\n")
	second := load()
	if len(second.BackdoorPorts) != 0 || len(second.Firewall.SMTPAllowUsers) != 0 {
		t.Fatalf("explicit empty after reload: backdoor_ports = %#v, smtp_allow_users = %#v", second.BackdoorPorts, second.Firewall.SMTPAllowUsers)
	}

	if err := os.Remove(filepath.Join(confd, "10-lists.yaml")); err != nil {
		t.Fatal(err)
	}
	third := load()
	if !reflect.DeepEqual(third.BackdoorPorts, packagedBackdoorPorts) ||
		!reflect.DeepEqual(third.Firewall.SMTPAllowUsers, packagedSMTPAllowUsers) {
		t.Fatalf("absent again: backdoor_ports = %#v, smtp_allow_users = %#v", third.BackdoorPorts, third.Firewall.SMTPAllowUsers)
	}
}
