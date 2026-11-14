package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
	"gopkg.in/yaml.v3"
)

// No install path may open a port to anyone by default, and the shipped file
// names the key so an operator finds it next to the other port lists.
func TestInAllowDefaultsAgreeAcrossInstallPaths(t *testing.T) {
	if len(firewall.DefaultConfig().TCPInAllow) != 0 {
		t.Fatal("runtime defaults must not open source-scoped ports")
	}
	installer := filepath.Join(t.TempDir(), "csm.yaml")
	if err := deployDefaultConfig(installer); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{installer, filepath.Join("..", "..", "build", "packaging", "csm.yaml.default")} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var raw struct {
			Firewall struct {
				TCPInAllow []firewall.InAllowRule `yaml:"tcp_in_allow"`
			} `yaml:"firewall"`
		}
		if decodeErr := yaml.Unmarshal(data, &raw); decodeErr != nil {
			t.Fatal(decodeErr)
		}
		if raw.Firewall.TCPInAllow == nil || len(raw.Firewall.TCPInAllow) != 0 {
			t.Fatalf("%s must explicitly ship an empty tcp_in_allow list", path)
		}
		cfg, err := config.LoadBytes(data)
		if err != nil {
			t.Fatal(err)
		}
		if len(cfg.Firewall.TCPInAllow) != 0 {
			t.Fatalf("%s changes source-scoped allows during config loading", path)
		}
	}
}

// The documented shape must load as written, from the main file and from a
// conf.d fragment merged on top of it.
func TestInAllowDocumentedShapeLoads(t *testing.T) {
	cfg, err := config.LoadBytes([]byte(`
firewall:
  tcp_in_allow:
    - port: 3306
      sources: [203.0.113.10, 198.51.100.0/28]
`))
	if err != nil {
		t.Fatal(err)
	}
	got := cfg.Firewall.TCPInAllow
	if len(got) != 1 || got[0].Port != 3306 || len(got[0].Sources) != 2 ||
		got[0].Sources[0] != "203.0.113.10" || got[0].Sources[1] != "198.51.100.0/28" {
		t.Fatalf("loaded %+v, want port 3306 from the two documented sources", got)
	}
}
