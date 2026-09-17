package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
	"gopkg.in/yaml.v3"
)

func TestOutAllowDefaultsAgreeAcrossInstallPaths(t *testing.T) {
	if len(firewall.DefaultConfig().TCPOutAllow) != 0 {
		t.Fatal("runtime defaults must not open destination-scoped egress")
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
				TCPOutAllow []firewall.OutAllowRule `yaml:"tcp_out_allow"`
			} `yaml:"firewall"`
		}
		if decodeErr := yaml.Unmarshal(data, &raw); decodeErr != nil {
			t.Fatal(decodeErr)
		}
		if raw.Firewall.TCPOutAllow == nil || len(raw.Firewall.TCPOutAllow) != 0 {
			t.Fatalf("%s must explicitly ship an empty tcp_out_allow list", path)
		}
		cfg, err := config.LoadBytes(data)
		if err != nil {
			t.Fatal(err)
		}
		if len(cfg.Firewall.TCPOutAllow) != 0 {
			t.Fatalf("%s changes outbound allows during config loading", path)
		}
	}
}
