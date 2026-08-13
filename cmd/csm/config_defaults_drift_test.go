package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
)

// loadInstallerTemplate renders the installer's built-in config to disk and
// parses it, which is the only way to read that template -- it is an inline
// literal inside deployDefaultConfig, not an exported var.
func loadInstallerTemplate(t *testing.T) *config.Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "csm.yaml")
	if err := deployDefaultConfig(path); err != nil {
		t.Fatalf("deployDefaultConfig: %v", err)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- test-owned temp path
	if err != nil {
		t.Fatalf("read rendered template: %v", err)
	}
	cfg, err := config.LoadBytes(data)
	if err != nil {
		t.Fatalf("parse rendered template: %v", err)
	}
	return cfg
}

func loadPackagedDefault(t *testing.T) *config.Config {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "build", "packaging", "csm.yaml.default"))
	if err != nil {
		t.Fatalf("read packaged default: %v", err)
	}
	cfg, err := config.LoadBytes(data)
	if err != nil {
		t.Fatalf("parse packaged default: %v", err)
	}
	return cfg
}

func samePorts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// E2: firewall defaults live in three places -- firewall.DefaultConfig, the
// installer template, and the packaged YAML. restricted_tcp had drifted: the
// runtime default protects the Web UI port but neither shipped file listed it,
// so a fresh install exposed 9443 to the internet while the documented default
// says it is infra-only.
func TestRestrictedTCPDefaultsAgreeAcrossAllThreeSources(t *testing.T) {
	want := firewall.DefaultConfig().RestrictedTCP

	installer := loadInstallerTemplate(t)
	if !samePorts(installer.Firewall.RestrictedTCP, want) {
		t.Errorf("installer template restricted_tcp = %v, want runtime default %v", installer.Firewall.RestrictedTCP, want)
	}

	packaged := loadPackagedDefault(t)
	if !samePorts(packaged.Firewall.RestrictedTCP, want) {
		t.Errorf("packaged default restricted_tcp = %v, want runtime default %v", packaged.Firewall.RestrictedTCP, want)
	}
}

// The Web UI port is the one that matters most: leaving it out of
// restricted_tcp publishes the management panel to the whole internet.
func TestShippedDefaultsRestrictWebUIPort(t *testing.T) {
	const webUIPort = 9443

	for _, tc := range []struct {
		name string
		cfg  *config.Config
	}{
		{"installer template", loadInstallerTemplate(t)},
		{"packaged default", loadPackagedDefault(t)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			found := false
			for _, p := range tc.cfg.Firewall.RestrictedTCP {
				if p == webUIPort {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("restricted_tcp = %v, missing web UI port %d", tc.cfg.Firewall.RestrictedTCP, webUIPort)
			}
		})
	}
}
