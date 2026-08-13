package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
	"gopkg.in/yaml.v3"
)

type firewallReference struct {
	Firewall struct {
		RestrictedTCP []int `yaml:"restricted_tcp"`
	} `yaml:"firewall"`
}

// loadInstallerTemplate renders the installer's built-in config to disk and
// parses it, which is the only way to read that template -- it is an inline
// literal inside deployDefaultConfig, not an exported var.
func loadInstallerTemplate(t *testing.T) []int {
	t.Helper()
	path := filepath.Join(t.TempDir(), "csm.yaml")
	if err := deployDefaultConfig(path); err != nil {
		t.Fatalf("deployDefaultConfig: %v", err)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- test-owned temp path
	if err != nil {
		t.Fatalf("read rendered template: %v", err)
	}
	return loadRestrictedTCP(t, "rendered installer template", data)
}

func loadPackagedDefault(t *testing.T) []int {
	t.Helper()
	return loadConfigFile(t, filepath.Join("..", "..", "build", "packaging", "csm.yaml.default"))
}

func loadProductionReference(t *testing.T) []int {
	t.Helper()
	return loadConfigFile(t, filepath.Join("..", "..", "configs", "csm.yaml.production.example"))
}

func loadConfigFile(t *testing.T, path string) []int {
	t.Helper()
	data, err := os.ReadFile(path) // #nosec G304 -- repository-owned test fixture path
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return loadRestrictedTCP(t, path, data)
}

func loadDocumentedReference(t *testing.T) []int {
	t.Helper()
	path := filepath.Join("..", "..", "docs", "src", "configuration.md")
	data, err := os.ReadFile(path) // #nosec G304 -- repository-owned test fixture path
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	const marker = "## Full Reference\n\n```yaml\n"
	_, yamlText, ok := strings.Cut(string(data), marker)
	if !ok {
		t.Fatalf("%s: full reference YAML block not found", path)
	}
	yamlText, _, ok = strings.Cut(yamlText, "\n```\n")
	if !ok {
		t.Fatalf("%s: full reference YAML block is not closed", path)
	}
	return loadRestrictedTCP(t, "full reference in "+path, []byte(yamlText))
}

func loadRestrictedTCP(t *testing.T, name string, data []byte) []int {
	t.Helper()
	if _, err := config.LoadBytes(data); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}

	// Read the explicit source value separately. Config loading applies runtime
	// defaults, which would make an omitted restricted_tcp key look correct.
	var ref firewallReference
	if err := yaml.Unmarshal(data, &ref); err != nil {
		t.Fatalf("parse raw %s: %v", name, err)
	}
	if ref.Firewall.RestrictedTCP == nil {
		t.Fatalf("%s: firewall.restricted_tcp is missing", name)
	}
	return ref.Firewall.RestrictedTCP
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

// Firewall defaults are repeated in runtime code, deployable configs, and the
// operator documentation. Keep the restricted ports aligned so copying any
// complete reference config cannot publish an infra-only management port.
func TestRestrictedTCPDefaultsAgreeAcrossReferences(t *testing.T) {
	want := firewall.DefaultConfig().RestrictedTCP

	for _, tc := range []struct {
		name  string
		ports []int
	}{
		{"installer template", loadInstallerTemplate(t)},
		{"packaged default", loadPackagedDefault(t)},
		{"production reference", loadProductionReference(t)},
		{"documented reference", loadDocumentedReference(t)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !samePorts(tc.ports, want) {
				t.Errorf("restricted_tcp = %v, want runtime default %v", tc.ports, want)
			}
		})
	}
}

// restricted_tcp filters matching ports out of the public allow list; it does
// not open them. Keep the Web UI listed so adding its port to tcp_in does not
// also publish the management panel beyond infra_ips.
func TestDefaultReferencesRestrictWebUIPort(t *testing.T) {
	const webUIPort = 9443

	for _, tc := range []struct {
		name  string
		ports []int
	}{
		{"installer template", loadInstallerTemplate(t)},
		{"packaged default", loadPackagedDefault(t)},
		{"production reference", loadProductionReference(t)},
		{"documented reference", loadDocumentedReference(t)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			found := false
			for _, p := range tc.ports {
				if p == webUIPort {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("restricted_tcp = %v, missing web UI port %d", tc.ports, webUIPort)
			}
		})
	}
}
