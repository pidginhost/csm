package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// `csm install` and the packages must start a host from the same config file.
// A separate installer copy drifted: keys, comments and defaults that the
// packaged file carried were missing on hosts installed by the CLI.
func TestInstallerWritesThePackagedDefaultConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "csm.yaml")
	if err := deployDefaultConfig(path); err != nil {
		t.Fatalf("deployDefaultConfig: %v", err)
	}
	written, err := os.ReadFile(path) // #nosec G304 -- test-owned temp path
	if err != nil {
		t.Fatal(err)
	}
	packaged, err := os.ReadFile(filepath.Join("..", "..", "build", "packaging", "csm.yaml.default"))
	if err != nil {
		t.Fatal(err)
	}

	token := regexp.MustCompile(`(?m)^  auth_token: "([0-9a-f]{64})"  # generated on install$`)
	if !token.Match(written) {
		t.Fatal("installed config carries no generated WebUI token")
	}
	issued := regexp.MustCompile(`(?m)^  auth_token_issued_at: "\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ"`)
	if !issued.Match(written) {
		t.Fatal("installed config does not record the token issue time")
	}

	normalize := func(b []byte) string {
		var out []string
		for _, line := range strings.Split(string(b), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "auth_token:") || strings.HasPrefix(trimmed, "auth_token_issued_at:") {
				continue
			}
			out = append(out, line)
		}
		return strings.Join(out, "\n")
	}
	if normalize(written) != normalize(packaged) {
		t.Fatal("installed config differs from build/packaging/csm.yaml.default beyond the generated token lines")
	}
}
