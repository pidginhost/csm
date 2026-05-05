package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveConfigPathFromArgsExplicitWins(t *testing.T) {
	got, explicit, err := resolveConfigPathFromArgs([]string{"csm", "validate", "--config", "/tmp/custom.yaml"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !explicit {
		t.Fatal("expected explicit config flag")
	}
	if got != "/tmp/custom.yaml" {
		t.Fatalf("config path = %q, want /tmp/custom.yaml", got)
	}
}

func TestResolveDefaultConfigPathPrefersPreferredPath(t *testing.T) {
	preferred, legacy := testConfigPaths(t)
	writeConfig(t, preferred, "hostname: prod\n")
	writeConfig(t, legacy, "hostname: prod\n")

	got, err := resolveDefaultConfigPath(preferred, legacy)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != preferred {
		t.Fatalf("config path = %q, want %q", got, preferred)
	}
}

func TestResolveDefaultConfigPathFallsBackToLegacyPath(t *testing.T) {
	preferred, legacy := testConfigPaths(t)
	writeConfig(t, legacy, "hostname: prod\n")

	got, err := resolveDefaultConfigPath(preferred, legacy)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != legacy {
		t.Fatalf("config path = %q, want %q", got, legacy)
	}
}

func TestResolveDefaultConfigPathRejectsSplitBrain(t *testing.T) {
	preferred, legacy := testConfigPaths(t)
	writeConfig(t, preferred, "hostname: preferred\n")
	writeConfig(t, legacy, "hostname: legacy\n")

	_, err := resolveDefaultConfigPath(preferred, legacy)
	if err == nil {
		t.Fatal("expected split-brain error")
	}
	if !strings.Contains(err.Error(), "different content") {
		t.Fatalf("error = %q, want different content", err)
	}
}

func TestMigrateDefaultConfigPathsCopiesLegacyAndLinksBack(t *testing.T) {
	preferred, legacy := testConfigPaths(t)
	writeConfig(t, legacy, "hostname: prod\n")

	if err := migrateDefaultConfigPaths(preferred, legacy); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	assertFileContent(t, preferred, "hostname: prod\n")
	assertSymlinkTarget(t, legacy, preferred)
}

func TestMigrateDefaultConfigPathsReplacesPlaceholderPreferred(t *testing.T) {
	preferred, legacy := testConfigPaths(t)
	writeConfig(t, preferred, "hostname: SET_HOSTNAME_HERE\nauth_token: \"\"\n")
	writeConfig(t, legacy, "hostname: prod\nauth_token: \"token\"\n")

	if err := migrateDefaultConfigPaths(preferred, legacy); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	assertFileContent(t, preferred, "hostname: prod\nauth_token: \"token\"\n")
	assertSymlinkTarget(t, legacy, preferred)
}

func TestMigrateDefaultConfigPathsPreservesPartialLegacyConfig(t *testing.T) {
	preferred, legacy := testConfigPaths(t)
	writeConfig(t, preferred, "hostname: SET_HOSTNAME_HERE\nauth_token: \"\"\n")
	writeConfig(t, legacy, "hostname: prod\nauth_token: \"\"\n")

	if err := migrateDefaultConfigPaths(preferred, legacy); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	assertFileContent(t, preferred, "hostname: prod\nauth_token: \"\"\n")
	assertSymlinkTarget(t, legacy, preferred)
}

func TestMigrateDefaultConfigPathsTreatsEmptyAuthTokenAsOperatorConfig(t *testing.T) {
	// `auth_token: ""` is a legitimate v2.11.0+ value when the operator
	// uses the scoped `webui.tokens:` block. It must NOT count as a
	// placeholder, or migration would silently overwrite a real config
	// with the legacy file.
	preferred, legacy := testConfigPaths(t)
	writeConfig(t, preferred, "hostname: prod\nwebui:\n  auth_token: \"\"\n  tokens:\n    - {name: ops, token: real, scope: admin}\n")
	writeConfig(t, legacy, "hostname: legacy\nauth_token: legacy-token\n")

	err := migrateDefaultConfigPaths(preferred, legacy)
	if err == nil {
		t.Fatal("expected migration conflict; preferred is a real operator config, not a placeholder")
	}
	if !strings.Contains(err.Error(), "refusing automatic config migration") {
		t.Fatalf("error = %q, want migration refusal", err)
	}
	assertFileContent(t, preferred, "hostname: prod\nwebui:\n  auth_token: \"\"\n  tokens:\n    - {name: ops, token: real, scope: admin}\n")
}

func TestMigrateDefaultConfigPathsRejectsDifferentOperatorConfigs(t *testing.T) {
	preferred, legacy := testConfigPaths(t)
	writeConfig(t, preferred, "hostname: preferred\n")
	writeConfig(t, legacy, "hostname: legacy\n")

	err := migrateDefaultConfigPaths(preferred, legacy)
	if err == nil {
		t.Fatal("expected migration conflict")
	}
	if !strings.Contains(err.Error(), "refusing automatic config migration") {
		t.Fatalf("error = %q, want migration refusal", err)
	}
	if info, statErr := os.Lstat(legacy); statErr != nil {
		t.Fatalf("legacy stat: %v", statErr)
	} else if info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("legacy config should remain a real file after conflict")
	}
}

func testConfigPaths(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	return filepath.Join(root, "etc", "csm", "csm.yaml"), filepath.Join(root, "opt", "csm", "csm.yaml")
}

func writeConfig(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func assertFileContent(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(got) != want {
		t.Fatalf("%s = %q, want %q", path, got, want)
	}
}

func assertSymlinkTarget(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.Readlink(path)
	if err != nil {
		t.Fatalf("readlink %s: %v", path, err)
	}
	if got != want {
		t.Fatalf("symlink target = %q, want %q", got, want)
	}
}
