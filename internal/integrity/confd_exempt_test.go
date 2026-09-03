package integrity

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A fragment its owning integration rewrites on every bootstrap cannot be
// pinned by a static hash without turning each restart into a manual rehash.
// Listing it under confd.integrity_exempt in the main config leaves its
// content out of confd_hash while every other fragment stays covered.
func TestVerify_IgnoresRewriteOfExemptFragment(t *testing.T) {
	cfg, binaryPath, confDir := signTestBaseline(t,
		"hostname: host1\nconfd:\n  integrity_exempt:\n    - 10-agent-runtime.yaml\n",
		map[string]string{
			"10-agent-runtime.yaml": "alerts:\n  webhook:\n    url: https://panel.example.com/v1\n",
			"20-operator.yaml":      "auto_response:\n  enabled: true\n",
		})
	if err := Verify(binaryPath, cfg); err != nil {
		t.Fatalf("freshly signed baseline must verify, got %v", err)
	}

	// The agent bootstraps again and rewrites its own fragment.
	if err := os.WriteFile(filepath.Join(confDir, "10-agent-runtime.yaml"),
		[]byte("alerts:\n  webhook:\n    url: https://panel.example.com/v2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Verify(binaryPath, cfg); err != nil {
		t.Fatalf("rewrite of an exempt fragment must not fail verification, got %v", err)
	}

	// Every other fragment is still pinned.
	if err := os.WriteFile(filepath.Join(confDir, "20-operator.yaml"),
		[]byte("auto_response:\n  enabled: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Verify(binaryPath, cfg); err == nil {
		t.Fatal("edit to a non-exempt fragment must still fail verification")
	}
}

// An exempt fragment hashes as if it were absent, so its presence, absence
// and content all leave the digest alone.
func TestHashConfDir_ExemptFragmentHashesAsAbsent(t *testing.T) {
	dir := t.TempDir()
	agent := filepath.Join(dir, "10-agent.yaml")
	if err := os.WriteFile(agent, []byte("hostname: a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "20-operator.yaml"), []byte("hostname: b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	exempt := []string{"10-agent.yaml"}
	before, err := HashConfDir(dir, exempt)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(agent, []byte("hostname: rewritten\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	after, err := HashConfDir(dir, exempt)
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Errorf("rewriting an exempt fragment changed the digest: %q -> %q", before, after)
	}
	if err := os.Remove(agent); err != nil {
		t.Fatal(err)
	}
	without, err := HashConfDir(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if without != before {
		t.Errorf("exempt fragment must hash as if absent: with=%q without=%q", before, without)
	}
}

// Every other fragment still counts even when one is exempt.
func TestHashConfDir_NonExemptFragmentStillCounts(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "10-agent.yaml"), []byte("hostname: a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	operator := filepath.Join(dir, "20-operator.yaml")
	if err := os.WriteFile(operator, []byte("hostname: b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	exempt := []string{"10-agent.yaml"}
	before, err := HashConfDir(dir, exempt)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(operator, []byte("hostname: c\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	after, err := HashConfDir(dir, exempt)
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Error("editing a non-exempt fragment must change the digest")
	}
}

// The failure used to read like tampering with no way out. It now names the
// command that re-signs after an intentional change and the knob for
// fragments an integration owns.
func TestVerify_ConfdMismatchNamesRemedy(t *testing.T) {
	cfg, binaryPath, confDir := signTestBaseline(t, "hostname: host1\n",
		map[string]string{"10-override.yaml": "auto_response:\n  enabled: true\n"})
	if err := os.WriteFile(filepath.Join(confDir, "10-override.yaml"),
		[]byte("auto_response:\n  enabled: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := Verify(binaryPath, cfg)
	if !errors.Is(err, ErrConfdHashMismatch) {
		t.Fatalf("err = %v, want ErrConfdHashMismatch", err)
	}
	for _, want := range []string{"conf.d hash mismatch", "csm rehash", "integrity_exempt"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should mention %q", err, want)
		}
	}
}

func TestVerify_ConfigMismatchNamesRemedy(t *testing.T) {
	cfg, binaryPath, _ := signTestBaseline(t, "hostname: host1\n", nil)
	edited := "hostname: host2\nintegrity:\n  binary_hash: " + cfg.Integrity.BinaryHash +
		"\n  config_hash: " + cfg.Integrity.ConfigHash + "\n"
	if err := os.WriteFile(cfg.ConfigFile, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	err := Verify(binaryPath, cfg)
	if !errors.Is(err, ErrConfigHashMismatch) {
		t.Fatalf("err = %v, want ErrConfigHashMismatch", err)
	}
	for _, want := range []string{"config hash mismatch", "csm rehash"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should mention %q", err, want)
		}
	}
}

func TestVerify_BinaryMismatchNamesRemedy(t *testing.T) {
	cfg, binaryPath, _ := signTestBaseline(t, "hostname: host1\n", nil)
	if err := os.WriteFile(binaryPath, []byte("replaced binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := Verify(binaryPath, cfg)
	if !errors.Is(err, ErrBinaryHashMismatch) {
		t.Fatalf("err = %v, want ErrBinaryHashMismatch", err)
	}
	for _, want := range []string{"binary hash mismatch", "csm rehash"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should mention %q", err, want)
		}
	}
}
