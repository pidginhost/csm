package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/integrity"
)

func signedStartupConfig(t *testing.T) (*config.Config, string, string) {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "csm.yaml")
	confDir := filepath.Join(dir, "conf.d")
	binPath := filepath.Join(dir, "bin")
	if err := os.MkdirAll(confDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binPath, []byte("stand-in"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(confDir, "10-agent.yaml"), []byte("hostname: agent.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, []byte("hostname: main.example.com\nintegrity:\n  binary_hash: \"\"\n  config_hash: \"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bh, err := integrity.HashFile(binPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, signErr := integrity.SignConfigFilePreserving(cfgPath, confDir, bh); signErr != nil {
		t.Fatal(signErr)
	}
	cfg, err := config.LoadWithDir(cfgPath, confDir)
	if err != nil {
		t.Fatal(err)
	}
	record, err := integrity.FragmentRecordPath(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	// Signed by a release that kept no per-fragment record.
	if err := os.Remove(record); err != nil {
		t.Fatal(err)
	}
	return cfg, binPath, record
}

// A host upgraded from a release without per-fragment records gets one at
// its first verified start, so the agent's scoped rehash works without an
// operator running a full rehash first.
func TestVerifyStartupIntegrityRecordsFragments(t *testing.T) {
	cfg, binPath, record := signedStartupConfig(t)

	if err := verifyStartupIntegrity(binPath, cfg); err != nil {
		t.Fatalf("verifyStartupIntegrity: %v", err)
	}
	if _, err := os.Stat(record); err != nil {
		t.Fatalf("verified start left no per-fragment record: %v", err)
	}
	if err := os.WriteFile(filepath.Join(cfg.ConfigDir, "10-agent.yaml"), []byte("hostname: rewritten.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := integrity.RehashFragments(binPath, cfg.ConfigFile, cfg.ConfigDir, []string{"10-agent.yaml"}); err != nil {
		t.Fatalf("scoped rehash after a verified start: %v", err)
	}
}

func TestVerifyStartupIntegrityRecordsNothingOnMismatch(t *testing.T) {
	cfg, binPath, record := signedStartupConfig(t)
	if err := os.WriteFile(filepath.Join(cfg.ConfigDir, "20-extra.yaml"), []byte("hostname: extra.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := verifyStartupIntegrity(binPath, cfg); !errors.Is(err, integrity.ErrConfdHashMismatch) {
		t.Fatalf("verifyStartupIntegrity = %v, want conf.d mismatch", err)
	}
	if _, err := os.Stat(record); !os.IsNotExist(err) {
		t.Fatalf("a failed verification must not record fragments: %v", err)
	}
}
