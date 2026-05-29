package integrity

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// signTestBaseline writes a main config + conf.d fragments, signs the main
// file (folding conf.d into confd_hash), and returns a *config.Config whose
// integrity fields and ConfigDir match what Verify will recompute. The
// returned binaryPath hashes to the stored binary_hash.
func signTestBaseline(t *testing.T, mainBody string, fragments map[string]string) (*config.Config, string, string) {
	t.Helper()
	dir := t.TempDir()
	mainPath := filepath.Join(dir, "csm.yaml")
	// An integrity block must already exist for the in-place YAMLEdit patch.
	mainBody += "integrity:\n  binary_hash: \"\"\n  config_hash: \"\"\n"
	if err := os.WriteFile(mainPath, []byte(mainBody), 0o600); err != nil {
		t.Fatal(err)
	}
	confDir := filepath.Join(dir, "conf.d")
	if err := os.MkdirAll(confDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range fragments {
		if err := os.WriteFile(filepath.Join(confDir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// A separate stable file stands in for the binary; signing rewrites the
	// main config, so it cannot double as the hashed binary.
	binaryPath := filepath.Join(dir, "csm.bin")
	if err := os.WriteFile(binaryPath, []byte("fake binary contents"), 0o600); err != nil {
		t.Fatal(err)
	}
	binaryHash, err := HashFile(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	configHash, confdHash, err := SignConfigFilePreserving(mainPath, confDir, binaryHash)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	cfg, err := config.LoadWithDir(mainPath, confDir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	cfg.Integrity.BinaryHash = binaryHash
	cfg.Integrity.ConfigHash = configHash
	cfg.Integrity.ConfdHash = confdHash
	return cfg, binaryPath, confDir
}

// A baseline with conf.d fragments verifies clean, and any later edit to a
// fragment is detected by Verify. Before confd_hash existed, the edit slipped
// through because only the main config file was hashed.
func TestVerify_DetectsConfDirFragmentTamper(t *testing.T) {
	cfg, binaryPath, confDir := signTestBaseline(t,
		"hostname: host1\n",
		map[string]string{"10-override.yaml": "auto_response:\n  enabled: true\n"})

	if err := Verify(binaryPath, cfg); err != nil {
		t.Fatalf("freshly signed baseline must verify, got %v", err)
	}

	// Attacker flips auto_response off via the drop-in.
	if err := os.WriteFile(filepath.Join(confDir, "10-override.yaml"),
		[]byte("auto_response:\n  enabled: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Verify(binaryPath, cfg); err == nil {
		t.Fatal("tampered conf.d fragment must fail verification")
	}
}

// A newly added fragment (none at sign time) is also caught: stored confd_hash
// is empty, the live digest is not.
func TestVerify_DetectsAddedConfDirFragment(t *testing.T) {
	cfg, binaryPath, confDir := signTestBaseline(t, "hostname: host1\n", nil)

	if err := Verify(binaryPath, cfg); err != nil {
		t.Fatalf("baseline without conf.d must verify, got %v", err)
	}

	if err := os.WriteFile(filepath.Join(confDir, "99-evil.yaml"),
		[]byte("auto_response:\n  enabled: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Verify(binaryPath, cfg); err == nil {
		t.Fatal("added conf.d fragment must fail verification")
	}
}

// Backward compatibility: a baseline with no conf.d (empty ConfdHash, no
// fragments) verifies clean -- existing deployments are unaffected.
func TestVerify_NoConfDirStaysCompatible(t *testing.T) {
	cfg, binaryPath, _ := signTestBaseline(t, "hostname: host1\n", nil)
	if cfg.Integrity.ConfdHash != "" {
		t.Fatalf("no fragments must yield empty confd_hash, got %q", cfg.Integrity.ConfdHash)
	}
	if err := Verify(binaryPath, cfg); err != nil {
		t.Fatalf("conf.d-free baseline must verify, got %v", err)
	}
}

func TestHashConfDir_EmptyWhenNoFragments(t *testing.T) {
	dir := t.TempDir()
	h, err := HashConfDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if h != "" {
		t.Errorf("empty conf.d must hash to empty string, got %q", h)
	}
	// A non-existent dir is also empty, not an error.
	h, err = HashConfDir(filepath.Join(dir, "nope"))
	if err != nil || h != "" {
		t.Errorf("missing conf.d: want (\"\", nil), got (%q, %v)", h, err)
	}
}
