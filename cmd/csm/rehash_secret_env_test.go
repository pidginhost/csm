package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/integrity"
)

// dpkg runs `csm rehash` from postinst without the service environment that
// holds the verdict callback secret. Rehash and verify only hash files, so an
// unset secret must not stop them; the daemon load must still refuse it.
func TestRehashAndVerifyWithoutRuntimeSecretEnv(t *testing.T) {
	const secretEnv = "CSM_TEST_VERDICT_HMAC_UNSET"
	t.Setenv(secretEnv, "")

	dir := t.TempDir()
	confDir := filepath.Join(dir, "conf.d")
	if err := os.Mkdir(confDir, 0o700); err != nil {
		t.Fatal(err)
	}
	const fragment = "50-agent.yaml"
	if err := os.WriteFile(filepath.Join(confDir, fragment), []byte("hostname: host1.example.test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "csm.yaml")
	body := "auto_response:\n" +
		"  verdict_callback:\n" +
		"    enabled: true\n" +
		"    url: https://panel.example.test/api/csm/verdict\n" +
		"    hmac_secret_env: " + secretEnv + "\n" +
		"integrity:\n  binary_hash: \"\"\n  config_hash: \"\"\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	binPath := filepath.Join(dir, "csm.bin")
	if err := os.WriteFile(binPath, []byte("fake binary"), 0o600); err != nil {
		t.Fatal(err)
	}

	oldArgs := os.Args
	t.Cleanup(func() { os.Args = oldArgs })
	os.Args = []string{"csm", "rehash", "--config", cfgPath, "--config-dir", confDir}

	if _, err := tryLoadConfigLite(); err == nil || !strings.Contains(err.Error(), secretEnv) {
		t.Fatalf("daemon load with the secret unset: err = %v, want the fail-closed secret error", err)
	}

	// Full rehash: the same load and signing runRehash performs.
	cfg, err := tryLoadConfigLiteWith(hashOnlyLoadOptions)
	if err != nil {
		t.Fatalf("rehash load: %v", err)
	}
	binaryHash, err := integrity.HashFile(binPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = integrity.SignConfigFilePreserving(cfg.ConfigFile, cfg.ConfigDir, binaryHash); err != nil {
		t.Fatalf("rehash sign: %v", err)
	}

	// Scoped rehash after an integration rewrote its fragment.
	if err = os.WriteFile(filepath.Join(confDir, fragment), []byte("hostname: host2.example.test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := rehashFragments(binPath, cfg.ConfigFile, cfg.ConfigDir, []string{fragment}, &stdout, &stderr); code != 0 {
		t.Fatalf("rehash --fragment exit %d: %s", code, stderr.String())
	}

	// Verify: the same load and check runVerify performs.
	os.Args = []string{"csm", "verify", "--config", cfgPath, "--config-dir", confDir}
	signed, err := tryLoadConfigLiteWith(hashOnlyLoadOptions)
	if err != nil {
		t.Fatalf("verify load: %v", err)
	}
	if err = integrity.Verify(binPath, signed); err != nil {
		t.Fatalf("verify: %v", err)
	}
}
