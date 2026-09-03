package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/integrity"
)

// An operator who exempts an integration's fragment in the same edit as a
// restart-required field must not be paged with tamper alerts until the
// restart: the re-signed confd_hash and the exemption list it was computed
// under have to reach the live config together.
func TestReloadConfigRestartRequiredCarriesExemptList(t *testing.T) {
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
	bh, err := integrity.HashFile(binPath)
	if err != nil {
		t.Fatal(err)
	}

	orig := &config.Config{}
	orig.Hostname = "main.example.com"
	orig.Integrity.BinaryHash = bh
	seedConfigAtPath(t, cfgPath, orig)
	agent := filepath.Join(confDir, "10-agent-runtime.yaml")
	if err := os.WriteFile(agent, []byte("alerts:\n  webhook:\n    url: https://panel.example.com/v1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := integrity.SignConfigFilePreserving(cfgPath, confDir, bh); err != nil {
		t.Fatalf("sign with conf.d: %v", err)
	}
	loaded, err := config.LoadWithDir(cfgPath, confDir)
	if err != nil {
		t.Fatal(err)
	}
	d := newDaemonForReloadTest(t, loaded)
	d.binaryPath = binPath

	// One edit: rename the host (restart-required) and exempt the agent's fragment.
	next := &config.Config{}
	next.Hostname = "renamed.example.com"
	next.Integrity = loaded.Integrity
	next.ConfD.IntegrityExempt = []string{"10-agent-runtime.yaml"}
	seedConfigAtPath(t, cfgPath, next)
	d.reloadConfig()

	if err := integrity.Verify(d.binaryPath, d.currentCfg()); err != nil {
		t.Errorf("live config must verify under the exemption it was re-signed with: %v", err)
	}

	// The agent bootstraps again before the restart happens.
	if err := os.WriteFile(agent, []byte("alerts:\n  webhook:\n    url: https://panel.example.com/v2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := integrity.Verify(d.binaryPath, d.currentCfg()); err != nil {
		t.Errorf("exempt fragment rewrite must not trip the live config: %v", err)
	}
	reloaded, err := config.LoadWithDir(cfgPath, confDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := integrity.Verify(d.binaryPath, reloaded); err != nil {
		t.Errorf("on-disk config must verify for the next restart: %v", err)
	}
}
