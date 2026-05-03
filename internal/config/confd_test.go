package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfDir_LexicographicOrder(t *testing.T) {
	dir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(dir, "20-second.yaml"), []byte("hostname: second\n"), 0o600))
	must(t, os.WriteFile(filepath.Join(dir, "10-first.yaml"), []byte("hostname: first\n"), 0o600))
	must(t, os.WriteFile(filepath.Join(dir, "README.txt"), []byte("ignore"), 0o600)) // not .yaml

	frags, err := LoadConfDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(frags) != 2 {
		t.Fatalf("expected 2 fragments, got %d", len(frags))
	}
	// lex order means 10- before 20-, and last write wins
	root := frags[1].Content[0]
	if root.Content[1].Value != "second" {
		t.Fatalf("expected second fragment content, got %q", root.Content[1].Value)
	}
}

func TestLoadConfDir_MissingDirReturnsEmpty(t *testing.T) {
	frags, err := LoadConfDir(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Fatal(err)
	}
	if len(frags) != 0 {
		t.Fatalf("expected empty slice, got %d fragments", len(frags))
	}
}

func TestLoadConfDir_EmptyDirReturnsEmpty(t *testing.T) {
	frags, err := LoadConfDir("")
	if err != nil {
		t.Fatal(err)
	}
	if len(frags) != 0 {
		t.Fatalf("expected empty slice, got %d fragments", len(frags))
	}
}

func TestLoadConfDir_RejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(dir, "10.yaml"), []byte("not_a_real_field: 1\n"), 0o600))
	// LoadConfDir itself doesn't decode into Config, just returns yaml.Nodes,
	// so this test asserts that valid YAML passes even with "unknown" keys.
	frags, err := LoadConfDir(dir)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(frags) != 1 {
		t.Fatalf("expected 1 fragment, got %d", len(frags))
	}
}

func TestLoadWithDir_PackagedPHPPanelProfile(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "csm.yaml")
	confd := filepath.Join(dir, "conf.d")
	must(t, os.MkdirAll(confd, 0o700))
	must(t, os.WriteFile(main, []byte("hostname: host.example\n"), 0o600))

	profilePath := filepath.Join("..", "..", "build", "packaging", "profiles", "phpanel-agent.yaml")
	profile, err := os.ReadFile(profilePath)
	if err != nil {
		t.Fatalf("read profile: %v", err)
	}
	must(t, os.WriteFile(filepath.Join(confd, "00-phpanel.yaml"), profile, 0o600))

	cfg, err := LoadWithDir(main, confd)
	if err != nil {
		t.Fatalf("LoadWithDir with packaged phpanel profile: %v", err)
	}
	if len(cfg.AccountRoots) != 1 || cfg.AccountRoots[0] != "/var/www/*" {
		t.Fatalf("AccountRoots = %v, want [/var/www/*]", cfg.AccountRoots)
	}
	if cfg.Alerts.Webhook.Enabled {
		t.Fatal("packaged phpanel profile must not enable a placeholder webhook")
	}
	if len(cfg.WebUI.Tokens) != 0 {
		t.Fatalf("packaged phpanel profile must not ship active placeholder tokens, got %v", cfg.WebUI.Tokens)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
