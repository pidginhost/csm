package config

import (
	"os"
	"path/filepath"
	"strings"
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

func TestConfDirFragmentDigestInputSkipsEmptyFragments(t *testing.T) {
	dir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(dir, "10-empty.yaml"), []byte("# comment only\n\n"), 0o600))

	frags, err := ConfDirFragmentDigestInput(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(frags) != 0 {
		t.Fatalf("expected no digest fragments, got %d", len(frags))
	}
}

func TestConfDirFragmentDigestInputRejectsInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(dir, "10-bad.yaml"), []byte("bad: :\n"), 0o600))

	_, err := ConfDirFragmentDigestInput(dir)
	if err == nil {
		t.Fatal("invalid YAML must be rejected")
	}
	if !strings.Contains(err.Error(), "parsing") {
		t.Fatalf("error = %v, want parsing error", err)
	}
}

func TestLoadConfDirRejectsIntegrityOverride(t *testing.T) {
	dir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(dir, "10-integrity.yaml"), []byte("integrity:\n  config_hash: \"\"\n"), 0o600))

	_, err := LoadConfDir(dir)
	if err == nil {
		t.Fatal("conf.d integrity override must be rejected")
	}
	if !strings.Contains(err.Error(), "integrity") {
		t.Fatalf("error = %v, want integrity refusal", err)
	}

	_, err = ConfDirFragmentDigestInput(dir)
	if err == nil {
		t.Fatal("digest input must reject the same fragment set")
	}
	if !strings.Contains(err.Error(), "integrity") {
		t.Fatalf("digest error = %v, want integrity refusal", err)
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

func TestLoadConfDir_RejectsWritableFragment(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "10.yaml")
	must(t, os.WriteFile(path, []byte("hostname: unsafe\n"), 0o600))
	must(t, os.Chmod(path, 0o666))

	_, err := LoadConfDir(dir)
	if err == nil {
		t.Fatal("world-writable fragment must be rejected")
	}
	if !strings.Contains(err.Error(), "conf.d fragment") || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("error = %v, want writable fragment refusal", err)
	}
}

func TestLoadConfDir_AcceptsSafeSymlinkFragment(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "profile.yaml")
	must(t, os.WriteFile(target, []byte("hostname: symlink-profile\n"), 0o600))
	must(t, os.Symlink(target, filepath.Join(dir, "10-profile.yaml")))

	frags, err := LoadConfDir(dir)
	if err != nil {
		t.Fatalf("LoadConfDir: %v", err)
	}
	if len(frags) != 1 {
		t.Fatalf("fragments = %d, want 1", len(frags))
	}
	root := frags[0].Content[0]
	if root.Content[1].Value != "symlink-profile" {
		t.Fatalf("hostname = %q, want symlink-profile", root.Content[1].Value)
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
	if !cfg.Reputation.Rspamd.Enabled {
		t.Fatal("packaged phpanel profile must keep rspamd threat-intel enabled")
	}
	if cfg.Reputation.Rspamd.URL != "http://127.0.0.1:11334" {
		t.Fatalf("Rspamd URL = %q, want local controller", cfg.Reputation.Rspamd.URL)
	}
	if cfg.Reputation.Upstream.Enabled {
		t.Fatal("packaged phpanel profile must not enable upstream without the runtime URL")
	}
	if cfg.Reputation.Upstream.TokenEnv != "CSM_UPSTREAM_TOKEN" {
		t.Fatalf("Upstream TokenEnv = %q, want CSM_UPSTREAM_TOKEN", cfg.Reputation.Upstream.TokenEnv)
	}
	if cfg.AutoResponse.VerdictCallback.Enabled {
		t.Fatal("packaged phpanel profile must not enable verdict_callback without a runtime URL")
	}
	if cfg.AutoResponse.VerdictCallback.HMACSecretEnv != "CSM_VERDICT_HMAC" {
		t.Fatalf("VerdictCallback.HMACSecretEnv = %q, want CSM_VERDICT_HMAC", cfg.AutoResponse.VerdictCallback.HMACSecretEnv)
	}
	if cfg.AutoResponse.VerdictCallback.TimeoutSec != 2 {
		t.Fatalf("VerdictCallback.TimeoutSec = %d, want 2", cfg.AutoResponse.VerdictCallback.TimeoutSec)
	}
}

func TestLoadWithDir_PackagedDefaultDoesNotPreseedMailLogUnits(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "csm.yaml")
	confd := filepath.Join(dir, "conf.d")
	must(t, os.MkdirAll(confd, 0o700))

	defaultPath := filepath.Join("..", "..", "build", "packaging", "csm.yaml.default")
	defaultConfig, err := os.ReadFile(defaultPath)
	if err != nil {
		t.Fatalf("read packaged default: %v", err)
	}
	must(t, os.WriteFile(main, defaultConfig, 0o600))
	must(t, os.WriteFile(filepath.Join(confd, "10-mail-logs.yaml"), []byte(`
mail_logs:
  source: journal
  units:
    - custom-postfix
`), 0o600))

	cfg, err := LoadWithDir(main, confd)
	if err != nil {
		t.Fatalf("LoadWithDir: %v", err)
	}
	if cfg.MailLogs.Source != "journal" {
		t.Fatalf("MailLogs.Source = %q, want journal", cfg.MailLogs.Source)
	}
	if len(cfg.MailLogs.Units) != 1 || cfg.MailLogs.Units[0] != "custom-postfix" {
		t.Fatalf("MailLogs.Units = %v, want [custom-postfix]", cfg.MailLogs.Units)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
