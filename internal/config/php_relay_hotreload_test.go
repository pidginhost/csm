package config

import "testing"

// The PHP-relay pipeline is wired once at startup: a reload cannot start it
// or stop it, only retune the running one. Toggling enabled therefore needs
// a restart and must be reported as such instead of as a successful reload,
// while thresholds stay hot-reloadable.
func TestPHPRelayEnableToggleRequiresRestart(t *testing.T) {
	load := func(body string) *Config {
		cfg, err := LoadBytes([]byte("hostname: x\nemail_protection:\n  php_relay:\n" + body))
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	off := load("    enabled: false\n    rate_window_min: 5\n")
	on := load("    enabled: true\n    rate_window_min: 5\n")
	if !RestartRequired(Diff(off, on)) {
		t.Fatal("enabling php_relay reported as hot-reloadable; the pipeline is only wired at startup")
	}
	retuned := load("    enabled: true\n    rate_window_min: 10\n")
	if RestartRequired(Diff(on, retuned)) {
		t.Fatal("a php_relay threshold change must stay hot-reloadable")
	}
}
