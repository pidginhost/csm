package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/admission"
	"gopkg.in/yaml.v3"
)

// A negative temporary block limit loads as 0, which every reader already
// made of it: the firewall caps nothing and admission works within its
// default capacity. Earlier releases accepted the value, so validation warns
// and never refuses it. An explicit 0 or a positive limit loads as written,
// without the warning.
func TestNegativeDenyTempIPLimitLoadsAsZeroAndWarns(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  int
		warn  bool
	}{
		{"-5", 0, true},
		{"-1", 0, true},
		{"0", 0, false},
		{"300", 300, false},
	} {
		cfg, err := LoadBytes([]byte("firewall:\n  deny_temp_ip_limit: " + tc.value + "\n"))
		if err != nil {
			t.Fatalf("%s: %v", tc.value, err)
		}
		if got := cfg.Firewall.DenyTempIPLimit; got != tc.want {
			t.Errorf("%s: loaded limit %d, want %d", tc.value, got, tc.want)
		}
		if tc.warn && admission.AutomaticCapacity(cfg.Firewall.DenyTempIPLimit) != admission.AutomaticCapacity(-5) {
			t.Errorf("%s: admission capacity changed", tc.value)
		}
		var found []ValidationResult
		for _, r := range Validate(cfg) {
			if r.Field == "firewall.deny_temp_ip_limit" {
				found = append(found, r)
			}
		}
		switch {
		case !tc.warn && len(found) != 0:
			t.Errorf("%s: unexpected results %+v", tc.value, found)
		case tc.warn && (len(found) != 1 || found[0].Level != "warn" || !strings.Contains(found[0].Message, "negative")):
			t.Errorf("%s: results %+v, want one warning about the negative value", tc.value, found)
		}
	}
}

// negativeLimitWarnings are the validation results about the limit.
func negativeLimitWarnings(cfg *Config) (found []ValidationResult) {
	for _, r := range Validate(cfg) {
		if r.Field == "firewall.deny_temp_ip_limit" {
			found = append(found, r)
		}
	}
	return found
}

// Only the value that takes effect is judged. A drop-in that replaces a
// negative limit silences the warning and one that brings a negative limit
// raises it. What the loader remembers about the written value reaches
// neither YAML nor JSON, and a later publication does not inherit it.
func TestNegativeTemporaryLimitLayeringAndReload(t *testing.T) {
	load := func(t *testing.T, main, dropIn string) *Config {
		t.Helper()
		confDir := t.TempDir()
		if dropIn != "" {
			if err := os.WriteFile(filepath.Join(confDir, "10-limit.yaml"), []byte("firewall:\n  deny_temp_ip_limit: "+dropIn+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		cfg, err := LoadBytesWithDir([]byte("firewall:\n  deny_temp_ip_limit: "+main+"\n"), confDir)
		if err != nil {
			t.Fatalf("main %s, drop-in %q: %v", main, dropIn, err)
		}
		return cfg
	}
	loaded := map[string]*Config{}
	for _, tc := range []struct {
		name, main, dropIn string
		want               int
		warn               bool
	}{
		{"negative", "-5", "", 0, true},
		{"zero over negative", "-5", "0", 0, false},
		{"positive over negative", "-5", "300", 300, false},
		{"negative over positive", "300", "-5", 0, true},
	} {
		cfg := load(t, tc.main, tc.dropIn)
		loaded[tc.name] = cfg
		found := negativeLimitWarnings(cfg)
		if cfg.Firewall.DenyTempIPLimit != tc.want || tc.warn != (len(found) == 1 && found[0].Level == "warn") || (!tc.warn && len(found) != 0) {
			t.Errorf("%s: limit %d, results %+v; want %d, warned %t", tc.name, cfg.Firewall.DenyTempIPLimit, found, tc.want, tc.warn)
		}
		if tc.warn && admission.AutomaticCapacity(cfg.Firewall.DenyTempIPLimit) != admission.TemporaryCapacity {
			t.Errorf("%s: admission plans for %d, want its default capacity", tc.name, admission.AutomaticCapacity(cfg.Firewall.DenyTempIPLimit))
		}
		asYAML, err := yaml.Marshal(cfg.Firewall)
		if err != nil {
			t.Fatal(err)
		}
		asJSON, err := json.Marshal(cfg.Firewall)
		if err != nil {
			t.Fatal(err)
		}
		if out := strings.ToLower(string(asYAML) + string(asJSON)); strings.Contains(out, "negative") {
			t.Errorf("%s: the loader's note about the written value is serialized: %s", tc.name, out)
		}
	}
	previous := Active()
	t.Cleanup(func() { SetActive(previous) })
	for _, step := range []struct {
		name string
		warn bool
	}{
		{"negative", true}, {"zero over negative", false}, {"negative over positive", true}, {"positive over negative", false},
	} {
		SetActive(loaded[step.name])
		if got := len(negativeLimitWarnings(Active())) == 1; got != step.warn {
			t.Errorf("after publishing %s: warned %t, want %t", step.name, got, step.warn)
		}
	}
}
