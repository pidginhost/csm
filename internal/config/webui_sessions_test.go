package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWebUISessionPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, yaml string
		invalid    bool
	}{
		{"defaults", "", false},
		{"custom", "webui:\n  session_lifetime: 2h\n  session_idle_timeout: 5m\n", false},
		{"zero", "webui:\n  session_lifetime: 0s\n", true},
		{"negative", "webui:\n  session_idle_timeout: -1m\n", true},
		{"invalid", "webui:\n  session_idle_timeout: tomorrow\n", true},
		{"idle exceeds lifetime", "webui:\n  session_lifetime: 5m\n  session_idle_timeout: 10m\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "csm.yaml")
			if err := os.WriteFile(file, []byte(tc.yaml), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(file)
			if tc.invalid {
				if err == nil {
					t.Fatal("invalid session policy accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			lifetime, idle, err := cfg.BrowserSessionDurations()
			if err != nil {
				t.Fatal(err)
			}
			if tc.name == "defaults" && (lifetime != 24*time.Hour || idle != 30*time.Minute) {
				t.Fatal("missing usable default session deadlines")
			}
			if tc.name == "custom" && (lifetime != 2*time.Hour || idle != 5*time.Minute) {
				t.Fatal("configured session deadlines ignored")
			}
		})
	}
}
