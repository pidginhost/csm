package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// yaraWorkerOn is the helper that decides whether to spin up the
// supervised YARA-X child process. Defaulting to true when the operator
// leaves the field unset is the ROADMAP item 2 follow-up: every host
// that upgrades past this flip gets crash-isolated YARA-X without
// editing csm.yaml, and anyone who explicitly opts out with
// `yara_worker_enabled: false` keeps the old in-process path.

func TestYaraWorkerOn_NilPointerMeansDefaultOn(t *testing.T) {
	cfg := &config.Config{}
	// Leave Signatures.YaraWorkerEnabled at its zero value (nil *bool).
	if !yaraWorkerOn(cfg) {
		t.Error("omitted yara_worker_enabled should default to true")
	}
}

func TestYaraWorkerOn_ExplicitFalseWins(t *testing.T) {
	cfg := &config.Config{}
	f := false
	cfg.Signatures.YaraWorkerEnabled = &f
	if yaraWorkerOn(cfg) {
		t.Error("explicit yara_worker_enabled: false should disable the worker")
	}
}

func TestYaraWorkerOn_ExplicitTrueWins(t *testing.T) {
	cfg := &config.Config{}
	tr := true
	cfg.Signatures.YaraWorkerEnabled = &tr
	if !yaraWorkerOn(cfg) {
		t.Error("explicit yara_worker_enabled: true should enable the worker")
	}
}

func TestYaraWorkerOn_NilCfgDoesNotPanic(t *testing.T) {
	// Defensive: if the daemon ever calls through a nil config (it
	// shouldn't in production), the helper should stay silent-off
	// rather than crash a running daemon.
	if yaraWorkerOn(nil) {
		t.Error("nil cfg should fall back to off to avoid surprising behaviour")
	}
}

// TestYaraWorkerEnabledYAMLRoundTrip pins the wire semantics of the
// tri-state field as seen by the YAML loader.
func TestYaraWorkerEnabledYAMLRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		body string
		want *bool
	}{
		{"omitted", "hostname: test\n", nil},
		{"explicit true", "hostname: test\nsignatures:\n  yara_worker_enabled: true\n", boolPtr(true)},
		{"explicit false", "hostname: test\nsignatures:\n  yara_worker_enabled: false\n", boolPtr(false)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := config.LoadBytes([]byte(tc.body))
			if err != nil {
				t.Fatalf("LoadBytes: %v", err)
			}
			got := cfg.Signatures.YaraWorkerEnabled
			switch {
			case tc.want == nil && got != nil:
				t.Errorf("want nil, got %v", *got)
			case tc.want != nil && got == nil:
				t.Errorf("want %v, got nil", *tc.want)
			case tc.want != nil && got != nil && *tc.want != *got:
				t.Errorf("want %v, got %v", *tc.want, *got)
			}
		})
	}
}

func boolPtr(b bool) *bool { return &b }
