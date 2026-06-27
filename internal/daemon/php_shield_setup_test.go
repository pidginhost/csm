package daemon

import "testing"

func TestPHPShieldWatchDecision(t *testing.T) {
	tests := []struct {
		name         string
		enabled      bool
		scriptExists bool
		wantWatch    bool
		wantWarn     bool
	}{
		{
			name:    "disabled: neither watch nor warn",
			enabled: false, scriptExists: false,
			wantWatch: false, wantWarn: false,
		},
		{
			name:    "disabled even if script present",
			enabled: false, scriptExists: true,
			wantWatch: false, wantWarn: false,
		},
		{
			name:    "enabled and installed: watch",
			enabled: true, scriptExists: true,
			wantWatch: true, wantWarn: false,
		},
		{
			// The cluster6 case: an upgrade wiped /opt/csm so the shield script
			// is gone, but php_shield.enabled stayed true in csm.yaml. We must
			// warn once (actionable) rather than spin the missing-file log
			// watcher retry forever.
			name:    "enabled but not installed: warn, do not watch",
			enabled: true, scriptExists: false,
			wantWatch: false, wantWarn: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			watch, warn := phpShieldWatchDecision(tt.enabled, tt.scriptExists)
			if watch != tt.wantWatch || warn != tt.wantWarn {
				t.Fatalf("phpShieldWatchDecision(%v, %v) = (watch=%v, warn=%v), want (watch=%v, warn=%v)",
					tt.enabled, tt.scriptExists, watch, warn, tt.wantWatch, tt.wantWarn)
			}
		})
	}
}
