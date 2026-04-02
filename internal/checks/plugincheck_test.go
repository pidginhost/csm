package checks

import "testing"

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		installed string
		available string
		wantMajor bool
		wantMinor int
	}{
		{"3.32.5", "4.0.1", true, 0},
		{"6.1.3", "6.4.2", false, 3},
		{"6.1.3", "6.1.5", false, 0},
		{"5.6", "5.6", false, 0},
		{"1.9.9", "1.9.9", false, 0},
		{"6.4.0", "6.5.13", false, 1},
		{"6.4.0", "6.7.0", false, 3},
		{"", "4.0.1", false, 0},
		{"3.0", "", false, 0},
	}
	for _, tt := range tests {
		gotMajor, gotMinor := compareVersions(tt.installed, tt.available)
		if gotMajor != tt.wantMajor || gotMinor != tt.wantMinor {
			t.Errorf("compareVersions(%q, %q) = (%v, %d), want (%v, %d)",
				tt.installed, tt.available, gotMajor, gotMinor, tt.wantMajor, tt.wantMinor)
		}
	}
}

func TestPluginAlertSeverity(t *testing.T) {
	tests := []struct {
		name      string
		installed string
		available string
		wantSev   string
	}{
		{"major gap", "3.32.5", "4.0.1", "critical"},
		{"3 minor", "6.1.3", "6.4.2", "high"},
		{"1 minor", "6.4.0", "6.5.13", "warning"},
		{"same version", "5.6", "5.6", ""},
		{"patch only", "6.1.3", "6.1.5", "warning"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pluginAlertSeverity(tt.installed, tt.available)
			if got != tt.wantSev {
				t.Errorf("pluginAlertSeverity(%q, %q) = %q, want %q",
					tt.installed, tt.available, got, tt.wantSev)
			}
		})
	}
}
