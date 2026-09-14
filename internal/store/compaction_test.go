package store

import "testing"

func TestCompactionDue(t *testing.T) {
	const mb = 1024 * 1024
	tests := []struct {
		name      string
		size      int64
		free      int64
		minSizeMB int
		fillRatio float64
		want      bool
	}{
		{"below min size", 50 * mb, 40 * mb, 128, 0.5, false},
		{"large and mostly free", 400 * mb, 380 * mb, 128, 0.5, true},
		{"large but mostly used", 400 * mb, 20 * mb, 128, 0.5, false},
		{"large, fill just under ratio", 200 * mb, 110 * mb, 128, 0.5, true}, // fill 0.45 < 0.5
		{"large, fill just over ratio", 200 * mb, 90 * mb, 128, 0.5, false},  // fill 0.55 >= 0.5
		{"min size disabled", 400 * mb, 380 * mb, 0, 0.5, false},
		{"fill ratio disabled", 400 * mb, 380 * mb, 128, 0, false},
		{"zero size", 0, 0, 128, 0.5, false},
		{"free exceeds size (clamped)", 200 * mb, 300 * mb, 128, 0.5, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CompactionDue(tt.size, tt.free, tt.minSizeMB, tt.fillRatio); got != tt.want {
				t.Fatalf("CompactionDue(%d,%d,%d,%g) = %v, want %v",
					tt.size, tt.free, tt.minSizeMB, tt.fillRatio, got, tt.want)
			}
		})
	}
}
