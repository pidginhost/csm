package bpf

import "testing"

func TestShouldLogDroppedEvent(t *testing.T) {
	tests := []struct {
		name    string
		dropped uint64
		want    bool
	}{
		{"none", 0, false},
		{"first", 1, true},
		{"second", 2, false},
		{"before stride", dropEventLogStride - 1, false},
		{"stride", dropEventLogStride, true},
		{"after stride", dropEventLogStride + 1, false},
		{"second stride", dropEventLogStride * 2, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldLogDroppedEvent(tt.dropped); got != tt.want {
				t.Fatalf("shouldLogDroppedEvent(%d) = %v, want %v", tt.dropped, got, tt.want)
			}
		})
	}
}
