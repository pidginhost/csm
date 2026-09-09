package queuehealth

import (
	"strings"
	"testing"
)

func TestEvidenceLabelsUnavailableCapacity(t *testing.T) {
	for _, unavailableDepth := range []bool{false, true} {
		status := Status{Depth: 4, CapacityUnavailable: true, DepthUnavailable: unavailableDepth}
		got := status.Evidence()
		want := "depth=4/unknown items"
		if unavailableDepth {
			want = "depth=unknown/unknown items"
		}
		if !strings.Contains(got, want) || strings.Contains(got, "/0") {
			t.Fatalf("unknown kernel capacity was presented as a zero limit: %q", got)
		}
	}
}
