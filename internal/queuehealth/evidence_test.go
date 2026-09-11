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

func TestEvidenceLabelsObservedQueueAge(t *testing.T) {
	got := (Status{LagBasis: "observed_age", LagSeconds: 121}).Evidence()
	if !strings.Contains(got, "observed_lag=121s") {
		t.Fatalf("observation age presented as persisted age: %q", got)
	}
}

func TestEvidenceLabelsOperationAndCheckpointAges(t *testing.T) {
	for basis, want := range map[string]string{
		"operation_progress":  "operation_stall=90s",
		"deferred_checkpoint": "deferred_age=90s",
	} {
		got := (Status{LagBasis: basis, LagSeconds: 90}).Evidence()
		if !strings.Contains(got, want) || strings.Contains(got, "lag=90s") {
			t.Fatalf("%s presented as a queue backlog age: %q", basis, got)
		}
	}
}
