package daemon

import (
	"slices"
	"testing"
)

func TestPopulatePolicyMapMatchesPolicy(t *testing.T) {
	pol := BPFEnforcementPolicy{Enforce: 1, DryRun: 0, Ports: []uint16{25, 587}}
	got := policyMapPayload(pol)
	if got.Enforce != 1 {
		t.Errorf("Enforce: want 1, got %d", got.Enforce)
	}
	if got.DryRun != 0 {
		t.Errorf("DryRun: want 0, got %d", got.DryRun)
	}
	if got.ProtectedPorts != 2 {
		t.Errorf("ProtectedPorts count: want 2, got %d", got.ProtectedPorts)
	}
}

func TestPopulatePolicyMapEmptyPolicyDisables(t *testing.T) {
	got := policyMapPayload(BPFEnforcementPolicy{})
	if got.Enforce != 0 || got.DryRun != 0 || got.ProtectedPorts != 0 {
		t.Errorf("zero policy must yield zero payload; got %+v", got)
	}
}

func TestStaleSafeUIDsDropsOnlyHostedUIDs(t *testing.T) {
	installed := []uint32{0, 89, 999, 1000, 1005, 1006}
	next := map[uint32]bool{0: true, 89: true, 1005: true}
	got := staleSafeUIDs(installed, next)
	slices.Sort(got)
	if want := []uint32{1000, 1006}; !slices.Equal(got, want) {
		t.Fatalf("stale UIDs = %v, want %v", got, want)
	}
}
