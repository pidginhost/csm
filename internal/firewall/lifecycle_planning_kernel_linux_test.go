//go:build linux && nftkernel

package firewall

import (
	"testing"
	"time"
)

func TestKernelLifecyclePlanningExpiryUsesOneTimestamp(t *testing.T) {
	isolatedFirewallNamespace(t)
	e, err := NewEngine(&FirewallConfig{Enabled: true, IPv6: true}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Apply(); err != nil {
		t.Fatal(err)
	}
	started := time.Now().Add(-2 * time.Second)
	a := FirewallAction{Request: ActionRequest{Operation: "block", Target: "192.0.2.181"}, CreatedAt: started, After: FirewallState{Blocked: []BlockedEntry{{IP: "192.0.2.181", BlockedAt: started, ExpiresAt: started.Add(time.Second)}}}}
	if err := e.prepareActionKernel(&a); err != nil {
		t.Fatal(err)
	}
	if err := (engineActionKernel{e}).ValidateEvidence(a); err != nil {
		t.Fatalf("expiry during planning creates unrecoverable evidence: %v", err)
	}
	for _, set := range a.KernelAfter {
		if len(set.Elements) != 0 {
			t.Fatal("planning rearmed expired target")
		}
	}
}
