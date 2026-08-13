//go:build !linux

package firewall

import (
	"errors"
	"testing"
)

func TestNewEngineReturnsError(t *testing.T) {
	e, err := NewEngine(nil, "")
	if !errors.Is(err, ErrUnsupportedPlatform) {
		t.Errorf("NewEngine err = %v, want ErrUnsupportedPlatform", err)
	}
	if e != nil {
		t.Errorf("NewEngine engine = %v, want nil", e)
	}
}

func TestConnectExistingReturnsError(t *testing.T) {
	e, err := ConnectExisting(nil, "")
	if !errors.Is(err, ErrUnsupportedPlatform) {
		t.Errorf("ConnectExisting err = %v, want ErrUnsupportedPlatform", err)
	}
	if e != nil {
		t.Errorf("ConnectExisting engine = %v, want nil", e)
	}
}

// Every mutating stub must fail loudly. A nil-success stub lets a caller
// record a phantom block that never reached any kernel.
func TestNonLinuxStubMutatorsReturnErrUnsupportedPlatform(t *testing.T) {
	e := &Engine{}
	calls := []struct {
		name string
		err  error
	}{
		{"Apply", e.Apply()},
		{"BlockIP", e.BlockIP("203.0.113.5", "r", 0)},
		{"BlockIPForce", e.BlockIPForce("203.0.113.5", "r", 0)},
		{"PromoteToPermanentBlock", e.PromoteToPermanentBlock("203.0.113.5", "r")},
		{"UnblockIP", e.UnblockIP("203.0.113.5")},
		{"AllowIP", e.AllowIP("203.0.113.5", "r")},
		{"RemoveAllowIP", e.RemoveAllowIP("203.0.113.5")},
		{"RemoveAllowIPBySrc", e.RemoveAllowIPBySource("203.0.113.5", "cli")},
		{"BlockSubnet", e.BlockSubnet("203.0.113.0/24", "r", 0)},
		{"ValidateSubnetBlock", e.ValidateSubnetBlock("203.0.113.0/24")},
		{"UnblockSubnet", e.UnblockSubnet("203.0.113.0/24")},
		{"TempAllowIP", e.TempAllowIP("203.0.113.5", "r", 0)},
		{"AllowIPPort", e.AllowIPPort("203.0.113.5", 25, "tcp", "r")},
		{"RemoveAllowIPPort", e.RemoveAllowIPPort("203.0.113.5", 25, "tcp")},
		{"FlushBlocked", e.FlushBlocked()},
		{"UpdateCloudflareSet", e.UpdateCloudflareSet(nil, nil)},
		{"RefreshDOSExemptSets", e.RefreshDOSExemptSets(nil)},
	}
	for _, call := range calls {
		if !errors.Is(call.err, ErrUnsupportedPlatform) {
			t.Errorf("%s = %v, want ErrUnsupportedPlatform", call.name, call.err)
		}
	}
}

func TestNonLinuxStubBlockIPOutcomeErrors(t *testing.T) {
	e := &Engine{}
	outcome, err := e.BlockIPOutcome("203.0.113.5", "r", 0)
	if !errors.Is(err, ErrUnsupportedPlatform) {
		t.Errorf("BlockIPOutcome err = %v, want ErrUnsupportedPlatform", err)
	}
	if outcome != BlockOutcomeNoop {
		t.Errorf("BlockIPOutcome outcome = %q, want noop", outcome)
	}
}

func TestNonLinuxStubIsBlockedLiveErrors(t *testing.T) {
	e := &Engine{}
	blocked, err := e.IsBlockedLive("203.0.113.5")
	if !errors.Is(err, ErrUnsupportedPlatform) {
		t.Errorf("IsBlockedLive err = %v, want ErrUnsupportedPlatform", err)
	}
	if blocked {
		t.Error("IsBlockedLive = true on stub")
	}
}

func TestNonLinuxStubLiveBlockedSetErrors(t *testing.T) {
	e := &Engine{}
	snapshot, err := e.LiveBlockedSet()
	if !errors.Is(err, ErrUnsupportedPlatform) {
		t.Errorf("LiveBlockedSet err = %v, want ErrUnsupportedPlatform", err)
	}
	if snapshot.V4 != nil || snapshot.V6 != nil || snapshot.HasV4 || snapshot.HasV6 {
		t.Errorf("LiveBlockedSet snapshot = %+v, want zero value", snapshot)
	}
}

// Read-only stubs stay inert so status paths degrade gracefully.
func TestNonLinuxStubReadsStayInert(t *testing.T) {
	e := &Engine{}
	if n := e.BlockedCount(); n != 0 {
		t.Errorf("BlockedCount = %d", n)
	}
	if counts := e.RuleCounts(); counts != (RuleCounts{}) {
		t.Errorf("RuleCounts = %+v, want zero value", counts)
	}
	if e.IsBlocked("203.0.113.5") {
		t.Error("IsBlocked should return false")
	}
	if e.IsAllowed("203.0.113.5") {
		t.Error("IsAllowed should return false")
	}
	if e.IsSubnetBlocked("203.0.113.0/24") {
		t.Error("IsSubnetBlocked should return false")
	}
	if cidr, ok := e.BlockedSubnetCovering("203.0.113.5"); cidr != "" || ok {
		t.Errorf("BlockedSubnetCovering = (%q, %t), want empty false", cidr, ok)
	}
	if n := e.CleanExpiredAllows(); n != 0 {
		t.Errorf("CleanExpiredAllows = %d", n)
	}
	if n := e.CleanExpiredSubnets(); n != 0 {
		t.Errorf("CleanExpiredSubnets = %d", n)
	}
	if subnets := e.BlockedSubnets(); subnets != nil {
		t.Errorf("BlockedSubnets = %v, want nil", subnets)
	}
	if s := e.Status(); s != nil {
		t.Errorf("Status = %v, want nil", s)
	}
	v4, v6 := e.CloudflareIPs()
	if v4 != nil || v6 != nil {
		t.Errorf("CloudflareIPs = (%v, %v)", v4, v6)
	}
	if e.CloudflareCovers("198.51.100.7") {
		t.Error("CloudflareCovers should return false")
	}
}
