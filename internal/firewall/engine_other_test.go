//go:build !linux

package firewall

import (
	"errors"
	"testing"
)

func TestNewEngineReturnsError(t *testing.T) {
	_, err := NewEngine(nil, "")
	if err == nil {
		t.Error("expected error on non-linux")
	}
}

func TestConnectExistingReturnsError(t *testing.T) {
	_, err := ConnectExisting(nil, "")
	if err == nil {
		t.Error("expected error on non-linux")
	}
}

// Every mutating stub must fail loudly. A nil-success stub lets a caller
// record a phantom block that never reached any kernel.
func TestNonLinuxStubMutatorsReturnErrUnsupportedPlatform(t *testing.T) {
	e := &Engine{}
	calls := map[string]error{
		"Apply":                e.Apply(),
		"BlockIP":              e.BlockIP("203.0.113.5", "r", 0),
		"BlockIPForce":         e.BlockIPForce("203.0.113.5", "r", 0),
		"UnblockIP":            e.UnblockIP("203.0.113.5"),
		"AllowIP":              e.AllowIP("203.0.113.5", "r"),
		"RemoveAllowIP":        e.RemoveAllowIP("203.0.113.5"),
		"RemoveAllowIPBySrc":   e.RemoveAllowIPBySource("203.0.113.5", "cli"),
		"BlockSubnet":          e.BlockSubnet("203.0.113.0/24", "r", 0),
		"UnblockSubnet":        e.UnblockSubnet("203.0.113.0/24"),
		"TempAllowIP":          e.TempAllowIP("203.0.113.5", "r", 0),
		"AllowIPPort":          e.AllowIPPort("203.0.113.5", 25, "tcp", "r"),
		"RemoveAllowIPPort":    e.RemoveAllowIPPort("203.0.113.5", 25, "tcp"),
		"FlushBlocked":         e.FlushBlocked(),
		"UpdateCloudflareSet":  e.UpdateCloudflareSet(nil, nil),
		"RefreshDOSExemptSets": e.RefreshDOSExemptSets(nil),
	}
	for name, err := range calls {
		if !errors.Is(err, ErrUnsupportedPlatform) {
			t.Errorf("%s = %v, want ErrUnsupportedPlatform", name, err)
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

// Read-only stubs stay inert so status paths degrade gracefully.
func TestNonLinuxStubReadsStayInert(t *testing.T) {
	e := &Engine{}
	if e.IsBlocked("203.0.113.5") {
		t.Error("IsBlocked should return false")
	}
	if n := e.CleanExpiredAllows(); n != 0 {
		t.Errorf("CleanExpiredAllows = %d", n)
	}
	if n := e.CleanExpiredSubnets(); n != 0 {
		t.Errorf("CleanExpiredSubnets = %d", n)
	}
	if s := e.Status(); s != nil {
		t.Errorf("Status = %v, want nil", s)
	}
	v4, v6 := e.CloudflareIPs()
	if v4 != nil || v6 != nil {
		t.Errorf("CloudflareIPs = (%v, %v)", v4, v6)
	}
}
