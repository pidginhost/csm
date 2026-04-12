//go:build !linux

package firewall

import (
	"testing"
	"time"
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

func TestEngineStubMethods(t *testing.T) {
	e := &Engine{}
	if err := e.Apply(); err != nil {
		t.Errorf("Apply: %v", err)
	}
	if err := e.BlockIP("1.2.3.4", "test", time.Hour); err != nil {
		t.Errorf("BlockIP: %v", err)
	}
	if err := e.UnblockIP("1.2.3.4"); err != nil {
		t.Errorf("UnblockIP: %v", err)
	}
	if e.IsBlocked("1.2.3.4") {
		t.Error("IsBlocked should return false")
	}
	if err := e.AllowIP("1.2.3.4", "test"); err != nil {
		t.Errorf("AllowIP: %v", err)
	}
	if err := e.RemoveAllowIP("1.2.3.4"); err != nil {
		t.Errorf("RemoveAllowIP: %v", err)
	}
	if err := e.RemoveAllowIPBySource("1.2.3.4", "src"); err != nil {
		t.Errorf("RemoveAllowIPBySource: %v", err)
	}
	if err := e.BlockSubnet("10.0.0.0/8", "test", time.Hour); err != nil {
		t.Errorf("BlockSubnet: %v", err)
	}
	if err := e.UnblockSubnet("10.0.0.0/8"); err != nil {
		t.Errorf("UnblockSubnet: %v", err)
	}
	if err := e.TempAllowIP("1.2.3.4", "test", time.Hour); err != nil {
		t.Errorf("TempAllowIP: %v", err)
	}
	if err := e.AllowIPPort("1.2.3.4", 80, "tcp", "test"); err != nil {
		t.Errorf("AllowIPPort: %v", err)
	}
	if err := e.RemoveAllowIPPort("1.2.3.4", 80, "tcp"); err != nil {
		t.Errorf("RemoveAllowIPPort: %v", err)
	}
	if n := e.CleanExpiredAllows(); n != 0 {
		t.Errorf("CleanExpiredAllows = %d", n)
	}
	if n := e.CleanExpiredSubnets(); n != 0 {
		t.Errorf("CleanExpiredSubnets = %d", n)
	}
	if err := e.FlushBlocked(); err != nil {
		t.Errorf("FlushBlocked: %v", err)
	}
	if s := e.Status(); s != nil {
		t.Errorf("Status = %v, want nil", s)
	}
	if err := e.UpdateCloudflareSet(nil, nil); err != nil {
		t.Errorf("UpdateCloudflareSet: %v", err)
	}
	v4, v6 := e.CloudflareIPs()
	if v4 != nil || v6 != nil {
		t.Errorf("CloudflareIPs = (%v, %v)", v4, v6)
	}
}
