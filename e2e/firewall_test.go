//go:build integration

package e2e

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/firewall"
)

func TestNFTablesEngineLifecycle(t *testing.T) {
	cfg := &firewall.FirewallConfig{
		Enabled: true,
		TCPIn:   []int{22, 80, 443, 9443},
	}
	statePath := t.TempDir()

	engine, err := firewall.NewEngine(cfg, statePath)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	if err := engine.Apply(); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	t.Run("BlockUnblock", func(t *testing.T) {
		err := engine.BlockIP("192.0.2.1", "integration-test", 5*time.Minute)
		if err != nil {
			t.Fatalf("BlockIP: %v", err)
		}
		if !engine.IsBlocked("192.0.2.1") {
			t.Error("IP should be blocked after BlockIP")
		}

		err = engine.UnblockIP("192.0.2.1")
		if err != nil {
			t.Fatalf("UnblockIP: %v", err)
		}
		if engine.IsBlocked("192.0.2.1") {
			t.Error("IP should not be blocked after UnblockIP")
		}
	})

	t.Run("PermanentBlock", func(t *testing.T) {
		err := engine.BlockIP("192.0.2.2", "permanent-test", 0)
		if err != nil {
			t.Fatalf("BlockIP permanent: %v", err)
		}
		if !engine.IsBlocked("192.0.2.2") {
			t.Error("permanent block should show as blocked")
		}
		_ = engine.UnblockIP("192.0.2.2")
	})

	t.Run("AllowRemove", func(t *testing.T) {
		err := engine.AllowIP("10.99.99.1", "integration-test")
		if err != nil {
			t.Fatalf("AllowIP: %v", err)
		}
		err = engine.RemoveAllowIP("10.99.99.1")
		if err != nil {
			t.Fatalf("RemoveAllowIP: %v", err)
		}
	})

	t.Run("TempAllow", func(t *testing.T) {
		err := engine.TempAllowIP("10.99.99.2", "temp-test", 5*time.Minute)
		if err != nil {
			t.Fatalf("TempAllowIP: %v", err)
		}
		cleaned := engine.CleanExpiredAllows()
		_ = cleaned // should be 0 since not expired yet
	})

	t.Run("BlockSubnet", func(t *testing.T) {
		err := engine.BlockSubnet("192.0.2.0/24", "subnet-test", 5*time.Minute)
		if err != nil {
			t.Fatalf("BlockSubnet: %v", err)
		}
		err = engine.UnblockSubnet("192.0.2.0/24")
		if err != nil {
			t.Fatalf("UnblockSubnet: %v", err)
		}
	})

	t.Run("AllowIPPort", func(t *testing.T) {
		err := engine.AllowIPPort("10.99.99.3", 3306, "tcp", "mysql-test")
		if err != nil {
			t.Fatalf("AllowIPPort: %v", err)
		}
		err = engine.RemoveAllowIPPort("10.99.99.3", 3306, "tcp")
		if err != nil {
			t.Fatalf("RemoveAllowIPPort: %v", err)
		}
	})

	t.Run("Status", func(t *testing.T) {
		status := engine.Status()
		if status == nil {
			t.Fatal("Status should not be nil")
		}
	})

	t.Run("FlushBlocked", func(t *testing.T) {
		_ = engine.BlockIP("192.0.2.10", "flush-test", 0)
		_ = engine.BlockIP("192.0.2.11", "flush-test", 0)
		err := engine.FlushBlocked()
		if err != nil {
			t.Fatalf("FlushBlocked: %v", err)
		}
	})
}

func TestNFTablesConnectExisting(t *testing.T) {
	cfg := &firewall.FirewallConfig{
		Enabled: true,
		TCPIn:   []int{22, 80, 443},
	}
	statePath := t.TempDir()

	// Create and apply first
	engine1, err := firewall.NewEngine(cfg, statePath)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if err := engine1.Apply(); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// Connect to existing
	engine2, err := firewall.ConnectExisting(cfg, statePath)
	if err != nil {
		t.Fatalf("ConnectExisting: %v", err)
	}
	if engine2 == nil {
		t.Fatal("ConnectExisting should return non-nil engine")
	}
}
