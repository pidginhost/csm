package webui

import (
	"time"

	"github.com/pidginhost/csm/internal/firewall"
)

// Optional firewall capabilities the Web UI uses when the IPBlocker behind
// it has them. Test stubs may implement any subset. The firewall engine
// implements all of them, and the assertions below check that at compile
// time: renaming an engine method fails the build instead of quietly turning
// a Web UI action into a 503 or a skipped step.
type (
	forceBlocker interface {
		BlockIPForce(ip string, reason string, timeout time.Duration) error
	}
	lifetimeKeepingBlocker interface {
		BlockIPForcePreserveLifetime(ip, reason string, timeout time.Duration) error
	}
	undoableBlocker interface {
		BlockIPForUndo(ip, reason string, timeout time.Duration) (before, after *firewall.BlockedEntry, err error)
	}
	undoableUnblocker interface {
		UnblockIPForUndo(ip string) (before *firewall.BlockedEntry, err error)
	}
	blockRestorer interface {
		RestoreBlockIfUnchanged(ip string, expected, prior *firewall.BlockedEntry) error
	}
	ipAllower interface {
		AllowIP(ip string, reason string) error
	}
	ipTempAllower interface {
		TempAllowIP(ip string, reason string, timeout time.Duration) error
	}
	allowRemover interface {
		RemoveAllowIP(ip string) error
	}
	subnetBlocker interface {
		BlockSubnet(cidr string, reason string, timeout time.Duration) error
	}
	subnetUnblocker interface {
		UnblockSubnet(cidr string) error
	}
	blockFlusher interface {
		FlushBlocked() error
	}
	cloudflareChecker interface {
		CloudflareCovers(ip string) bool
	}
)

var (
	_ IPBlocker              = (*firewall.Engine)(nil)
	_ forceBlocker           = (*firewall.Engine)(nil)
	_ lifetimeKeepingBlocker = (*firewall.Engine)(nil)
	_ undoableBlocker        = (*firewall.Engine)(nil)
	_ undoableUnblocker      = (*firewall.Engine)(nil)
	_ blockRestorer          = (*firewall.Engine)(nil)
	_ ipAllower              = (*firewall.Engine)(nil)
	_ ipTempAllower          = (*firewall.Engine)(nil)
	_ allowRemover           = (*firewall.Engine)(nil)
	_ subnetBlocker          = (*firewall.Engine)(nil)
	_ subnetUnblocker        = (*firewall.Engine)(nil)
	_ blockFlusher           = (*firewall.Engine)(nil)
	_ cloudflareChecker      = (*firewall.Engine)(nil)
)
