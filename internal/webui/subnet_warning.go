package webui

import "fmt"

// subnetCoverer is implemented by the firewall engine: it reports the
// blocked subnet, if any, that still covers an address.
type subnetCoverer interface {
	BlockedSubnetCovering(ip string) (string, bool)
}

// coveringSubnetWarning explains why an unblocked or allowed address may
// still be dropped: the chain drops @blocked_nets before it accepts
// @allowed_ips, so a covering blocked subnet overrides both actions. Empty
// when nothing covers the address or the blocker cannot tell.
func coveringSubnetWarning(blocker IPBlocker, ip string) string {
	cov, ok := blocker.(subnetCoverer)
	if !ok {
		return ""
	}
	cidr, covered := cov.BlockedSubnetCovering(ip)
	if !covered {
		return ""
	}
	return fmt.Sprintf("still dropped by blocked subnet %s; unblock that subnet to restore access", cidr)
}
