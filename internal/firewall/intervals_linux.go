//go:build linux

package firewall

import (
	"bytes"
	"fmt"
	"net"
	"slices"
	"time"

	"github.com/google/nftables"
)

// normalizeIntervalElements unions independent start/end pairs of one address
// family. Stored source entries stay separate; only their kernel view is merged.
// A start without an end represents a range through the family's last address.
func normalizeIntervalElements(elements []nftables.SetElement) []nftables.SetElement {
	type ipRange struct{ start, end []byte }
	ranges := make([]ipRange, 0, len(elements)/2+1)
	for i := 0; i < len(elements); i++ {
		r := ipRange{start: elements[i].Key}
		if i+1 < len(elements) && elements[i+1].IntervalEnd {
			i++
			r.end = bytes.Clone(elements[i].Key)
			for j := len(r.end) - 1; j >= 0; j-- {
				r.end[j]--
				if r.end[j] != 0xff {
					break
				}
			}
		} else {
			r.end = bytes.Repeat([]byte{0xff}, len(r.start))
		}
		ranges = append(ranges, r)
	}
	slices.SortFunc(ranges, func(a, b ipRange) int { return bytes.Compare(a.start, b.start) })
	var out []nftables.SetElement
	for i := 0; i < len(ranges); {
		merged := ranges[i]
		i++
		for i < len(ranges) {
			next, hasNext := nextIntervalKey(merged.end)
			if hasNext && bytes.Compare(ranges[i].start, next) > 0 {
				break
			}
			if bytes.Compare(ranges[i].end, merged.end) > 0 {
				merged.end = ranges[i].end
			}
			i++
		}
		out = appendIntervalSetElements(out, merged.start, merged.end)
	}
	return out
}

// Preserve the set's key width even when an IPv6 boundary has the numeric
// shape of an IPv4-mapped address.
func nextIntervalKey(key []byte) ([]byte, bool) {
	next := bytes.Clone(key)
	for i := len(next) - 1; i >= 0; i-- {
		next[i]++
		if next[i] != 0 {
			return next, true
		}
	}
	return nil, false
}

func subnetIntervalElements(entries []SubnetEntry, ipv6 bool, now time.Time) (v4, v6 []nftables.SetElement) {
	for _, entry := range entries {
		if !entry.ExpiresAt.IsZero() && !now.Before(entry.ExpiresAt) {
			continue
		}
		_, network, err := net.ParseCIDR(entry.CIDR)
		if err != nil {
			continue
		}
		// The public block path refuses default routes. Old state must obey
		// that same lockout guard when it is restored at startup.
		if ones, _ := network.Mask.Size(); ones == 0 {
			continue
		}
		end := lastIPInRange(network)
		if start := network.IP.To4(); start != nil {
			v4 = appendIntervalSetElements(v4, start, end)
		} else if ipv6 {
			v6 = appendIntervalSetElements(v6, network.IP.To16(), end)
		}
	}
	return normalizeIntervalElements(v4), normalizeIntervalElements(v6)
}

// Rebuild the union in one transaction. Deleting the original boundaries of
// an overlapping entry could otherwise remove a different source's protection.
func (e *Engine) replaceBlockedSubnetSets(entries []SubnetEntry) error {
	// A pending config reload may differ from the installed ruleset. Keep
	// every family that still has a live set until Apply replaces the table.
	v4, v6 := subnetIntervalElements(entries, e.setBlockedNet6 != nil, time.Now())
	// A non-lasting connection only dials at Flush and cannot fail here. A
	// separate batch also makes any queue error discard the entire update.
	conn, _ := nftables.New(nftables.WithSockOptions(applyNFTSocketBuffer), nftables.WithNetNSFd(e.conn.NetNS), nftables.WithTestDial(e.conn.TestDial))
	for _, family := range []struct {
		set      *nftables.Set
		elements []nftables.SetElement
	}{{e.setBlockedNet, v4}, {e.setBlockedNet6, v6}} {
		if family.set == nil {
			continue
		}
		conn.FlushSet(family.set)
		if err := addElementsChunked(conn, family.set, family.elements); err != nil {
			return err
		}
	}
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("replacing subnet sets: %w", err)
	}
	return nil
}

func (e *Engine) updateSubnetStateAndKernel(prior, next FirewallState) error {
	if err := e.saveState(&next); err != nil {
		return fmt.Errorf("persisting subnet change: %w", err)
	}
	if err := e.replaceBlockedSubnetSets(next.BlockedNet); err != nil {
		if restoreErr := e.saveState(&prior); restoreErr != nil {
			return fmt.Errorf("%w (state restore failed: %v)", err, restoreErr)
		}
		return err
	}
	return nil
}
