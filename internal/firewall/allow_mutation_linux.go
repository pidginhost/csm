//go:build linux

package firewall

import (
	"fmt"
	"time"

	"github.com/google/nftables"
)

// Persist intent before touching the kernel so a restart converges to the
// requested policy. A failed atomic kernel batch restores the previous intent.
// The caller holds e.mu across both writes and the kernel transaction.
func (e *Engine) commitAllowedRemovals(prior, next FirewallState, removeIPs []string) error {
	if err := e.persistFirewallIntent(prior, next); err != nil {
		return fmt.Errorf("persisting allow removal: %w", err)
	}
	if err := e.deleteAllowedElements(removeIPs, next.Allowed); err != nil {
		if restoreErr := e.saveState(&prior); restoreErr != nil {
			return fmt.Errorf("partial failure: %w (state restore failed: %w)", err, restoreErr)
		}
		return err
	}
	return nil
}

func (e *Engine) deleteAllowedElements(ips []string, remaining []AllowedEntry) error {
	if len(ips) == 0 {
		return nil
	}
	conn := e.newMutationConn()
	sets := make(map[*nftables.Set]bool)
	for _, ip := range ips {
		set, key, err := e.resolveIPSet(ip, e.setAllowed, e.setAllowed6)
		if err != nil || set == nil {
			continue
		}
		if err := conn.SetDeleteElements(set, []nftables.SetElement{{Key: key}}); err != nil {
			return fmt.Errorf("removing allow for %s: %w", ip, err)
		}
		sets[set] = true
	}
	if err := conn.Flush(); err != nil {
		if !isNftNotFound(err) {
			return fmt.Errorf("removing allows: %w", err)
		}
		// An element already absent aborts the whole delete batch. Rebuild the
		// affected sets atomically so one missing element cannot wedge cleanup.
		return e.replaceAllowedSets(sets, remaining)
	}
	return nil
}

func (e *Engine) replaceAllowedSets(sets map[*nftables.Set]bool, entries []AllowedEntry) error {
	conn := e.newMutationConn()
	elements := make(map[*nftables.Set][]nftables.SetElement)
	seen := make(map[string]bool)
	now := time.Now()
	for _, entry := range entries {
		if !entry.ExpiresAt.IsZero() && !now.Before(entry.ExpiresAt) {
			continue
		}
		ip, ok := canonicalIPKey(entry.IP)
		if !ok || seen[ip] {
			continue
		}
		set, key, err := e.resolveIPSet(ip, e.setAllowed, e.setAllowed6)
		if err != nil || !sets[set] {
			continue
		}
		seen[ip] = true
		elements[set] = append(elements[set], nftables.SetElement{Key: key})
	}
	for set := range sets {
		conn.FlushSet(set)
		if err := addElementsChunked(conn, set, elements[set]); err != nil {
			return err
		}
	}
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("rebuilding allowed sets: %w", err)
	}
	return nil
}

// A separate non-lasting connection discards queued messages on any error.
// Its constructor cannot fail because it does not dial until Flush.
func (e *Engine) newMutationConn() *nftables.Conn {
	conn, _ := nftables.New(nftables.WithSockOptions(applyNFTSocketBuffer), nftables.WithNetNSFd(e.conn.NetNS), nftables.WithTestDial(e.conn.TestDial))
	return conn
}
