package webui

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/store"
)

func (s *Server) blockIPPreservingLifetime(ip, reason string, ttl time.Duration) error {
	if ttl > 0 {
		if guarded, ok := s.blocker.(lifetimeKeepingBlocker); ok {
			err := guarded.BlockIPForcePreserveLifetime(ip, reason, ttl)
			checks.ObserveOperatorBlock(err, checks.BlockSourceWebUI)
			return err
		}
		// Test blockers and integrations without the engine extension still
		// honor the persisted lifetime. The live engine checks under its lock.
		blocks, err := snapshotFirewallBlocks(s.cfg.StatePath)
		if err != nil {
			return err
		}
		if entry, ok := blocks[ip]; ok {
			if entry.ExpiresAt.IsZero() {
				return firewall.ErrPermanentBlock
			}
			if time.Until(entry.ExpiresAt) > ttl {
				return firewall.ErrLongerBlock
			}
		}
	}
	return blockIPForOperator(s.blocker, ip, reason, ttl)
}

func snapshotFirewallBlocks(statePath string) (map[string]firewall.BlockedEntry, error) {
	state, err := firewall.LoadState(statePath)
	if err != nil {
		return nil, err
	}
	blocks := make(map[string]firewall.BlockedEntry, len(state.Blocked))
	for _, entry := range state.Blocked {
		if ip := net.ParseIP(entry.IP); ip != nil {
			entry.IP = ip.String()
			blocks[entry.IP] = entry
		}
	}
	return blocks, nil
}

func invalidateIPUndo(ip string) {
	if db := store.Global(); db != nil {
		if err := db.InvalidateUndoTargets([]string{ip}); err != nil {
			log.Printf("webui: invalidate IP undo: %v", err)
		}
	}
}

func threatRowsForIP(rows []undoThreatRow, ip string) []undoThreatRow {
	for _, row := range rows {
		if row.IP == ip {
			return []undoThreatRow{row}
		}
	}
	return nil
}

// undoSnapshotBlocks restores each original deadline, never a fresh 24h
// window. Later firewall decisions invalidate the snapshot even if they
// originated outside the Web UI and did not touch the threat database.
func (s *Server) undoSnapshotBlocks(payload undoPayloadIPs, clearEvidence bool) (int, error) {
	if s.blocker == nil {
		return 0, fmt.Errorf("firewall engine not available")
	}
	current, err := snapshotFirewallBlocks(s.cfg.StatePath)
	if err != nil {
		return 0, err
	}
	for _, ip := range payload.IPs {
		got, exists := current[ip]
		want, expected := payload.ExpectedBlocks[ip]
		if exists != expected || (exists && !firewall.SameBlockedEntry(got, want)) {
			return 0, firewall.ErrBlockChanged
		}
	}
	count := 0
	for _, ip := range payload.IPs {
		if _, err := parseAndValidateIP(ip); err != nil {
			continue
		}
		prior, hadPrior := payload.RestoreBlocks[ip]
		ttl := time.Duration(0)
		if hadPrior && !prior.ExpiresAt.IsZero() {
			ttl = time.Until(prior.ExpiresAt)
			if ttl <= 0 {
				hadPrior = false
			}
		}
		if !hadPrior && !clearEvidence {
			continue
		}
		if restorer, ok := s.blocker.(blockRestorer); ok {
			var expected, restore *firewall.BlockedEntry
			if entry, exists := payload.ExpectedBlocks[ip]; exists {
				expected = &entry
			}
			if hadPrior {
				restore = &prior
			}
			err := restorer.RestoreBlockIfUnchanged(ip, expected, restore)
			if hadPrior {
				checks.ObserveOperatorBlock(err, checks.BlockSourceWebUI)
			}
			if err != nil {
				continue
			}
		} else if hadPrior {
			if err := blockIPForOperator(s.blocker, ip, prior.Reason, ttl); err != nil {
				continue
			}
		} else if err := s.blocker.UnblockIP(ip); err != nil {
			continue
		}

		if clearEvidence {
			if tdb := checks.GetThreatDB(); tdb != nil {
				tdb.RemovePermanent(ip)
			}
		}
		restoreUndoThreatRows(threatRowsForIP(payload.RestoreThreats, ip))
		if clearEvidence && !hadPrior {
			_ = flushCphulk(ip) // best effort
		}
		count++
	}
	return count, nil
}

func (s *Server) blockIPForUndo(ip, reason string, ttl time.Duration) (*firewall.BlockedEntry, *firewall.BlockedEntry, error) {
	if blocker, ok := s.blocker.(undoableBlocker); ok {
		before, after, err := blocker.BlockIPForUndo(ip, reason, ttl)
		checks.ObserveOperatorBlock(err, checks.BlockSourceWebUI)
		return before, after, err
	}
	before, err := snapshotFirewallBlocks(s.cfg.StatePath)
	if err != nil {
		return nil, nil, err
	}
	if err = s.blockIPPreservingLifetime(ip, reason, ttl); err != nil {
		return nil, nil, err
	}
	after, err := snapshotFirewallBlocks(s.cfg.StatePath)
	return blockPointer(before, ip), blockPointer(after, ip), err
}

func (s *Server) unblockIPForUndo(ip string) (*firewall.BlockedEntry, error) {
	if blocker, ok := s.blocker.(undoableUnblocker); ok {
		return blocker.UnblockIPForUndo(ip)
	}
	before, err := snapshotFirewallBlocks(s.cfg.StatePath)
	if err != nil {
		return nil, err
	}
	if err := s.blocker.UnblockIP(ip); err != nil {
		return nil, err
	}
	return blockPointer(before, ip), nil
}

func blockPointer(blocks map[string]firewall.BlockedEntry, ip string) *firewall.BlockedEntry {
	if entry, exists := blocks[ip]; exists {
		return &entry
	}
	return nil
}
