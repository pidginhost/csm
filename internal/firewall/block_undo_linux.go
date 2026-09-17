//go:build linux

package firewall

import "time"

// BlockIPForUndo captures both sides of a forced operator block under the
// mutation lock. A later CLI decision must never become part of this undo.
func (e *Engine) BlockIPForUndo(ip, reason string, ttl time.Duration) (before, after *BlockedEntry, resultErr error) {
	defer func() {
		if e.shouldLegacyOutcome(resultErr) {
			recordBlockOutcome(ip, reason, ttl, BlockOutcomeLive, resultErr, true, "")
		}
	}()
	canonical, err := canonicalFirewallIP(ip)
	if err != nil {
		return nil, nil, err
	}
	ip = canonical
	e.mu.Lock()
	defer e.mu.Unlock()
	state := e.loadStateFile()
	if e.stateReadErr != nil {
		return nil, nil, e.stateReadErr
	}
	if entry, exists := blockedStateEntry(state, ip); exists {
		before = &entry
	}
	_, err = e.blockIPRequestLocked(ip, reason, ttl, false, false,
		ActionRequest{Operation: "block", Target: ip, Reason: reason, TTL: ttl}, nil, true)
	if err != nil {
		return nil, nil, err
	}
	state = e.loadStateFile()
	entry, _ := blockedStateEntry(state, ip)
	return before, &entry, nil
}

// UnblockIPForUndo captures the removed block in the same critical section.
func (e *Engine) UnblockIPForUndo(ip string) (before *BlockedEntry, resultErr error) {
	defer func() { e.legacyFirewallFailure("unblock", ip, "", "", 0, resultErr) }()
	canonical, err := canonicalFirewallIP(ip)
	if err != nil {
		return nil, err
	}
	ip = canonical
	e.mu.Lock()
	defer e.mu.Unlock()
	state := e.loadStateFile()
	if e.stateReadErr != nil {
		return nil, e.stateReadErr
	}
	if entry, exists := blockedStateEntry(state, ip); exists {
		before = &entry
	}
	if err := e.unblockIPLocked(ip); err != nil {
		return nil, err
	}
	return before, nil
}

// RestoreBlockIfUnchanged applies a saved lifetime only while the action's
// firewall snapshot still matches. The comparison and mutation share e.mu.
func (e *Engine) RestoreBlockIfUnchanged(ip string, expected, prior *BlockedEntry) (resultErr error) {
	var action, reason string
	var duration time.Duration
	defer func() {
		switch action {
		case "block":
			if e.shouldLegacyOutcome(resultErr) {
				recordBlockOutcome(ip, reason, duration, BlockOutcomeLive, resultErr, true, "")
			}
		case "unblock":
			e.legacyFirewallFailure("unblock", ip, "", "", 0, resultErr)
		}
	}()
	canonical, err := canonicalFirewallIP(ip)
	if err != nil {
		return err
	}
	ip = canonical
	e.mu.Lock()
	defer e.mu.Unlock()
	state := e.loadStateFile()
	if e.stateReadErr != nil {
		return e.stateReadErr
	}
	current, exists := blockedStateEntry(state, ip)
	if exists != (expected != nil) || (exists && !SameBlockedEntry(current, *expected)) {
		return ErrBlockChanged
	}
	if !exists {
		live, err := e.isBlockedLiveLocked(ip)
		if err != nil {
			return err
		}
		if live {
			return ErrBlockChanged
		}
	}
	if prior != nil {
		ttl := time.Duration(0)
		if !prior.ExpiresAt.IsZero() {
			ttl = time.Until(prior.ExpiresAt)
			if ttl <= 0 {
				prior = nil
			}
		}
		if prior != nil {
			action, reason, duration = "block", prior.Reason, ttl
			_, err := e.blockIPRequestLocked(ip, prior.Reason, ttl, false, false,
				ActionRequest{Operation: "block", Target: ip, Reason: prior.Reason, TTL: ttl}, nil, false)
			return err
		}
	}
	if !exists {
		return nil
	}
	action = "unblock"
	return e.unblockIPLocked(ip)
}
