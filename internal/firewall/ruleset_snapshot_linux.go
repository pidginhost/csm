//go:build linux

package firewall

import (
	"context"
	"os/exec"
	"time"
)

// RulesetSnapshot returns the live rules and the baseline captured immediately
// after the last successful Apply. The engine lock keeps our own concurrent
// reconfiguration from splitting the pair. An empty baseline means capture
// failed or this engine attached to an existing table without applying it.
func (e *Engine) RulesetSnapshot() (current, applied string, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	current, err = e.readRulesetLocked()
	return current, e.appliedRuleset, err
}

func (e *Engine) readRulesetLocked() (string, error) {
	if e.readRuleset != nil {
		return e.readRuleset()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Terse/stateless output omits members, counters, and elapsed timeouts.
	// Keep transient traffic state out of both the baseline and its memory cost.
	out, err := exec.CommandContext(ctx, "nft", "-s", "-t", "list", "table", "inet", "csm").Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}
