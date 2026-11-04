//go:build linux

package firewall

import "fmt"

// HeldBlockActions reports, for each verified admission block, whether
// what it applied may remain in the kernel: retirement's answer reversed
// (spec 5.4), with no state write. An element still at the address that
// no other action's verified row proves answers held, even after a
// forward wall step makes the block's own row look expired, and so does
// an address whose family the snapshot cannot read; only a removal
// answers false. An error answers nothing.
func (e *Engine) HeldBlockActions(actions []BlockAction) ([]bool, error) {
	if len(actions) > MaxHeldBlockActions {
		return nil, fmt.Errorf("a held check names at most %d blocks", MaxHeldBlockActions)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	canonical, unread, err := e.canonicalBlockActions(actions, "checking")
	if err != nil {
		return nil, err
	}
	snap, err := e.blockBatchSnapshotLocked()
	if err != nil {
		return nil, err
	}
	held := clearBlockActions(snap, canonical, unread)
	for i := range held {
		held[i] = !held[i]
	}
	return held, nil
}
