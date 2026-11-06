package admissionowner

import (
	"fmt"
	"time"

	"github.com/pidginhost/csm/internal/firewall"
)

// heldEvery spaces bounded held checks. Each batch gets two answered
// calls before the ledger advances to the next batch.
const heldEvery = time.Minute

// observeHeld asks the firewall, at most once every heldEvery and only
// while the ledger counts a verified block, whether each such block is
// still held, and hands the answer to the ledger. A block two consecutive
// answers no longer hold left early (an operator unblock, undo or flush,
// or a lost kernel element): the ledger marks it gone and stops counting
// its slot (spec 5.2, 5.6). A fault marks nothing and waits for the next
// check; like eviction cleanup it never fails the turn.
func (o *Owner) observeHeld() error {
	if !o.mayRetire() || monoNow().Before(o.heldAt) {
		return nil
	}
	asked, err := o.ledger.HeldEffects(firewall.MaxHeldBlockActions)
	if err == nil && len(asked) == 0 {
		o.heldAt = time.Time{}
		return nil
	}
	o.heldAt = monoNow().Add(heldEvery)
	if err != nil {
		return err
	}
	engine := o.opts.Blocks()
	if engine == nil {
		return nil
	}
	actions := make([]firewall.BlockAction, len(asked))
	for i, h := range asked {
		addr, _ := h.Target.Addr()
		actions[i] = firewall.BlockAction{Action: string(h.Action), IP: addr.String()}
	}
	held, err := engine.HeldBlockActions(actions)
	if err != nil {
		return fmt.Errorf("checking held blocks: %w", err)
	}
	// The ledger refuses a short answer whole.
	gone, err := o.ledger.ObserveHeld(asked, held)
	for _, h := range gone {
		// An element lost outside CSM leaves its row behind. Retire it as
		// an evicted victim's row, so a firewall reload cannot restore what
		// the ledger no longer counts.
		addr, _ := h.Target.Addr()
		o.evicted = append(o.evicted, firewall.BlockAction{Action: string(h.Action), IP: addr.String()})
	}
	if len(gone) > 0 {
		// Do not leave restorable rows waiting for the next held check.
		// Cleanup retains failures and schedules its own retry.
		_ = o.retireEvicted()
	}
	return err
}
