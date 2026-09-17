package daemon

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/firewall"
	csmlog "github.com/pidginhost/csm/internal/log"
)

// firewallActionBoundary is the durable-action surface an engine exposes once
// a lifecycle is attached. Keeping it an interface means the daemon compiles
// on platforms whose engine has no lifecycle at all.
type firewallActionBoundary interface {
	DurableActionsEnabled() bool
	RecoverActions() error
	PendingActions() ([]firewall.FirewallAction, error)
	ResolveAction(id, outcome, detail string) (firewall.FirewallAction, error)
}

// recoverFirewallActions settles outcomes left uncertain by a crash or a
// kernel that could not answer. Until every action is settled the engine
// refuses new mutations, so this runs at startup and on the maintenance tick.
func recoverFirewallActions(engine any) {
	boundary, ok := engine.(firewallActionBoundary)
	if !ok || boundary == nil || !boundary.DurableActionsEnabled() {
		return
	}
	if err := boundary.RecoverActions(); err != nil {
		csmlog.Error("firewall action recovery incomplete", "err", err)
	}
}

func (c *ControlListener) firewallActions() (firewallActionBoundary, error) {
	if c.d.fwActions == nil || !c.d.fwActions.DurableActionsEnabled() {
		return nil, fmt.Errorf("durable firewall actions are not active")
	}
	return c.d.fwActions, nil
}

// handleFirewallActions reports the actions that still block firewall
// mutations, with the evidence an operator needs to decide what happened.
func (c *ControlListener) handleFirewallActions(json.RawMessage) (any, error) {
	boundary, err := c.firewallActions()
	if err != nil {
		return nil, err
	}
	pending, err := boundary.PendingActions()
	if err != nil {
		return nil, err
	}
	if len(pending) == 0 {
		return control.FirewallListResult{Lines: []string{"No firewall actions are waiting for recovery."}}, nil
	}
	lines := make([]string, 0, len(pending)*2)
	for _, a := range pending {
		lines = append(lines,
			fmt.Sprintf("%s  %s  %s %s", a.UpdatedAt.Format("2006-01-02 15:04:05"), a.Phase, a.Request.Operation, a.Request.Target),
			fmt.Sprintf("    id %s  actor %s  source %s", a.Request.ID, a.Request.Actor, a.Request.Source),
		)
		if a.Request.Reason != "" {
			lines = append(lines, "    reason "+a.Request.Reason)
		}
		if a.Detail != "" {
			lines = append(lines, "    detail "+a.Detail)
		}
		if a.Phase == "unknown" {
			lines = append(lines, fmt.Sprintf("    resolve with: csm firewall actions resolve %s applied|rejected", a.Request.ID))
		}
	}
	return control.FirewallListResult{Lines: lines}, nil
}

// handleFirewallActionResolve records what an operator established by hand.
// The engine still prefers kernel evidence when it can prove the outcome.
func (c *ControlListener) handleFirewallActionResolve(argsRaw json.RawMessage) (any, error) {
	var args control.FirewallActionResolveArgs
	if len(argsRaw) > 0 {
		if err := json.Unmarshal(argsRaw, &args); err != nil {
			return nil, fmt.Errorf("parsing args: %w", err)
		}
	}
	if strings.TrimSpace(args.ID) == "" {
		return nil, fmt.Errorf("resolve needs the action id")
	}
	var outcome string
	switch args.Outcome {
	case "applied":
		outcome = "verified"
	case "rejected":
		outcome = "failed"
	default:
		return nil, fmt.Errorf("outcome must be applied or rejected, not %q", args.Outcome)
	}
	boundary, err := c.firewallActions()
	if err != nil {
		return nil, err
	}
	detail := "operator resolved via cli"
	if note := strings.TrimSpace(args.Note); note != "" {
		detail += ": " + note
	}
	resolved, err := boundary.ResolveAction(args.ID, outcome, detail)
	if err != nil {
		return nil, err
	}
	message := fmt.Sprintf("action %s recorded as %s", args.ID, resolved.Phase)
	if resolved.Phase != outcome {
		message = fmt.Sprintf("action %s was proven %s by the firewall itself; the operator decision was not used", args.ID, resolved.Phase)
	}
	return control.FirewallAckResult{Message: message}, nil
}
