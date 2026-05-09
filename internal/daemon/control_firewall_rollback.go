package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/firewall/rollback"
)

func (c *ControlListener) handleFirewallRollbackStatus(_ json.RawMessage) (any, error) {
	mgr := rollback.Global()
	if mgr == nil {
		return control.FirewallRollbackStatus{}, nil
	}
	st := mgr.Status()
	out := control.FirewallRollbackStatus{
		Pending:          st.Pending,
		AppliedBy:        st.AppliedBy,
		PrevHash:         st.PrevHash,
		NewHash:          st.NewHash,
		SecondsRemaining: st.SecondsRemaining,
	}
	if !st.AppliedAt.IsZero() {
		out.AppliedAtRFC3339 = st.AppliedAt.Format(time.RFC3339)
	}
	if !st.ExpiresAt.IsZero() {
		out.ExpiresAtRFC3339 = st.ExpiresAt.Format(time.RFC3339)
	}
	return out, nil
}

func (c *ControlListener) handleFirewallRollbackConfirm(_ json.RawMessage) (any, error) {
	mgr := rollback.Global()
	if mgr == nil {
		return control.FirewallAckResult{Message: "rollback manager not initialised"}, nil
	}
	if !mgr.Status().Pending {
		return control.FirewallAckResult{Message: "no pending rollback"}, nil
	}
	if err := mgr.Confirm(); err != nil {
		return nil, fmt.Errorf("confirm rollback: %w", err)
	}
	return control.FirewallAckResult{Message: "rollback confirmed; pending change is now permanent"}, nil
}

func (c *ControlListener) handleFirewallRollbackRevert(_ json.RawMessage) (any, error) {
	mgr := rollback.Global()
	if mgr == nil {
		return control.FirewallAckResult{Message: "rollback manager not initialised"}, nil
	}
	if !mgr.Status().Pending {
		return control.FirewallAckResult{Message: "no pending rollback"}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := mgr.Revert(ctx); err != nil {
		return nil, fmt.Errorf("revert rollback: %w", err)
	}
	return control.FirewallAckResult{Message: "rollback reverted; previous config restored, daemon restart issued"}, nil
}
