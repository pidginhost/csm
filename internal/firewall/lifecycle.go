package firewall

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

func sameActionState(a, b FirewallState) bool {
	left, err := json.Marshal(a)
	if err != nil {
		return false
	}
	right, err := json.Marshal(b)
	return err == nil && string(left) == string(right)
}
func actionResult(a FirewallAction) error {
	switch a.Phase {
	case "verified":
		return nil
	case "failed":
		return fmt.Errorf("%w: %s", ErrActionFailed, a.Request.ID)
	default:
		return fmt.Errorf("%w: %s", ErrActionUnknown, a.Request.ID)
	}
}

// Execute admits once and executes only a fresh request. Repeated IDs inspect
// the original evidence; they never renew the plan or replay a kernel batch.
func (l *Lifecycle) Execute(plan FirewallAction, kernel ActionKernel) (FirewallAction, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.execute(plan, kernel)
}
func (l *Lifecycle) execute(plan FirewallAction, kernel ActionKernel) (FirewallAction, error) {
	a, fresh, err := l.Store.AdmitFirewallAction(plan)
	if err != nil {
		return FirewallAction{}, err
	}
	if !fresh {
		if a.Phase != "verified" && a.Phase != "failed" {
			a, err = l.reconcile(a, kernel, nil)
		} else {
			err = actionResult(a)
		}
		return a, errors.Join(err, l.deliverAudit())
	}
	a, err = l.Store.TransitionFirewallAction(a.Request.ID, "executing", "", time.Now())
	if err != nil {
		return FirewallAction{}, fmt.Errorf("%w: execution admission: %w", ErrActionUnknown, err)
	}
	observed, inspectErr := kernel.ObserveFirewallAction(a)
	if inspectErr != nil || !observed.Before {
		cause := errors.New("target changed before execution")
		if inspectErr != nil {
			cause = inspectErr
		}
		result, unknownErr := l.markUnknown(a, cause)
		return result, errors.Join(unknownErr, l.deliverAudit())
	}
	kernelErr := kernel.ApplyFirewallAction(a)
	if kernelErr == nil {
		a, err = l.Store.TransitionFirewallAction(a.Request.ID, "applied", "", time.Now())
		if err != nil {
			return FirewallAction{}, fmt.Errorf("%w: applied outcome persistence: %w", ErrActionUnknown, err)
		}
	}
	a, err = l.reconcile(a, kernel, kernelErr)
	return a, errors.Join(err, l.deliverAudit())
}
func (l *Lifecycle) markUnknown(a FirewallAction, cause error) (FirewallAction, error) {
	result, err := l.Store.TransitionFirewallAction(a.Request.ID, "unknown", cause.Error(), time.Now())
	return result, errors.Join(fmt.Errorf("%w: %s: %w", ErrActionUnknown, a.Request.ID, cause), err)
}
func (l *Lifecycle) reconcile(a FirewallAction, kernel ActionKernel, kernelErr error) (FirewallAction, error) {
	observed, err := kernel.ObserveFirewallAction(a)
	if err != nil {
		return l.markUnknown(a, err)
	}
	phase := ""
	switch {
	case observed.After && !observed.Before:
		phase = "verified"
	case observed.Before && !observed.After:
		phase = "failed"
	case observed.After && observed.Before && a.Phase == "applied":
		phase = "verified"
	case observed.After && observed.Before && a.Phase == "planned":
		phase = "failed"
	default:
		return l.markUnknown(a, errors.New("kernel does not prove a complete before or after state"))
	}
	detail := ""
	if kernelErr != nil {
		detail = kernelErr.Error()
	}
	result, err := l.Store.TransitionFirewallAction(a.Request.ID, phase, detail, time.Now())
	if err != nil {
		return FirewallAction{}, fmt.Errorf("%w: outcome persistence: %w", ErrActionUnknown, err)
	}
	return result, actionResult(result)
}

// Recover proves incomplete outcomes without executing host mutations. A
// proven rejected action is recovered successfully, though its result is failed.
func (l *Lifecycle) Recover(kernel ActionKernel) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	actions, err := l.Store.PendingFirewallActions()
	if err != nil {
		return err
	}
	var failures []error
	for _, a := range actions {
		if _, err := l.reconcile(a, kernel, nil); err != nil && !errors.Is(err, ErrActionFailed) {
			failures = append(failures, err)
		}
	}
	failures = append(failures, l.deliverAudit())
	return errors.Join(failures...)
}
func (l *Lifecycle) DeliverAudit() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.deliverAudit()
}
func (l *Lifecycle) deliverAudit() error {
	actions, err := l.Store.FirewallAuditPending()
	if err != nil {
		return err
	}
	for _, a := range actions {
		if l.Audit == nil {
			return errors.New("durable firewall audit writer unavailable")
		}
		if err := l.Audit(a); err != nil {
			return fmt.Errorf("firewall audit pending for %s: %w", a.Request.ID, err)
		}
		if err := l.Store.AcknowledgeFirewallAudit(a.Request.ID, a.AuditVersion); err != nil {
			return err
		}
	}
	return nil
}

// Undo admits an inverse state transition, never a command string. The complete
// recorded result must still be current; this also protects eviction victims.
func (l *Lifecycle) Undo(req ActionRequest, kernel ActionKernel) (FirewallAction, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if req.Operation != "undo" || req.UndoOf == "" {
		return FirewallAction{}, errors.New("invalid firewall undo request")
	}
	if existing, err := l.Store.ReadFirewallAction(req.ID); err == nil {
		if existing.Request != req {
			return FirewallAction{}, ErrStateConflict
		}
		return l.execute(existing, kernel)
	} else if !errors.Is(err, ErrActionMissing) {
		return FirewallAction{}, err
	}
	original, err := l.Store.ReadFirewallAction(req.UndoOf)
	if err != nil {
		return FirewallAction{}, err
	}
	if original.Request.Operation == "apply" {
		return FirewallAction{}, errors.New("ruleset configuration undo requires the confirmed-apply rollback protocol")
	}
	if original.Phase != "verified" {
		return FirewallAction{}, errors.New("only a verified firewall action can be undone")
	}
	state, revision, err := l.Store.ReadFirewallState()
	if err != nil {
		return FirewallAction{}, err
	}
	if !sameActionState(state, original.After) {
		return FirewallAction{}, fmt.Errorf("%w: undo state changed", ErrStateConflict)
	}
	observed, err := kernel.ObserveFirewallAction(original)
	if err != nil {
		return FirewallAction{}, err
	}
	if !observed.After {
		return FirewallAction{}, fmt.Errorf("%w: undo target changed", ErrStateConflict)
	}
	plan := FirewallAction{Request: req, Before: state, After: original.Before, Revision: revision, CreatedAt: time.Now(), KernelBefore: original.KernelAfter, KernelAfter: original.KernelBefore}
	if planner, ok := kernel.(interface{ PrepareFirewallUndo(*FirewallAction) error }); ok {
		if err := planner.PrepareFirewallUndo(&plan); err != nil {
			return FirewallAction{}, err
		}
	}
	return l.execute(plan, kernel)
}
