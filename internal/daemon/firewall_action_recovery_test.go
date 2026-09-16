package daemon

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/firewall"
)

type recordingActionEngine struct {
	enabled    bool
	recovered  int
	recoverErr error
	pending    []firewall.FirewallAction
	pendingErr error
	resolved   []string
	resolveErr error
}

func (e *recordingActionEngine) DurableActionsEnabled() bool { return e.enabled }
func (e *recordingActionEngine) RecoverActions() error {
	e.recovered++
	return e.recoverErr
}
func (e *recordingActionEngine) PendingActions() ([]firewall.FirewallAction, error) {
	return e.pending, e.pendingErr
}
func (e *recordingActionEngine) ResolveAction(id, outcome, detail string) (firewall.FirewallAction, error) {
	e.resolved = append(e.resolved, id+" "+outcome+" "+detail)
	if e.resolveErr != nil {
		return firewall.FirewallAction{}, e.resolveErr
	}
	return firewall.FirewallAction{Request: firewall.ActionRequest{ID: id}, Phase: outcome, Detail: detail}, nil
}

func strandedActionFixture() firewall.FirewallAction {
	return firewall.FirewallAction{
		Request:   firewall.ActionRequest{ID: "stranded", Operation: "block", Target: "203.0.113.5", Actor: "daemon", Source: "scan", Reason: "CSM auto-block"},
		Phase:     "unknown",
		Detail:    "kernel inspection unavailable",
		CreatedAt: time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC),
		UpdatedAt: time.Date(2026, 3, 4, 5, 6, 8, 0, time.UTC),
	}
}

func TestRecoverFirewallActionsRunsOnlyWhenDurable(t *testing.T) {
	engine := &recordingActionEngine{enabled: false}
	recoverFirewallActions(engine)
	if engine.recovered != 0 {
		t.Fatal("recovery ran without durable actions")
	}
	engine.enabled = true
	recoverFirewallActions(engine)
	if engine.recovered != 1 {
		t.Fatalf("recovered = %d, want 1", engine.recovered)
	}
	engine.recoverErr = errors.New("still uncertain")
	recoverFirewallActions(engine)
	if engine.recovered != 2 {
		t.Fatalf("recovered = %d, want 2 even after a failure", engine.recovered)
	}
	// A nil engine and one without the boundary must both be no-ops.
	recoverFirewallActions(nil)
	recoverFirewallActions(struct{}{})
}

func TestHandleFirewallActionsListsWhatBlocksMutations(t *testing.T) {
	c := newListenerForTest(t)
	if _, err := c.handleFirewallActions(nil); err == nil {
		t.Fatal("actions listed without a firewall engine")
	}
	engine := &recordingActionEngine{enabled: true, pending: []firewall.FirewallAction{strandedActionFixture()}}
	c.d.fwActions = engine
	raw, err := c.handleFirewallActions(nil)
	if err != nil {
		t.Fatalf("handleFirewallActions: %v", err)
	}
	lines := raw.(control.FirewallListResult).Lines
	joined := strings.Join(lines, "\n")
	for _, want := range []string{"stranded", "unknown", "203.0.113.5", "kernel inspection unavailable"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("listing %q missing %q", joined, want)
		}
	}
	engine.pending = nil
	raw, err = c.handleFirewallActions(nil)
	if err != nil {
		t.Fatalf("handleFirewallActions: %v", err)
	}
	if lines := raw.(control.FirewallListResult).Lines; len(lines) != 1 || !strings.Contains(lines[0], "No") {
		t.Fatalf("empty listing = %#v", lines)
	}
}

func TestHandleFirewallActionResolveRecordsOperatorDecision(t *testing.T) {
	c := newListenerForTest(t)
	engine := &recordingActionEngine{enabled: true}
	c.d.fwActions = engine
	args, _ := json.Marshal(control.FirewallActionResolveArgs{ID: "stranded", Outcome: "applied", Note: "rule present in nft list"})
	raw, err := c.handleFirewallActionResolve(args)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	message := raw.(control.FirewallAckResult).Message
	if !strings.Contains(message, "stranded") || !strings.Contains(message, "verified") {
		t.Fatalf("ack = %q", message)
	}
	if len(engine.resolved) != 1 || !strings.HasPrefix(engine.resolved[0], "stranded verified ") {
		t.Fatalf("engine calls = %#v", engine.resolved)
	}
	if !strings.Contains(engine.resolved[0], "rule present in nft list") {
		t.Fatalf("operator note lost: %q", engine.resolved[0])
	}
	rejected, _ := json.Marshal(control.FirewallActionResolveArgs{ID: "stranded", Outcome: "rejected"})
	if _, err := c.handleFirewallActionResolve(rejected); err != nil {
		t.Fatalf("resolve rejected: %v", err)
	}
	if !strings.HasPrefix(engine.resolved[1], "stranded failed ") {
		t.Fatalf("engine calls = %#v", engine.resolved)
	}
	for _, bad := range []control.FirewallActionResolveArgs{{}, {ID: "stranded"}, {ID: "stranded", Outcome: "maybe"}, {Outcome: "applied"}} {
		badArgs, _ := json.Marshal(bad)
		if _, err := c.handleFirewallActionResolve(badArgs); err == nil {
			t.Fatalf("resolve accepted %#v", bad)
		}
	}
}
