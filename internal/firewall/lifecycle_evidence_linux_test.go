//go:build linux

package firewall

import (
	"testing"
	"time"
)

func TestLifecycleEvidenceRejectsIncompleteEffects(t *testing.T) {
	validator, ok := any(engineActionKernel{}).(interface{ ValidateEvidence(FirewallAction) error })
	if !ok {
		t.Fatal("kernel evidence lacks complete effect validation")
	}
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	for _, tc := range []struct {
		name string
		sets []ActionSet
	}{
		{"missing family", []ActionSet{{Name: "blocked_ips", Exists: true}}},
		{"duplicate family", []ActionSet{{Name: "blocked_ips", Exists: true}, {Name: "blocked_ips", Exists: true}}},
		{"missing requested element", []ActionSet{{Name: "blocked_ips", Exists: true}, {Name: "blocked_ips6", Exists: false}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := FirewallAction{Request: ActionRequest{Operation: "block"}, CreatedAt: at, After: FirewallState{Blocked: []BlockedEntry{{IP: "192.0.2.10", BlockedAt: at}}}, KernelBefore: tc.sets, KernelAfter: tc.sets}
			if err := validator.ValidateEvidence(a); err == nil {
				t.Fatal("incomplete evidence accepted")
			}
		})
	}
}

type replayLifecycleStore struct {
	ActionStore
	action  FirewallAction
	current FirewallState
}

func (s replayLifecycleStore) ReadFirewallAction(string) (FirewallAction, error) {
	return s.action, nil
}
func (s replayLifecycleStore) AdmitFirewallAction(FirewallAction) (FirewallAction, bool, error) {
	return s.action, false, nil
}
func (s replayLifecycleStore) FirewallAuditPending() ([]FirewallAction, error) { return nil, nil }
func (s replayLifecycleStore) ReadFirewallState() (FirewallState, uint64, error) {
	return s.current, 9, nil
}
func (s replayLifecycleStore) PendingFirewallActions() ([]FirewallAction, error) { return nil, nil }
func TestLifecycleConcurrentReplayRechecksUnderMutationLock(t *testing.T) {
	req := normalizeActionRequest(ActionRequest{ID: "racing-request", Operation: "block", Target: "192.0.2.161"})
	current := FirewallState{Blocked: []BlockedEntry{{IP: "192.0.2.162"}}}
	e := &Engine{lifecycle: &Lifecycle{Store: replayLifecycleStore{action: FirewallAction{Request: req, Phase: "verified"}, current: current}}}
	// Another caller committed this ID between the public replay check and
	// acquisition of the actual mutation lock. No kernel connection is needed.
	out, err := e.blockIPLockedRequest(req.Target, req.Reason, req.TTL, false, false, req, nil)
	if err != nil || out != BlockOutcomeNoop {
		t.Fatalf("racing replay=%s,%v", out, err)
	}
	if e.stateCache == nil || len(e.stateCache.Blocked) != 1 || e.stateCache.Blocked[0].IP != "192.0.2.162" {
		t.Fatalf("replayed historical cache: %#v", e.stateCache)
	}
}
